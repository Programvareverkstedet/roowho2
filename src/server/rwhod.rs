use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::Path,
    sync::Arc,
};

use anyhow::Context;
use chrono::{DateTime, Duration, Timelike, Utc};
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags, sys::stat::stat};
use serde::{Deserialize, Serialize};
use uucore::utmpx::Utmpx;
use zlink::{ReplyError, service::MethodReply};

use crate::proto::{Whod, WhodStatusUpdate, WhodUserEntry};

/// Default port for rwhod communication.
pub const RWHOD_BROADCAST_PORT: u16 = 513;

/// Reads utmp entries to determine currently logged-in users.
pub fn generate_rwhod_user_entries(now: DateTime<Utc>) -> anyhow::Result<Vec<WhodUserEntry>> {
    Utmpx::iter_all_records()
        .filter(|entry| entry.is_user_process())
        .map(|entry| {
            let login_time = entry
                .login_time()
                .checked_to_utc()
                .and_then(|t| DateTime::<Utc>::from_timestamp_secs(t.unix_timestamp()))
                .ok_or_else(|| anyhow::anyhow!("Failed to convert login time to UTC"))?;

            let idle_time = stat(&Path::new("/dev").join(entry.tty_device()))
                .ok()
                .and_then(|st| {
                    let last_active = DateTime::<Utc>::from_timestamp_secs(st.st_atime)?;
                    Some((now - last_active).max(Duration::zero()))
                })
                .unwrap_or(Duration::zero());

            debug_assert!(
                idle_time.num_seconds() >= 0,
                "Idle time should never be negative"
            );

            Ok(WhodUserEntry::new(
                entry.tty_device(),
                entry.user(),
                login_time,
                idle_time,
            ))
        })
        .collect()
}

/// Generate a rwhod status update packet representing the current system state.
pub fn generate_rwhod_status_update() -> anyhow::Result<WhodStatusUpdate> {
    let sysinfo = nix::sys::sysinfo::sysinfo().unwrap();
    let load_average = sysinfo.load_average();
    let uptime = sysinfo.uptime();
    let hostname = nix::unistd::gethostname()?.to_str().unwrap().to_string();
    let now = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());

    let result = WhodStatusUpdate::new(
        now,
        None,
        hostname,
        (
            (load_average.0 * 100.0).abs() as i32,
            (load_average.1 * 100.0).abs() as i32,
            (load_average.2 * 100.0).abs() as i32,
        ),
        now - uptime,
        generate_rwhod_user_entries(now)?,
    );

    Ok(result)
}

#[derive(Debug, Clone)]
pub struct RwhodSendTarget {
    /// Name of the network interface.
    pub name: String,

    /// Address to send rwhod packets to.
    /// This is either the broadcast address (for broadcast interfaces)
    /// or the point-to-point destination address (for point-to-point interfaces).
    pub addr: IpAddr,
}

/// Find all networks network interfaces suitable for rwhod communication.
pub fn determine_relevant_interfaces() -> anyhow::Result<Vec<RwhodSendTarget>> {
    getifaddrs().map_err(|e| e.into()).map(|ifaces| {
        ifaces
            // interface must be up
            .filter(|iface| iface.flags.contains(InterfaceFlags::IFF_UP))
            // interface must be broadcast or point-to-point
            .filter(|iface| {
                iface
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_POINTOPOINT)
            })
            .filter_map(|iface| {
                let neighbor_addr = if iface.flags.contains(InterfaceFlags::IFF_BROADCAST) {
                    iface.broadcast
                } else if iface.flags.contains(InterfaceFlags::IFF_POINTOPOINT) {
                    iface.destination
                } else {
                    None
                };

                match neighbor_addr {
                    Some(addr) => addr
                        .as_sockaddr_in()
                        .map(|sa| IpAddr::V4(sa.ip()))
                        .or_else(|| addr.as_sockaddr_in6().map(|sa| IpAddr::V6(sa.ip())))
                        .map(|ip_addr| RwhodSendTarget {
                            name: iface.interface_name,
                            addr: ip_addr,
                        }),
                    None => None,
                }
            })
            /* keep first occurrence per interface name */
            .scan(HashSet::new(), |seen, n| {
                if seen.insert(n.name.clone()) {
                    Some(n)
                } else {
                    None
                }
            })
            .collect::<Vec<RwhodSendTarget>>()
    })
}

pub async fn send_rwhod_packet_to_interface(
    socket: Arc<tokio::net::UdpSocket>,
    interface: &RwhodSendTarget,
    packet: &Whod,
) -> anyhow::Result<()> {
    let serialized_packet = packet.to_bytes();

    // TODO: the old rwhod daemon doesn't actually ever listen to ipv6, maybe remove it
    let target_addr = match interface.addr {
        IpAddr::V4(addr) => std::net::SocketAddr::new(IpAddr::V4(addr), RWHOD_BROADCAST_PORT),
        IpAddr::V6(addr) => std::net::SocketAddr::new(IpAddr::V6(addr), RWHOD_BROADCAST_PORT),
    };

    tracing::debug!(
        "Sending rwhod packet to interface {} at address {}",
        interface.name,
        target_addr
    );

    socket
        .send_to(&serialized_packet, &target_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send rwhod packet: {}", e))?;

    Ok(())
}

pub async fn rwhod_packet_receiver_task(
    socket: Arc<tokio::net::UdpSocket>,
    whod_status_store: Arc<tokio::sync::RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; Whod::MAX_SIZE];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;

        tracing::debug!("Received rwhod packet of length {} bytes from {}", len, src);

        if len < Whod::HEADER_SIZE {
            tracing::error!(
                "Received too short packet from {src}: {len} bytes (needs to be at least {} bytes)",
                Whod::HEADER_SIZE
            );
            continue;
        }

        let result = Whod::from_bytes(&buf[..len])
            .context("Failed to parse whod packet")?
            .try_into()
            .map(|mut status_update: WhodStatusUpdate| {
                let timestamp = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());
                status_update.recvtime = Some(timestamp);
                status_update
            })
            .map_err(|e| anyhow::anyhow!("Invalid whod packet: {}", e));

        match result {
            Ok(status_update) => {
                tracing::debug!("Processed whod packet from {src}: {:?}", status_update);

                let mut store = whod_status_store.write().await;
                store.insert(src.ip(), status_update);
            }
            Err(err) => {
                tracing::error!("Error processing whod packet from {src}: {err}");
            }
        }
    }
}

pub async fn rwhod_packet_sender_task(
    socket: Arc<tokio::net::UdpSocket>,
    interfaces: Vec<RwhodSendTarget>,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

    loop {
        interval.tick().await;

        let status_update = generate_rwhod_status_update()?;

        tracing::debug!("Generated rwhod packet: {:?}", status_update);

        let packet = status_update
            .try_into()
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        for interface in &interfaces {
            if let Err(e) = send_rwhod_packet_to_interface(socket.clone(), interface, &packet).await
            {
                tracing::error!(
                    "Failed to send rwhod packet on interface {}: {}",
                    interface.name,
                    e
                );
            }
        }
    }
}

#[zlink::proxy("no.ntnu.pvv.roowho2.rwhod")]
pub trait RwhodClientProxy {
    async fn rwho(
        &mut self,
        all: bool,
    ) -> zlink::Result<Result<Vec<WhodUserEntry>, RwhodClientError>>;

    async fn ruptime(&mut self) -> zlink::Result<Result<Vec<WhodStatusUpdate>, RwhodClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum RwhodClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.rwhod.Rwho")]
    Rwho {
        /// Retrieve all users, even those that have been idle for a long time.
        all: bool,
    },

    #[serde(rename = "no.ntnu.pvv.roowho2.rwhod.Ruptime")]
    Ruptime,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RwhodClientResponse {
    Rwho(Vec<WhodUserEntry>),
    Ruptime(Vec<WhodStatusUpdate>),
}

#[derive(Debug, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.rwhod")]
pub enum RwhodClientError {
    InvalidRequest,
}

#[derive(Debug, Clone)]
pub struct RwhodClientServer {
    whod_status_store: Arc<tokio::sync::RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
}

impl RwhodClientServer {
    pub fn new(
        whod_status_store: Arc<tokio::sync::RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
    ) -> Self {
        Self { whod_status_store }
    }
}

impl zlink::Service for RwhodClientServer {
    type MethodCall<'de> = RwhodClientRequest;
    type ReplyParams<'se> = RwhodClientResponse;
    type ReplyStreamParams = ();
    type ReplyStream = futures_util::stream::Empty<zlink::Reply<()>>;
    type ReplyError<'se> = RwhodClientError;

    async fn handle<'ser, 'de: 'ser, Sock: zlink::connection::Socket>(
        &'ser mut self,
        call: zlink::Call<Self::MethodCall<'de>>,
        _conn: &mut zlink::Connection<Sock>,
    ) -> MethodReply<Self::ReplyParams<'ser>, Self::ReplyStream, Self::ReplyError<'ser>> {
        match call.method() {
            // TODO: handle 'all' parameter
            RwhodClientRequest::Rwho { .. } => {
                let store = self.whod_status_store.read().await;
                let mut all_user_entries = Vec::new();
                for status_update in store.values() {
                    all_user_entries.extend_from_slice(&status_update.users);
                }
                MethodReply::Single(Some(RwhodClientResponse::Rwho(all_user_entries)))
            }
            RwhodClientRequest::Ruptime => {
                let store = self.whod_status_store.read().await;
                let all_status_updates = store.values().cloned().collect();
                MethodReply::Single(Some(RwhodClientResponse::Ruptime(all_status_updates)))
            }
        }
    }
}

pub async fn rwhod_client_server_task(
    socket: zlink::unix::Listener,
    whod_status_store: Arc<tokio::sync::RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
) -> anyhow::Result<()> {
    let service = RwhodClientServer::new(whod_status_store);

    let server = zlink::Server::new(socket, service);

    tracing::info!("Starting Rwhod client API server");

    server
        .run()
        .await
        .context("Rwhod client API server failed")?;

    Ok(())
}
