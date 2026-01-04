use std::{collections::HashSet, net::IpAddr, path::Path};

use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags, sys::stat::stat};
use uucore::utmpx::Utmpx;

use crate::proto::{Whod, WhodStatusUpdate, WhodUserEntry};

/// Reads utmp entries to determine currently logged-in users.
pub fn generate_rwhod_user_entries() -> anyhow::Result<Vec<WhodUserEntry>> {
    Utmpx::iter_all_records()
        .filter(|entry| entry.is_user_process())
        .map(|entry| {
            let login_time = entry
                .login_time()
                .checked_to_utc()
                .and_then(|t| {
                    chrono::DateTime::<chrono::Utc>::from_timestamp_secs(t.unix_timestamp())
                })
                .ok_or_else(|| anyhow::anyhow!("Failed to convert login time to UTC"))?;

            let idle_time = stat(&Path::new("/dev").join(entry.tty_device()))
                .map(|st| (chrono::Utc::now().timestamp() - st.st_atime) as i32)
                .unwrap_or(0);

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
pub fn generate_rwhod_status_update() -> anyhow::Result<Whod> {
    let sysinfo = nix::sys::sysinfo::sysinfo().unwrap();
    let load_average = sysinfo.load_average();
    let uptime = sysinfo.uptime();
    let hostname = nix::unistd::gethostname()?.to_str().unwrap().to_string();

    let result = WhodStatusUpdate::new(
        chrono::Utc::now(),
        None,
        hostname,
        (load_average.0 * 100.0).abs() as i32,
        (load_average.1 * 100.0).abs() as i32,
        (load_average.2 * 100.0).abs() as i32,
        chrono::Utc::now() - uptime,
        generate_rwhod_user_entries()?,
    )
    .try_into()
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(result)
}

#[derive(Debug)]
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
                        .map(|sa| IpAddr::V4(sa.ip().into()))
                        .or_else(|| addr.as_sockaddr_in6().map(|sa| IpAddr::V6(sa.ip().into())))
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
    socket: &mut tokio::net::UdpSocket,
    interface: &RwhodSendTarget,
    packet: &Whod,
) -> anyhow::Result<()> {
    let serialized_packet = packet.to_bytes();

    let target_addr = match interface.addr {
        IpAddr::V4(addr) => std::net::SocketAddr::new(IpAddr::V4(addr), 0),
        IpAddr::V6(addr) => std::net::SocketAddr::new(IpAddr::V6(addr), 0),
    };

    socket
        .send_to(&serialized_packet, &target_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send rwhod packet: {}", e))?;

    Ok(())
}

// TODO: implement receiving rwhod packets from other hosts

// TODO: implement storing and loading rwhod packets to/from file

// TODO: implement protocol for cli - daemon communication
