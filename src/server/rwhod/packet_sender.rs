use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags, sys::socket::SockaddrStorage};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{Duration as TokioDuration, interval},
};

use crate::{
    proto::Whod,
    server::{
        ignore_list::IgnoreList,
        rwhod::{IpRange, rwhod_status::generate_rwhod_status_update},
    },
};

/// Default port for rwhod communication.
pub const RWHOD_BROADCAST_PORT: u16 = 513;

/// How long to wait after a realtime update before actually reading utmp and sending a status update.
/// This is necessary because audit log events can arrive before the utmp record gets updated.
const REALTIME_UPDATE_SETTLE_DELAY: TokioDuration = TokioDuration::from_millis(500);

#[derive(Debug, Clone)]
pub struct RwhodSendTarget {
    /// Name of the network interface.
    pub name: String,

    /// Address to send rwhod packets to.
    /// This is either the broadcast address (for broadcast interfaces)
    /// or the point-to-point destination address (for point-to-point interfaces).
    pub addr: IpAddr,
}

/// Computes the broadcast address for an IPv4 address/netmask pair
fn ipv4_broadcast_address(address: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(address) | !u32::from(netmask))
}

/// Extracts the IP address from a socket address
fn sockaddr_ip(addr: &SockaddrStorage) -> Option<IpAddr> {
    addr.as_sockaddr_in()
        .map(|sa| IpAddr::V4(sa.ip()))
        .or_else(|| addr.as_sockaddr_in6().map(|sa| IpAddr::V6(sa.ip())))
}

/// Find all networks network interfaces suitable for rwhod communication.
///
/// If `allowed_interfaces` is `Some`, only interfaces whose name is contained
/// in it are considered; otherwise all suitable interfaces are returned.
///
/// Interface addresses contained in any of the `excluded_addresses` ranges
/// are skipped.
pub fn determine_relevant_interfaces(
    allowed_interfaces: Option<&HashSet<String>>,
    excluded_addresses: &[IpRange],
) -> anyhow::Result<Vec<RwhodSendTarget>> {
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
            // interface must be in the configured allowlist, if any
            .filter(|iface| {
                allowed_interfaces
                    .is_none_or(|allowed| allowed.contains(iface.interface_name.as_str()))
            })
            // interface address must not be in the configured exclude list
            .filter(|iface| {
                let Some(local_addr) = iface.address.as_ref().and_then(sockaddr_ip) else {
                    return true;
                };
                let excluded = excluded_addresses
                    .iter()
                    .any(|range| range.contains(local_addr));
                if excluded {
                    tracing::debug!(
                        "Skipping excluded address {} on interface {}",
                        local_addr,
                        iface.interface_name
                    );
                }
                !excluded
            })
            .filter_map(|iface| {
                let neighbor_addr = if iface.flags.contains(InterfaceFlags::IFF_BROADCAST) {
                    match (
                        iface.address.as_ref().and_then(|a| a.as_sockaddr_in()),
                        iface.netmask.as_ref().and_then(|a| a.as_sockaddr_in()),
                    ) {
                        (Some(addr), Some(mask)) => {
                            Some(ipv4_broadcast_address(addr.ip(), mask.ip()).into())
                        }
                        _ => None,
                    }
                } else if iface.flags.contains(InterfaceFlags::IFF_POINTOPOINT) {
                    iface.destination.as_ref().and_then(sockaddr_ip)
                } else {
                    None
                };

                neighbor_addr.map(|ip_addr| RwhodSendTarget {
                    name: iface.interface_name,
                    addr: ip_addr,
                })
            })
            // keep first occurrence per interface name
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
    socket: Arc<UdpSocket>,
    interface: &RwhodSendTarget,
    packet: &Whod,
) -> anyhow::Result<()> {
    let serialized_packet = packet.to_bytes();

    // TODO: the old rwhod daemon doesn't actually ever listen to ipv6, maybe remove it
    let target_addr = match interface.addr {
        IpAddr::V4(addr) => SocketAddr::new(IpAddr::V4(addr), RWHOD_BROADCAST_PORT),
        IpAddr::V6(addr) => SocketAddr::new(IpAddr::V6(addr), RWHOD_BROADCAST_PORT),
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

pub async fn rwhod_packet_sender_task(
    socket: Arc<UdpSocket>,
    interfaces: Vec<RwhodSendTarget>,
    ignore_list: Option<IgnoreList>,
    send_interval: TokioDuration,
    mut realtime_update_trigger: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    let mut interval = interval(send_interval);
    let mut trigger_closed = false;

    loop {
        if trigger_closed {
            interval.tick().await;
        } else {
            tokio::select! {
                _ = interval.tick() => {}
                triggered = realtime_update_trigger.recv() => {
                    if triggered.is_some() {
                        tracing::debug!("Sending an early rwhod update due to realtime trigger");
                        interval.reset();
                        tokio::time::sleep(REALTIME_UPDATE_SETTLE_DELAY).await;
                    } else {
                        tracing::warn!(
                            "Realtime update channel closed unexpectedly; falling back to interval-only updates"
                        );
                        trigger_closed = true;
                        continue;
                    }
                }
            }
        }

        let status_update = match generate_rwhod_status_update(ignore_list.as_ref()) {
            Ok(status_update) => status_update,
            Err(e) => {
                tracing::error!("Failed to generate rwhod status update: {e:#}");
                continue;
            }
        };

        tracing::debug!("Generated rwhod packet: {:?}", status_update);

        let packet = match status_update.try_into() {
            Ok(packet) => packet,
            Err(e) => {
                tracing::error!("Failed to convert rwhod status update to packet: {e}");
                continue;
            }
        };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_broadcast_address() {
        assert_eq!(
            ipv4_broadcast_address(
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(255, 255, 255, 0)
            ),
            Ipv4Addr::new(192, 168, 1, 255)
        );

        assert_eq!(
            ipv4_broadcast_address(Ipv4Addr::new(10, 0, 5, 200), Ipv4Addr::new(255, 0, 0, 0)),
            Ipv4Addr::new(10, 255, 255, 255)
        );

        assert_eq!(
            ipv4_broadcast_address(
                Ipv4Addr::new(203, 0, 113, 42),
                Ipv4Addr::new(255, 255, 255, 255)
            ),
            Ipv4Addr::new(203, 0, 113, 42)
        );
    }

    #[test]
    fn test_determine_relevant_interfaces() {
        let interfaces = determine_relevant_interfaces(None, &[]).unwrap();
        for interface in interfaces {
            println!("Interface: {} Address: {}", interface.name, interface.addr);
        }
    }

    #[test]
    fn test_determine_relevant_interfaces_with_allowlist_excludes_unlisted() {
        let allowed = HashSet::from(["definitely-not-a-real-interface".to_string()]);
        let interfaces = determine_relevant_interfaces(Some(&allowed), &[]).unwrap();
        assert!(interfaces.is_empty());
    }

    #[test]
    fn test_determine_relevant_interfaces_with_catchall_exclude_list() {
        let excluded = ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        let interfaces = determine_relevant_interfaces(None, &excluded).unwrap();
        assert!(interfaces.is_empty());
    }
}
