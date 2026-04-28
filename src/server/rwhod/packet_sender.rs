use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::UdpSocket,
    time::{Duration as TokioDuration, interval},
};

use crate::{proto::Whod, server::rwhod::rwhod_status::generate_rwhod_status_update};

/// Default port for rwhod communication.
pub const RWHOD_BROADCAST_PORT: u16 = 513;

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
) -> anyhow::Result<()> {
    let mut interval = interval(TokioDuration::from_secs(60));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_relevant_interfaces() {
        let interfaces = determine_relevant_interfaces().unwrap();
        for interface in interfaces {
            println!("Interface: {} Address: {}", interface.name, interface.addr);
        }
    }
}
