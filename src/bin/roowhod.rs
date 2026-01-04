use std::net::SocketAddrV4;

use anyhow::Context;
use chrono::Timelike;
use roowho2_lib::proto::{Whod, WhodStatusUpdate};

const RWHOD_BROADCAST_PORT: u16 = 513;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, RWHOD_BROADCAST_PORT);
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    socket.set_broadcast(true)?;

    let mut buf = [0u8; Whod::MAX_SIZE];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        if len < Whod::HEADER_SIZE {
            eprintln!(
                "Received too short packet from {src}: {len} bytes (needs to be at least {} bytes)",
                Whod::HEADER_SIZE
            );
            continue;
        }
        let result: WhodStatusUpdate = Whod::from_bytes(&buf[..len])
            .context("Failed to parse whod packet")?
            .try_into()
            .map(|mut status_update: WhodStatusUpdate| {
                let timestamp = chrono::Utc::now()
                    .with_nanosecond(0)
                    .unwrap_or(chrono::Utc::now());
                status_update.recvtime = Some(timestamp);
                status_update
            })
            .map_err(|e| anyhow::anyhow!("Invalid whod packet: {}", e))?;

        println!("Received whod packet from {src}:\n{result:#?}");

        buf = [0u8; Whod::MAX_SIZE];
    }
}
