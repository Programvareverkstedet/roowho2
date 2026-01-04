use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use roowho2_lib::server::rwhod::{
    RWHOD_BROADCAST_PORT, rwhod_packet_receiver_task, rwhod_packet_sender_task,
};
use tokio::sync::RwLock;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RWHOD_BROADCAST_PORT);
    tracing::info!("Binding RWHOD socket to {}", addr);
    let socket = Arc::new(tokio::net::UdpSocket::bind(addr).await?);
    socket.set_broadcast(true)?;

    let interfaces = roowho2_lib::server::rwhod::determine_relevant_interfaces()?;
    let sender_task = rwhod_packet_sender_task(socket.clone(), interfaces);

    let status_store = Arc::new(RwLock::new(HashMap::new()));
    let receiver_task = rwhod_packet_receiver_task(socket.clone(), status_store);

    tokio::select! {
        res = sender_task => {
            if let Err(err) = res {
                eprintln!("RWHOD sender task error: {}", err);
            }
        }
        res = receiver_task => {
            if let Err(err) = res {
                eprintln!("RWHOD receiver task error: {}", err);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("Received Ctrl-C, shutting down.");
        }
    }

    Ok(())
}
