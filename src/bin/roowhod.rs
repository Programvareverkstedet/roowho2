use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use anyhow::Context;
use roowho2_lib::server::rwhod::{
    RWHOD_BROADCAST_PORT, rwhod_client_server_task, rwhod_packet_receiver_task,
    rwhod_packet_sender_task,
};
use tokio::sync::RwLock;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let config = toml::from_str::<roowho2_lib::server::config::Config>(
        &std::fs::read_to_string("/etc/roowho2/roowho2.toml")
            .context("Failed to read configuration file /etc/roowho2/roowho2.toml")?,
    )?;

    let mut join_set = tokio::task::JoinSet::new();

    if config.rwhod.enable {
        tracing::info!("Starting RWHOD server");

        join_set.spawn(rwhod_server());
    } else {
        tracing::debug!("RWHOD server is disabled in configuration");
    }

    join_set.spawn(ctrl_c_handler());

    join_set.join_next().await.unwrap()??;

    Ok(())
}

async fn ctrl_c_handler() -> anyhow::Result<()> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to listen for Ctrl-C: {}", e))
}

async fn rwhod_server() -> anyhow::Result<()> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RWHOD_BROADCAST_PORT);
    tracing::debug!("Binding RWHOD socket to {}", addr);
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .context("Failed to bind RWHOD UDP socket")
        .and_then(|socket| {
            socket.set_broadcast(true)?;
            Ok(socket)
        })
        .context("Failed to enable broadcast on RWHOD UDP socket")
        .map(Arc::new)?;

    let interfaces = roowho2_lib::server::rwhod::determine_relevant_interfaces()?;
    let sender_task = rwhod_packet_sender_task(socket.clone(), interfaces);

    let status_store = Arc::new(RwLock::new(HashMap::new()));
    let receiver_task = rwhod_packet_receiver_task(socket.clone(), status_store.clone());

    tracing::debug!("Binding RWHOD client-server socket at /run/roowho2/rwhod.socket");
    let client_server_socket = zlink::unix::bind("/run/roowho2/rwhod.varlink")?;
    let client_server_task = rwhod_client_server_task(client_server_socket, status_store.clone());

    tokio::select! {
        res = sender_task => res?,
        res = receiver_task => res?,
        res = client_server_task => res?,
    }

    Ok(())
}
