use std::{
    collections::HashMap,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context;
use clap::Parser;
use roowho2_lib::{
    proto::WhodStatusUpdate,
    server::{
        rwhod::{rwhod_packet_receiver_task, rwhod_packet_sender_task},
        varlink_api::varlink_client_server_task,
    },
};
use tokio::{net::UdpSocket, sync::RwLock};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(
    author = "Programvareverkstedet <projects@pvv.ntnu.no>",
    about,
    version
)]
struct Args {
    /// Path to configuration file
    #[arg(
        short = 'c',
        long = "config",
        default_value = "/etc/roowho2/roowho2.toml",
        value_name = "PATH"
    )]
    config_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let config = toml::from_str::<roowho2_lib::server::config::Config>(
        &std::fs::read_to_string(args.config_path)
            .context("Failed to read configuration file /etc/roowho2/roowho2.toml")?,
    )?;

    let fd_map: HashMap<String, OwnedFd> = HashMap::from_iter(
        sd_notify::listen_fds_with_names(false)?.map(|(fd_num, name)| {
            (
                name.clone(),
                // SAFETY: please don't mess around with file descriptors in random places
                //         around the codebase lol
                unsafe { std::os::fd::OwnedFd::from_raw_fd(fd_num) },
            )
        }),
    );

    let mut join_set = tokio::task::JoinSet::new();

    let whod_status_store = Arc::new(RwLock::new(HashMap::new()));

    if config.rwhod.enable {
        tracing::info!("Starting RWHOD server");

        let socket = fd_map
            .get("rwhod_socket")
            .map(|fd| {
                // SAFETY: see above
                let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd.as_raw_fd()) };
                std_socket.set_nonblocking(true)?;
                UdpSocket::from_std(std_socket)
            })
            .context("RWHOD server is enabled, but socket fd not provided by systemd")??;

        join_set.spawn(rwhod_server(socket, whod_status_store.clone()));
    } else {
        tracing::debug!("RWHOD server is disabled in configuration");
    }

    join_set.spawn(client_server(
        fd_map
            .get("client_socket")
            .context("RWHOD client-server socket fd not provided by systemd")?
            .try_clone()
            .context("Failed to clone RWHOD client-server socket fd")?,
        whod_status_store.clone(),
    ));

    join_set.spawn(ctrl_c_handler());

    join_set.join_next().await.unwrap()??;

    Ok(())
}

async fn ctrl_c_handler() -> anyhow::Result<()> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to listen for Ctrl-C: {}", e))
}

async fn rwhod_server(
    socket: UdpSocket,
    whod_status_store: Arc<RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
) -> anyhow::Result<()> {
    let socket = Arc::new(socket);

    let interfaces = roowho2_lib::server::rwhod::determine_relevant_interfaces()?;
    let sender_task = rwhod_packet_sender_task(socket.clone(), interfaces);

    let receiver_task = rwhod_packet_receiver_task(socket.clone(), whod_status_store);

    tokio::select! {
        res = sender_task => res?,
        res = receiver_task => res?,
    }

    Ok(())
}

async fn client_server(
    socket_fd: OwnedFd,
    whod_status_store: Arc<RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
) -> anyhow::Result<()> {
    // SAFETY: see above
    let std_socket =
        unsafe { std::os::unix::net::UnixListener::from_raw_fd(socket_fd.as_raw_fd()) };
    std_socket.set_nonblocking(true)?;
    let zlink_listener = zlink::unix::Listener::try_from(OwnedFd::from(std_socket))?;
    let client_server_task = varlink_client_server_task(zlink_listener, whod_status_store);

    client_server_task.await?;

    Ok(())
}
