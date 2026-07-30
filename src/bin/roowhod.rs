use std::{
    collections::{HashMap, HashSet},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use tokio::{net::UdpSocket, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

use roowho2_lib::{
    server::{
        config::{DEFAULT_CONFIG_PATH, LogLevel},
        ignore_list::IgnoreList,
        rwhod::{
            RwhodStatusRegistry, RwhodStatusStore, rwhod_packet_receiver_task,
            rwhod_packet_sender_task,
        },
        varlink_api::varlink_client_server_task,
    },
    version,
};

#[derive(Parser)]
#[command(
  author = "Programvareverkstedet <projects@pvv.ntnu.no>",
  about,
  version,
  long_version = version::LONG_VERSION
)]
struct Args {
    /// Path to configuration file
    #[arg(
        short = 'c',
        long = "config",
        default_value = DEFAULT_CONFIG_PATH,
        value_name = "PATH"
    )]
    config_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let config = toml::from_str::<roowho2_lib::server::config::Config>(
        &std::fs::read_to_string(&args.config_path).context(format!(
            "Failed to read configuration file {:?}",
            args.config_path
        ))?,
    )?;

    let log_filter = match config.log_level.unwrap_or(LogLevel::Info) {
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    };

    let subscriber = tracing_subscriber::registry()
        .with(log_filter)
        .with(tracing_journald::layer()?);

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set global default tracing subscriber")?;

    let rwhod_ignore_list = IgnoreList::load_optional(config.rwhod.ignore_list_path.as_deref())?;
    let finger_ignore_list = IgnoreList::load_optional(config.fingerd.ignore_list_path.as_deref())?;

    let fd_map: HashMap<String, OwnedFd> =
        HashMap::from_iter(sd_notify::listen_fds_with_names()?.map(|(fd_num, name)| {
            (
                name.clone(),
                // SAFETY: please don't mess around with file descriptors in random places
                //         around the codebase lol
                unsafe { std::os::fd::OwnedFd::from_raw_fd(fd_num) },
            )
        }));

    let mut join_set = tokio::task::JoinSet::new();

    let whod_status_store: RwhodStatusStore = Arc::new(RwLock::new(RwhodStatusRegistry::new(
        config.rwhod.max_status_entries(),
    )));

    let client_server_token = CancellationToken::new();
    let client_server_token_ = client_server_token.clone();
    tokio::spawn(async move {
        client_server_token_.cancelled().await;
        tracing::info!("RWHOD client-server is now accepting connections");
        #[cfg(feature = "systemd")]
        sd_notify::notify(&[sd_notify::NotifyState::Ready]).ok();
        Ok::<(), anyhow::Error>(())
    });

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

        let audit_socket: Option<OwnedFd> = fd_map
            .get("audit_socket")
            .map(|fd| fd.try_clone())
            .transpose()
            .context("Failed to clone audit socket fd")?;

        join_set.spawn(rwhod_server(
            socket,
            whod_status_store.clone(),
            rwhod_ignore_list.clone(),
            config.rwhod.interfaces.clone(),
            config.rwhod.send_interval(),
            config.rwhod.realtime_updates_enabled(),
            audit_socket,
        ));
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
        config.rwhod.enable,
        config.fingerd.enable,
        config.walld.enable,
        finger_ignore_list,
        client_server_token,
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
    whod_status_store: RwhodStatusStore,
    ignore_list: Option<IgnoreList>,
    allowed_interfaces: Option<HashSet<String>>,
    send_interval: Duration,
    realtime_updates_enabled: bool,
    audit_socket: Option<OwnedFd>,
) -> anyhow::Result<()> {
    let socket = Arc::new(socket);

    let interfaces =
        roowho2_lib::server::rwhod::determine_relevant_interfaces(allowed_interfaces.as_ref())?;

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    match (realtime_updates_enabled, audit_socket) {
        (true, Some(fd)) => {
            tokio::spawn(roowho2_lib::server::rwhod::audit_change_notifier(tx, fd));
        }
        (true, None) => {
            tracing::warn!(
                "rwhod.realtime_updates is enabled, but no audit socket fd was provided by \
                 systemd (e.g. the kernel might not have been booted with `audit=1`); \
                 falling back to interval-only updates"
            );
        }
        (false, _) => {}
    }

    let sender_task =
        rwhod_packet_sender_task(socket.clone(), interfaces, ignore_list, send_interval, rx);
    let receiver_task = rwhod_packet_receiver_task(socket.clone(), whod_status_store);

    tokio::select! {
        res = sender_task => res?,
        res = receiver_task => res?,
    }

    Ok(())
}

async fn client_server(
    socket_fd: OwnedFd,
    whod_status_store: RwhodStatusStore,
    rwhod_enabled: bool,
    fingerd_enabled: bool,
    walld_enabled: bool,
    finger_ignore_list: Option<IgnoreList>,
    startup_token: CancellationToken,
) -> anyhow::Result<()> {
    // SAFETY: see above
    let std_socket =
        unsafe { std::os::unix::net::UnixListener::from_raw_fd(socket_fd.as_raw_fd()) };
    std_socket.set_nonblocking(true)?;
    let zlink_listener = zlink::tokio::unix::Listener::try_from(OwnedFd::from(std_socket))?;
    let client_server_task = varlink_client_server_task(
        zlink_listener,
        whod_status_store,
        rwhod_enabled,
        fingerd_enabled,
        walld_enabled,
        finger_ignore_list,
    );

    startup_token.cancel();

    client_server_task.await?;

    Ok(())
}
