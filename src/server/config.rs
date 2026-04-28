use std::net::SocketAddrV4;

use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/roowho2/config.toml";

pub const DEFAULT_CLIENT_SOCKET_PATH: &str = "/run/roowho2/server_client.sock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Logging level for the daemon.
    pub log_level: Option<LogLevel>,

    /// Configuration for the rwhod server.
    pub rwhod: RwhodConfig,

    /// Path to the Unix domain socket for client-server communication.
    ///
    /// If left as `None`, the server expects to be served a file descriptor to the socket named 'client'.
    pub client_socket_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwhodConfig {
    /// Enable or disable the rwhod server functionality.
    pub enable: bool,

    /// Network interfaces to listen on (e.g., ["eth0", "wlan0"]).
    ///
    /// If left as `None`, the server will automatically determine relevant interfaces.
    ///
    /// Note that if `broadcast_addresses` is specified, this field is ignored.
    pub interfaces: Option<Vec<String>>,

    /// Broadcast addresses to send rwhod packets to.
    ///
    /// If left as `None`, the server will automatically determine broadcast addresses for the selected interfaces.
    pub broadcast_addresses: Option<Vec<SocketAddrV4>>,
}
