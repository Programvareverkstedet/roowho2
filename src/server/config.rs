use std::{collections::HashSet, path::PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/roowho2/config.toml";

pub const DEFAULT_CLIENT_SOCKET_PATH: &str = "/run/roowho2/server_client.sock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Logging level for the daemon.
    pub log_level: Option<LogLevel>,

    /// Configuration for the rwhod server.
    pub rwhod: RwhodConfig,

    /// Configuration for the fingerd server.
    pub fingerd: FingerdConfig,

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

    /// Path to the ignore list for users that should be hidden from rwhod.
    pub ignore_list_path: Option<PathBuf>,

    /// Network interfaces to send rwhod packets on (e.g., ["eth0", "wlan0"]).
    ///
    /// If left as `None`, the server will send on all relevant interfaces it can find.
    pub interfaces: Option<HashSet<String>>,

    /// Interval between rwhod status packet broadcasts.
    ///
    /// If left as `None`, defaults to 60 seconds.
    pub send_interval_seconds: Option<u64>,

    /// Maximum number of distinct hosts to keep rwhod status records for at
    /// the same time. Once at capacity, the least recently updated record
    /// is evicted to make room for a newly-seen host.
    ///
    /// If left as `None`, defaults to 4096.
    pub max_status_entries: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerdConfig {
    /// Enable or disable the fingerd server functionality.
    pub enable: bool,

    /// Path to the ignore list for users that should be hidden from fingerd.
    pub ignore_list_path: Option<PathBuf>,
}
