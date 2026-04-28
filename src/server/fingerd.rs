mod local_email;
mod local_user_info;
mod remote_user_info;

pub use local_user_info::{finger_utmp_users, search_for_user};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FingerRequestNetworking {
    Any,
    IPv4Only,
    IPv6Only,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FingerRequestInfo {
    ShortHost { restrict_gecos: bool },
    ShortOffice { restrict_gecos: bool },
    Long { prevent_files: bool },
}
