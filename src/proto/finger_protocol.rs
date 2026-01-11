use std::path::PathBuf;

use chrono::{DateTime, Utc};
use nix::libc::uid_t;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerPerson {
    /// User id
    uid: uid_t,
    /// User' home directory
    dir: PathBuf,
    /// Home phone no.
    homephone: String,
    /// Login name
    name: String,
    /// Office name
    office: String,
    /// Office phone no.
    officephone: String,
    /// Full name
    realname: String,
    /// User's shell
    shell: String,
    /// Last time mail was read
    mailread: DateTime<Utc>,
    /// Last time mail was received
    mailrecv: DateTime<Utc>,
    /// List of where the user is or has been
    where_: Vec<FingerWhere>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerWhere {
    /// Type/status of request
    status: FingerWhereStatus,
    /// Tty is writable
    writable: bool,
    /// Time of (last) login
    loginat: DateTime<Utc>,
    /// how long idle (if logged in)
    idletime: DateTime<Utc>,
    // TODO: are technically limited by UT_LINESIZE and UT_HOSTSIZE
    /// Tty line
    tty: String,
    /// Remote hostname
    host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub enum FingerWhereStatus {
    LastLog,
    LoggedIn,
}
