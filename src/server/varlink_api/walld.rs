use std::time::Duration;

use nix::unistd::gethostname;
use serde::{Deserialize, Serialize};
use zlink::ReplyError;

use crate::server::walld::tty_utils::{self, TtyError};

#[zlink::proxy("no.ntnu.pvv.roowho2.walld")]
pub trait VarlinkWalldClientProxy {
    /// Broadcast `message` to the tty of every logged in user, optionally restricted to `group`.
    async fn wall(
        &mut self,
        source_tty: Option<String>,
        message: String,
        group: Option<String>,
        nobanner: bool,
        timeout_secs: u32,
    ) -> zlink::Result<Result<VarlinkWalldClientResponse, VarlinkWalldClientError>>;

    /// Send `message` to a the tty of a single user, optionally targeting a specific tty.
    async fn write(
        &mut self,
        source_tty: Option<String>,
        target_user: String,
        target_tty: Option<String>,
        message: String,
    ) -> zlink::Result<Result<VarlinkWalldClientResponse, VarlinkWalldClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum VarlinkWalldClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.walld.Wall")]
    Wall {
        source_tty: Option<String>,
        message: String,
        group: Option<String>,
        nobanner: bool,
        timeout_secs: u32,
    },

    #[serde(rename = "no.ntnu.pvv.roowho2.walld.Write")]
    Write {
        source_tty: Option<String>,
        target_user: String,
        target_tty: Option<String>,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VarlinkWalldClientResponse {
    Wall(VarlinkWallResponse),
    Write(VarlinkWriteResponse),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VarlinkWallResponse {
    pub delivered: Vec<VarlinkWallDelivery>,
    pub failures: Vec<VarlinkWallDeliveryFailure>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarlinkWallDelivery {
    pub user: String,
    pub tty: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarlinkWallDeliveryFailure {
    pub user: String,
    pub tty: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VarlinkWriteResponse {
    /// The tty the message was actually delivered to.
    /// This is relevant when the caller didn't specify one, and it was picked automatically.
    pub tty: String,
}

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.walld")]
pub enum VarlinkWalldClientError {
    /// The walld service is not enabled on the server.
    Disabled,
    /// Caller was not authorized by polkit to perform the request.
    NotAuthorized,
    /// The target user is not logged in anywhere.
    UserNotLoggedIn { user: String },
    /// The target user has disabled incoming messages on the relevant tty/ttys.
    MessagesDisabled { user: String },
    /// The requested tty does not belong to the target user, or does not exist.
    TtyNotFound { user: String, tty: String },
    /// The request parameters were invalid (e.g. unknown group).
    InvalidRequest { message: String },
    /// The request timed out.
    TimedOut,
    /// Something went wrong while talking to the tty (open/write failure).
    Io { message: String },
}

// TODO: use `thiserror` to derive `Display` the impl instead.

impl std::fmt::Display for VarlinkWalldClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VarlinkWalldClientError::Disabled => {
                write!(f, "The walld service is disabled on the server")
            }
            VarlinkWalldClientError::NotAuthorized => write!(f, "Caller is not authorized"),
            VarlinkWalldClientError::UserNotLoggedIn { user } => {
                write!(f, "User '{}' is not logged in", user)
            }
            VarlinkWalldClientError::MessagesDisabled { user } => {
                write!(f, "User '{}' has disabled incoming messages", user)
            }
            VarlinkWalldClientError::TtyNotFound { user, tty } => {
                write!(f, "Tty '{}' not found for user '{}'", tty, user)
            }
            VarlinkWalldClientError::InvalidRequest { message } => {
                write!(f, "Invalid request: {}", message)
            }
            VarlinkWalldClientError::TimedOut => write!(f, "Request timed out"),
            VarlinkWalldClientError::Io { message } => {
                write!(f, "I/O error while sending message: {}", message)
            }
        }
    }
}

fn username_for_uid(uid: u32) -> String {
    users::get_user_by_uid(uid)
        .map(|u| u.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| uid.to_string())
}

fn hostname() -> String {
    gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn tty_error_to_walld_error(user: &str, tty: &str, err: TtyError) -> VarlinkWalldClientError {
    match err {
        TtyError::NotFound(_) | TtyError::InvalidName(_) | TtyError::NotCharacterDevice(_) => {
            VarlinkWalldClientError::TtyNotFound {
                user: user.to_string(),
                tty: tty.to_string(),
            }
        }
        TtyError::Unavailable(_) => VarlinkWalldClientError::MessagesDisabled {
            user: user.to_string(),
        },
        other => VarlinkWalldClientError::Io {
            message: other.to_string(),
        },
    }
}

// TODO: have the client send the name of the TTY
//       verify that the TTY is owned by the user from peercred.

pub async fn handle_wall_request(
    _source_pid: u32,
    source_uid: u32,
    source_tty: Option<String>,
    message: String,
    group: Option<String>,
    nobanner: bool,
    timeout_secs: u32,
) -> Result<VarlinkWallResponse, VarlinkWalldClientError> {
    if let Some(group) = &group
        && users::get_group_by_name(group).is_none()
    {
        return Err(VarlinkWalldClientError::InvalidRequest {
            message: format!("unknown group {group:?}"),
        });
    }

    // TODO: authorize against polkit

    let body = tty_utils::format_wall_message(
        &username_for_uid(source_uid),
        &hostname(),
        source_tty.as_deref(),
        &message,
        nobanner,
    );

    let timeout = Duration::from_secs(timeout_secs.max(1) as u64);
    let sessions = tty_utils::all_sessions(group.as_deref());

    let mut response = VarlinkWallResponse::default();
    for session in sessions {
        match tty_utils::deliver_message(&session.tty, &body, timeout).await {
            Ok(()) => response.delivered.push(VarlinkWallDelivery {
                user: session.user,
                tty: session.tty,
            }),
            Err(err) => response.failures.push(VarlinkWallDeliveryFailure {
                user: session.user,
                tty: session.tty,
                reason: err.to_string(),
            }),
        }
    }

    Ok(response)
}

const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn handle_write_request(
    _source_pid: u32,
    source_uid: u32,
    source_tty: Option<String>,
    user: String,
    tty: Option<String>,
    message: String,
) -> Result<VarlinkWriteResponse, VarlinkWalldClientError> {
    // TODO: authorize against polkit

    let sessions = tty_utils::sessions_for_user(&user);
    if sessions.is_empty() {
        return Err(VarlinkWalldClientError::UserNotLoggedIn { user });
    }

    let target_tty = match &tty {
        Some(tty) => {
            if !sessions.iter().any(|s| &s.tty == tty) {
                return Err(VarlinkWalldClientError::TtyNotFound {
                    user,
                    tty: tty.clone(),
                });
            }
            tty.clone()
        }
        // No tty requested, pick the one the user touched most recently
        None => sessions
            .iter()
            .filter_map(|s| {
                tty_utils::stat_tty(&s.tty)
                    .ok()
                    .map(|info| (s.tty.clone(), info))
            })
            .max_by_key(|(_, info)| info.atime)
            .map(|(tty, _)| tty)
            .ok_or_else(|| VarlinkWalldClientError::MessagesDisabled { user: user.clone() })?,
    };

    match tty_utils::stat_tty(&target_tty) {
        Ok(info) if info.writable => {}
        Ok(_) => return Err(VarlinkWalldClientError::MessagesDisabled { user }),
        Err(_) => {
            return Err(VarlinkWalldClientError::TtyNotFound {
                user,
                tty: target_tty,
            });
        }
    }

    let source_user = username_for_uid(source_uid);
    let body =
        tty_utils::format_write_message(&source_user, &hostname(), source_tty.as_deref(), &message);

    tty_utils::deliver_message(&target_tty, &body, DEFAULT_WRITE_TIMEOUT)
        .await
        .map_err(|err| tty_error_to_walld_error(&user, &target_tty, err))?;

    Ok(VarlinkWriteResponse { tty: target_tty })
}
