use serde::{Deserialize, Serialize};
use zlink::ReplyError;

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum VarlinkWalldClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.walld.Wall")]
    Wall {
        message: String,
        group: Option<String>,
        nobanner: bool,
        timeout_secs: u32,
    },

    #[serde(rename = "no.ntnu.pvv.roowho2.walld.Write")]
    Write {
        user: String,
        tty: Option<String>,
        message: String,
    },
}

#[zlink::proxy("no.ntnu.pvv.roowho2.walld")]
pub trait VarlinkWalldClientProxy {
    /// Broadcast `message` to the tty of every logged in user, optionally restricted to `group`.
    async fn wall(
        &mut self,
        message: String,
        group: Option<String>,
        nobanner: bool,
        timeout_secs: u32,
    ) -> zlink::Result<Result<VarlinkWalldClientResponse, VarlinkWalldClientError>>;

    /// Send `message` to a the tty of a single `user`, optionally targeting a specific `tty`.
    async fn write(
        &mut self,
        user: String,
        tty: Option<String>,
        message: String,
    ) -> zlink::Result<Result<VarlinkWalldClientResponse, VarlinkWalldClientError>>;
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
