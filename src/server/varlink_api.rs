use std::{collections::HashMap, os::fd::OwnedFd, time::Duration};

use anyhow::Context;
use futures_util::stream;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use zlink::{
    ReplyError,
    service::MethodReply,
    tokio::unix::{Listener as UnixListener, Stream as UnixStream},
};

use crate::{
    proto::{WhodStatusUpdate, WhodUserEntry, finger_protocol::FingerResponseUserEntry},
    server::{
        fingerd::{self, FingerRequestInfo, FingerRequestNetworking, finger_utmp_users},
        ignore_list::IgnoreList,
        rwhod::RwhodStatusStore,
    },
};

pub const DEFAULT_CLIENT_SERVER_SOCKET_PATH: &str = "/run/roowho2/roowho2.varlink";

// Types for 'no.ntnu.pvv.roowho2.rwhod'

#[zlink::proxy("no.ntnu.pvv.roowho2.rwhod")]
pub trait VarlinkRwhodClientProxy {
    /// `max_idle_seconds` is the maximum idle time (in seconds) for a user
    /// to be included in the response. `None` means no limit (i.e. the old
    /// `all: true`). The client is expected to always send an explicit
    /// value, defaulting to whatever it considers reasonable if the user
    /// didn't ask for a specific limit.
    async fn rwho(
        &mut self,
        max_idle_seconds: Option<i64>,
    ) -> zlink::Result<Result<VarlinkRwhoResponse, VarlinkRwhodClientError>>;

    /// See [`VarlinkRwhodClientProxy::rwho`] for the meaning of `max_idle_seconds`.
    async fn ruptime(
        &mut self,
        max_idle_seconds: Option<i64>,
    ) -> zlink::Result<Result<VarlinkRuptimeResponse, VarlinkRwhodClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum VarlinkRwhodClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.rwhod.Rwho")]
    Rwho {
        /// Maximum idle time (in seconds) for a user to be included.
        /// `None` means no limit (i.e. return all users).
        max_idle_seconds: Option<i64>,
    },

    #[serde(rename = "no.ntnu.pvv.roowho2.rwhod.Ruptime")]
    Ruptime {
        /// Maximum idle time (in seconds) for a user to be counted.
        /// `None` means no limit (i.e. return all users).
        max_idle_seconds: Option<i64>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum VarlinkRwhodClientResponse {
    Rwho(VarlinkRwhoResponse),
    Ruptime(VarlinkRuptimeResponse),
}

pub type VarlinkRwhoResponse = HashMap<String, Vec<WhodUserEntry>>;
pub type VarlinkRuptimeResponse = Vec<WhodStatusUpdate>;

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.rwhod")]
pub enum VarlinkRwhodClientError {
    InvalidRequest,
    TimedOut,
    Disabled,
}

// Types for 'no.ntnu.pvv.roowho2.finger'

#[zlink::proxy("no.ntnu.pvv.roowho2.finger")]
pub trait VarlinkFingerClientProxy {
    async fn finger(
        &mut self,
        user_queries: Option<Vec<String>>,
        match_fullnames: bool,
        request_info: FingerRequestInfo,
        request_networking: FingerRequestNetworking,
        disable_user_account_db: bool,
        raw_remote_output: bool,
    ) -> zlink::Result<Result<VarlinkFingerResponse, VarlinkFingerClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum VarlinkFingerClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.finger.Finger")]
    Finger {
        user_queries: Option<Vec<String>>,
        match_fullnames: bool,
        request_info: FingerRequestInfo,
        request_networking: FingerRequestNetworking,
        disable_user_account_db: bool,
        raw_remote_output: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum VarlinkFingerClientResponse {
    Finger(VarlinkFingerResponse),
}

pub type VarlinkFingerResponse = Vec<FingerResponseUserEntry>;

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.finger")]
pub enum VarlinkFingerClientError {
    InvalidRequest,
    TimedOut,
    Disabled,
}

// Types for 'no.ntnu.pvv.roowho2.walld'

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

// --------------------

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum VarlinkMethod {
    Rwhod(VarlinkRwhodClientRequest),
    Finger(VarlinkFingerClientRequest),
    Walld(VarlinkWalldClientRequest),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum VarlinkReply {
    Rwhod(VarlinkRwhodClientResponse),
    Finger(VarlinkFingerClientResponse),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum VarlinkReplyError {
    Rwhod(VarlinkRwhodClientError),
    Finger(VarlinkFingerClientError),
}

#[derive(Debug, Clone)]
pub struct VarlinkRoowhoo2ClientServer {
    whod_status_store: RwhodStatusStore,
    rwhod_enabled: bool,
    fingerd_enabled: bool,
    finger_ignore_list: Option<IgnoreList>,
}

impl VarlinkRoowhoo2ClientServer {
    pub fn new(
        whod_status_store: RwhodStatusStore,
        rwhod_enabled: bool,
        fingerd_enabled: bool,
        finger_ignore_list: Option<IgnoreList>,
    ) -> Self {
        Self {
            whod_status_store,
            rwhod_enabled,
            fingerd_enabled,
            finger_ignore_list,
        }
    }
}

impl VarlinkRoowhoo2ClientServer {
    async fn handle_rwho_request(
        &self,
        max_idle_time: Option<chrono::TimeDelta>,
    ) -> VarlinkRwhoResponse {
        tracing::debug!(?max_idle_time, "Handling Rwho request");
        let store = self.whod_status_store.read().await;

        store
            .values()
            .filter_map(|status_update| {
                let users: Vec<WhodUserEntry> = status_update
                    .users
                    .iter()
                    .filter(|user| max_idle_time.is_none_or(|max| user.idle_time < max))
                    .cloned()
                    .collect();

                (!users.is_empty()).then(|| (status_update.hostname.clone(), users))
            })
            .collect()
    }

    async fn handle_ruptime_request(
        &self,
        max_idle_time: Option<chrono::TimeDelta>,
    ) -> VarlinkRuptimeResponse {
        tracing::debug!(?max_idle_time, "Handling Ruptime request");
        let store = self.whod_status_store.read().await;

        store
            .values()
            .cloned()
            .map(|mut status_update| {
                if let Some(max_idle_time) = max_idle_time {
                    status_update
                        .users
                        .retain(|user| user.idle_time < max_idle_time);
                }
                status_update
            })
            .collect()
    }

    async fn handle_finger_request(
        &self,
        user_queries: Option<Vec<String>>,
        match_fullnames: bool,
        request_info: FingerRequestInfo,
        _request_networking: FingerRequestNetworking,
        _disable_user_account_db: bool,
        _raw_remote_output: bool,
    ) -> VarlinkFingerResponse {
        tracing::debug!(
          user_queries = ?user_queries,
          match_fullnames = match_fullnames,
          request_info = ?request_info,
          "Handling Finger request",
        );
        match user_queries {
            Some(usernames) => usernames
                .into_iter()
                .flat_map::<Vec<_>, _>(|username| {
                    fingerd::search_for_user(
                        &username,
                        match_fullnames,
                        &request_info,
                        self.finger_ignore_list.as_ref(),
                    )
                    .into_iter()
                    .map(|res| (username.clone(), res))
                    .collect()
                })
                .dedup_by(|a, b| match (&a.1, &b.1) {
                    (Ok(user_a), Ok(user_b)) => user_a.username == user_b.username,
                    _ => false,
                })
                .filter_map(|(username, user)| match user {
                    Ok(user_info) => Some(user_info),
                    Err(err) => {
                        tracing::error!(
                            "Error retrieving local user information for '{}': {}",
                            username,
                            err
                        );
                        None
                    }
                })
                .map(Box::new)
                .map(FingerResponseUserEntry::Structured)
                .collect(),
            None => finger_utmp_users(&request_info, self.finger_ignore_list.as_ref())
                .into_iter()
                .filter_map(|res| match res {
                    Ok(user_info) => Some(user_info),
                    Err(err) => {
                        tracing::error!("Error retrieving local user information: {}", err);
                        None
                    }
                })
                .map(Box::new)
                .map(FingerResponseUserEntry::Structured)
                .collect(),
        }
    }
}

impl zlink::Service<UnixStream> for VarlinkRoowhoo2ClientServer {
    type MethodCall<'de> = VarlinkMethod;
    type ReplyParams<'se> = VarlinkReply;
    type ReplyError<'se> = VarlinkReplyError;
    type ReplyStreamParams = ();
    type ReplyStream = stream::Empty<(
        Result<zlink::Reply<Self::ReplyStreamParams>, Self::ReplyStreamError>,
        Vec<OwnedFd>,
    )>;
    type ReplyStreamError = ();

    async fn handle<'service>(
        &'service mut self,
        call: &'service zlink::Call<Self::MethodCall<'_>>,
        _conn: &mut zlink::Connection<UnixStream>,
        _fds: Vec<OwnedFd>,
    ) -> zlink::service::HandleResult<
        Self::ReplyParams<'service>,
        Self::ReplyStream,
        Self::ReplyError<'service>,
    > {
        match call.method() {
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Rwho { max_idle_seconds }) => {
                if !self.rwhod_enabled {
                    return (
                        MethodReply::Error(VarlinkReplyError::Rwhod(
                            VarlinkRwhodClientError::Disabled,
                        )),
                        Default::default(),
                    );
                }

                let max_idle_time = match max_idle_seconds
                    .map(|secs| chrono::TimeDelta::try_seconds(secs).ok_or(()))
                    .transpose()
                    .map_err(|_| {
                        tracing::error!(
                            "Received out-of-range max_idle_seconds: {:?}",
                            max_idle_seconds
                        );
                        (
                            MethodReply::Error(VarlinkReplyError::Rwhod(
                                VarlinkRwhodClientError::InvalidRequest,
                            )),
                            Default::default(),
                        )
                    }) {
                    Ok(max_idle_time) => max_idle_time,
                    Err(err) => return err,
                };

                let result = match timeout(
                    Duration::from_secs(2),
                    self.handle_rwho_request(max_idle_time),
                )
                .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        tracing::error!("Rwho request timed out after 2 seconds");
                        return (
                            MethodReply::Error(VarlinkReplyError::Rwhod(
                                VarlinkRwhodClientError::TimedOut,
                            )),
                            Default::default(),
                        );
                    }
                };

                (
                    MethodReply::Single(Some(VarlinkReply::Rwhod(
                        VarlinkRwhodClientResponse::Rwho(result),
                    ))),
                    Default::default(),
                )
            }
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Ruptime { max_idle_seconds }) => {
                if !self.rwhod_enabled {
                    return (
                        MethodReply::Error(VarlinkReplyError::Rwhod(
                            VarlinkRwhodClientError::Disabled,
                        )),
                        Default::default(),
                    );
                }

                let max_idle_time = match max_idle_seconds
                    .map(|secs| chrono::TimeDelta::try_seconds(secs).ok_or(()))
                    .transpose()
                    .map_err(|_| {
                        tracing::error!(
                            "Received out-of-range max_idle_seconds: {:?}",
                            max_idle_seconds
                        );
                        (
                            MethodReply::Error(VarlinkReplyError::Rwhod(
                                VarlinkRwhodClientError::InvalidRequest,
                            )),
                            Default::default(),
                        )
                    }) {
                    Ok(max_idle_time) => max_idle_time,
                    Err(err) => return err,
                };

                let result = match timeout(
                    Duration::from_secs(2),
                    self.handle_ruptime_request(max_idle_time),
                )
                .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        tracing::error!("Ruptime request timed out after 2 seconds");
                        return (
                            MethodReply::Error(VarlinkReplyError::Rwhod(
                                VarlinkRwhodClientError::TimedOut,
                            )),
                            Default::default(),
                        );
                    }
                };

                (
                    MethodReply::Single(Some(VarlinkReply::Rwhod(
                        VarlinkRwhodClientResponse::Ruptime(result),
                    ))),
                    Default::default(),
                )
            }
            VarlinkMethod::Finger(VarlinkFingerClientRequest::Finger {
                user_queries,
                match_fullnames,
                request_info,
                request_networking,
                disable_user_account_db,
                raw_remote_output,
            }) => {
                if !self.fingerd_enabled {
                    return (
                        MethodReply::Error(VarlinkReplyError::Finger(
                            VarlinkFingerClientError::Disabled,
                        )),
                        Default::default(),
                    );
                }

                let result = match timeout(
                    Duration::from_secs(2),
                    self.handle_finger_request(
                        user_queries.clone(),
                        *match_fullnames,
                        request_info.clone(),
                        request_networking.clone(),
                        *disable_user_account_db,
                        *raw_remote_output,
                    ),
                )
                .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        tracing::error!("Finger request timed out after 2 seconds");
                        return (
                            MethodReply::Error(VarlinkReplyError::Finger(
                                VarlinkFingerClientError::TimedOut,
                            )),
                            Default::default(),
                        );
                    }
                };

                (
                    MethodReply::Single(Some(VarlinkReply::Finger(
                        VarlinkFingerClientResponse::Finger(result),
                    ))),
                    Default::default(),
                )
            }
            VarlinkMethod::Walld(VarlinkWalldClientRequest::Wall { .. }) => {
                tracing::error!("Received Wall request, but walld service is not implemented");
                (
                    MethodReply::Error(VarlinkReplyError::Rwhod(
                        VarlinkRwhodClientError::InvalidRequest,
                    )),
                    Default::default(),
                )
            }
            VarlinkMethod::Walld(VarlinkWalldClientRequest::Write { .. }) => {
                tracing::error!("Received Write request, but walld service is not implemented");
                (
                    MethodReply::Error(VarlinkReplyError::Rwhod(
                        VarlinkRwhodClientError::InvalidRequest,
                    )),
                    Default::default(),
                )
            }
        }
    }
}

pub async fn varlink_client_server_task(
    socket: UnixListener,
    whod_status_store: RwhodStatusStore,
    rwhod_enabled: bool,
    fingerd_enabled: bool,
    finger_ignore_list: Option<IgnoreList>,
) -> anyhow::Result<()> {
    let service = VarlinkRoowhoo2ClientServer::new(
        whod_status_store,
        rwhod_enabled,
        fingerd_enabled,
        finger_ignore_list,
    );

    let server = zlink::Server::new(socket, service);

    tracing::info!("Starting Rwhod client API server");

    server
        .run()
        .await
        .context("Rwhod client API server failed")?;

    Ok(())
}
