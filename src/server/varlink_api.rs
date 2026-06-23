use std::{os::fd::OwnedFd, time::Duration};

use anyhow::Context;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use zlink::{ReplyError, service::MethodReply};

use crate::{
    proto::{WhodStatusUpdate, WhodUserEntry, finger_protocol::FingerResponseUserEntry},
    server::{
        fingerd::{self, FingerRequestInfo, FingerRequestNetworking, finger_utmp_users},
        rwhod::RwhodStatusStore,
    },
};

// Types for 'no.ntnu.pvv.roowho2.rwhod'

#[zlink::proxy("no.ntnu.pvv.roowho2.rwhod")]
pub trait VarlinkRwhodClientProxy {
    async fn rwho(
        &mut self,
        all: bool,
    ) -> zlink::Result<Result<VarlinkRwhoResponse, VarlinkRwhodClientError>>;

    async fn ruptime(
        &mut self,
        all: bool,
    ) -> zlink::Result<Result<VarlinkRuptimeResponse, VarlinkRwhodClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum VarlinkRwhodClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.rwhod.Rwho")]
    Rwho {
        /// Retrieve all users, even those that have been idle for a long time.
        all: bool,
    },

    #[serde(rename = "no.ntnu.pvv.roowho2.rwhod.Ruptime")]
    Ruptime {
        /// Count all users, even those that have been idle for a long time.
        all: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum VarlinkRwhodClientResponse {
    Rwho(VarlinkRwhoResponse),
    Ruptime(VarlinkRuptimeResponse),
}

pub type VarlinkRwhoResponse = Vec<(String, WhodUserEntry)>;
pub type VarlinkRuptimeResponse = Vec<WhodStatusUpdate>;

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.rwhod")]
pub enum VarlinkRwhodClientError {
    InvalidRequest,
    TimedOut,
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
}

// --------------------

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum VarlinkMethod {
    Rwhod(VarlinkRwhodClientRequest),
    Finger(VarlinkFingerClientRequest),
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
}

impl VarlinkRoowhoo2ClientServer {
    pub fn new(whod_status_store: RwhodStatusStore) -> Self {
        Self { whod_status_store }
    }
}

impl VarlinkRoowhoo2ClientServer {
    async fn handle_rwho_request(&self, all: bool) -> VarlinkRwhoResponse {
        tracing::debug!(all, "Handling Rwho request");
        let store = self.whod_status_store.read().await;

        let mut all_user_entries = Vec::with_capacity(store.len());
        for status_update in store.values() {
            all_user_entries.extend(
                status_update
                    .users
                    .iter()
                    .filter(|user| all || user.idle_time < chrono::Duration::hours(1))
                    .cloned()
                    .map(|user| (status_update.hostname.clone(), user)),
            );
        }

        all_user_entries
    }

    async fn handle_ruptime_request(&self, all: bool) -> VarlinkRuptimeResponse {
        tracing::debug!(all, "Handling Ruptime request");
        let store = self.whod_status_store.read().await;
        store
            .values()
            .filter(|status_update| {
                all || chrono::Utc::now() - status_update.sendtime < chrono::Duration::hours(1)
            })
            .cloned()
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
                    fingerd::search_for_user(&username, match_fullnames, &request_info)
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
            None => finger_utmp_users(&request_info)
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

impl zlink::Service<zlink::unix::Stream> for VarlinkRoowhoo2ClientServer {
    type MethodCall<'de> = VarlinkMethod;
    type ReplyParams<'se> = VarlinkReply;
    type ReplyStreamParams = ();
    type ReplyStream = futures_util::stream::Empty<(zlink::Reply<()>, Vec<OwnedFd>)>;
    type ReplyError<'se> = VarlinkReplyError;

    async fn handle<'service>(
        &'service mut self,
        call: &'service zlink::Call<Self::MethodCall<'_>>,
        _conn: &mut zlink::Connection<zlink::unix::Stream>,
        _fds: Vec<std::os::fd::OwnedFd>,
    ) -> zlink::service::HandleResult<
        Self::ReplyParams<'service>,
        Self::ReplyStream,
        Self::ReplyError<'service>,
    > {
        match call.method() {
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Rwho { all }) => {
                let result =
                    match timeout(Duration::from_secs(2), self.handle_rwho_request(*all)).await {
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
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Ruptime { all }) => {
                let result = match timeout(
                    Duration::from_secs(2),
                    self.handle_ruptime_request(*all),
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
        }
    }
}

pub async fn varlink_client_server_task(
    socket: zlink::unix::Listener,
    whod_status_store: RwhodStatusStore,
) -> anyhow::Result<()> {
    let service = VarlinkRoowhoo2ClientServer::new(whod_status_store);

    let server = zlink::Server::new(socket, service);

    tracing::info!("Starting Rwhod client API server");

    server
        .run()
        .await
        .context("Rwhod client API server failed")?;

    Ok(())
}
