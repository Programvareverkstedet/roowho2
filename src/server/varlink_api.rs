mod fingerd;
mod rwhod;
mod walld;

use std::{os::fd::OwnedFd, time::Duration};

use anyhow::Context;
use futures_util::stream;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use zlink::{
    service::MethodReply,
    tokio::unix::{Listener as UnixListener, Stream as UnixStream},
};

use crate::server::{ignore_list::IgnoreList, rwhod::RwhodStatusStore};

pub use crate::server::varlink_api::{fingerd::*, rwhod::*, walld::*};

pub const DEFAULT_CLIENT_SERVER_SOCKET_PATH: &str = "/run/roowho2/roowho2.varlink";

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

impl VarlinkRoowhoo2ClientServer {}

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
                    handle_rwho_request(&self.whod_status_store, max_idle_time),
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
                    handle_ruptime_request(&self.whod_status_store, max_idle_time),
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
                    handle_finger_request(
                        &self.finger_ignore_list,
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
