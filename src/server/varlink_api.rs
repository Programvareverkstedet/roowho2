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

use crate::server::{ignore_list::IgnoreList, polkit::PolkitAuthority, rwhod::RwhodStatusStore};

pub use crate::server::varlink_api::{fingerd::*, rwhod::*, walld::*};

pub const DEFAULT_CLIENT_SERVER_SOCKET_PATH: &str = "/run/roowho2/roowho2.varlink";

macro_rules! require_enabled {
    ($self:ident, $flag:ident, $reply_variant:ident, $error_ty:ident) => {
        if !$self.$flag {
            return (
                MethodReply::Error(VarlinkReplyError::$reply_variant($error_ty::Disabled)),
                Default::default(),
            );
        }
    };
}

macro_rules! with_timeout {
    ($future:expr, $name:literal, $reply_variant:ident, $error_ty:ident) => {
        match timeout(Duration::from_secs(2), $future).await {
            Ok(response) => response,
            Err(_) => {
                tracing::error!(concat!($name, " request timed out after 2 seconds"));
                return (
                    MethodReply::Error(VarlinkReplyError::$reply_variant($error_ty::TimedOut)),
                    Default::default(),
                );
            }
        }
    };
}

macro_rules! reply_ok {
    ($reply_variant:ident, $response_variant:path, $value:expr) => {
        (
            MethodReply::Single(Some(VarlinkReply::$reply_variant($response_variant(
                $value,
            )))),
            Default::default(),
        )
    };
}

macro_rules! reply_result {
    ($reply_variant:ident, $response_variant:path, $result:expr) => {
        match $result {
            Ok(response) => reply_ok!($reply_variant, $response_variant, response),
            Err(err) => (
                MethodReply::Error(VarlinkReplyError::$reply_variant(err)),
                Default::default(),
            ),
        }
    };
}

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
    Walld(VarlinkWalldClientResponse),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum VarlinkReplyError {
    Rwhod(VarlinkRwhodClientError),
    Finger(VarlinkFingerClientError),
    Walld(VarlinkWalldClientError),
}

#[derive(Clone)]
pub struct VarlinkRoowhoo2ClientServer {
    whod_status_store: RwhodStatusStore,
    rwhod_enabled: bool,
    fingerd_enabled: bool,
    walld_enabled: bool,
    finger_ignore_list: Option<IgnoreList>,
    polkit: Option<PolkitAuthority>,
}

impl VarlinkRoowhoo2ClientServer {
    pub fn new(
        whod_status_store: RwhodStatusStore,
        rwhod_enabled: bool,
        fingerd_enabled: bool,
        walld_enabled: bool,
        finger_ignore_list: Option<IgnoreList>,
        polkit: Option<PolkitAuthority>,
    ) -> Self {
        Self {
            whod_status_store,
            rwhod_enabled,
            fingerd_enabled,
            walld_enabled,
            finger_ignore_list,
            polkit,
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
        conn: &mut zlink::Connection<UnixStream>,
        _fds: Vec<OwnedFd>,
    ) -> zlink::service::HandleResult<
        Self::ReplyParams<'service>,
        Self::ReplyStream,
        Self::ReplyError<'service>,
    > {
        let (peer_pid, peer_uid) = match conn.peer_credentials().await {
            Ok(creds) => (
                creds.process_id().as_raw_pid() as u32,
                creds.unix_user_id().as_raw(),
            ),
            Err(e) => {
                tracing::error!("failed to read peer credentials: {e}");
                // TODO: peercreds are currently only used for walld, but this should be a more "toplevel"
                //       error at some point when we start using peercred for other things as well.
                return (
                    MethodReply::Error(VarlinkReplyError::Walld(VarlinkWalldClientError::Io {
                        message: "failed to identify caller".to_string(),
                    })),
                    Default::default(),
                );
            }
        };

        match call.method() {
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Rwho { max_idle_seconds }) => {
                require_enabled!(self, rwhod_enabled, Rwhod, VarlinkRwhodClientError);

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

                let result = with_timeout!(
                    handle_rwho_request(&self.whod_status_store, max_idle_time),
                    "Rwho",
                    Rwhod,
                    VarlinkRwhodClientError
                );

                reply_ok!(Rwhod, VarlinkRwhodClientResponse::Rwho, result)
            }
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Ruptime { max_idle_seconds }) => {
                require_enabled!(self, rwhod_enabled, Rwhod, VarlinkRwhodClientError);

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

                let result = with_timeout!(
                    handle_ruptime_request(&self.whod_status_store, max_idle_time),
                    "Ruptime",
                    Rwhod,
                    VarlinkRwhodClientError
                );

                reply_ok!(Rwhod, VarlinkRwhodClientResponse::Ruptime, result)
            }
            VarlinkMethod::Finger(VarlinkFingerClientRequest::Finger {
                user_queries,
                match_fullnames,
                request_info,
                request_networking,
                disable_user_account_db,
                raw_remote_output,
            }) => {
                require_enabled!(self, fingerd_enabled, Finger, VarlinkFingerClientError);

                let result = with_timeout!(
                    handle_finger_request(
                        &self.finger_ignore_list,
                        user_queries.clone(),
                        *match_fullnames,
                        request_info.clone(),
                        request_networking.clone(),
                        *disable_user_account_db,
                        *raw_remote_output,
                    ),
                    "Finger",
                    Finger,
                    VarlinkFingerClientError
                );

                reply_ok!(Finger, VarlinkFingerClientResponse::Finger, result)
            }
            VarlinkMethod::Walld(VarlinkWalldClientRequest::Wall {
                source_tty,
                message,
                group,
                nobanner,
                timeout_secs,
            }) => {
                require_enabled!(self, walld_enabled, Walld, VarlinkWalldClientError);

                // TODO: ensure the outer duration is more than the inner duration.
                let result = with_timeout!(
                    handle_wall_request(
                        self.polkit.as_ref(),
                        peer_pid,
                        peer_uid,
                        source_tty.clone(),
                        message.clone(),
                        group.clone(),
                        *nobanner,
                        *timeout_secs,
                    ),
                    "Wall",
                    Walld,
                    VarlinkWalldClientError
                );

                reply_result!(Walld, VarlinkWalldClientResponse::Wall, result)
            }
            VarlinkMethod::Walld(VarlinkWalldClientRequest::Write {
                source_tty,
                target_user,
                target_tty,
                message,
            }) => {
                require_enabled!(self, walld_enabled, Walld, VarlinkWalldClientError);

                let result = with_timeout!(
                    handle_write_request(
                        self.polkit.as_ref(),
                        peer_pid,
                        peer_uid,
                        source_tty.clone(),
                        target_user.clone(),
                        target_tty.clone(),
                        message.clone(),
                    ),
                    "Write",
                    Walld,
                    VarlinkWalldClientError
                );

                reply_result!(Walld, VarlinkWalldClientResponse::Write, result)
            }
        }
    }
}

pub async fn varlink_client_server_task(
    socket: UnixListener,
    whod_status_store: RwhodStatusStore,
    rwhod_enabled: bool,
    fingerd_enabled: bool,
    walld_enabled: bool,
    finger_ignore_list: Option<IgnoreList>,
) -> anyhow::Result<()> {
    let polkit = if !walld_enabled {
        None
    } else {
        match timeout(Duration::from_secs(5), PolkitAuthority::connect()).await {
            Ok(Ok(polkit)) => Some(polkit),
            Ok(Err(e)) => {
                tracing::warn!(
                    "Failed to connect to polkit; Wall/Write requests will be denied: {e:#}"
                );
                None
            }
            Err(_) => {
                tracing::warn!(
                    "Timed out connecting to polkit after 5 seconds; Wall/Write requests will be denied"
                );
                None
            }
        }
    };

    let service = VarlinkRoowhoo2ClientServer::new(
        whod_status_store,
        rwhod_enabled,
        fingerd_enabled,
        walld_enabled,
        finger_ignore_list,
        polkit,
    );

    let server = zlink::Server::new(socket, service);

    tracing::info!("Starting Rwhod client API server");

    server
        .run()
        .await
        .context("Rwhod client API server failed")?;

    Ok(())
}
