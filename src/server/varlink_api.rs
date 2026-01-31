use anyhow::Context;
use serde::{Deserialize, Serialize};
use zlink::{ReplyError, service::MethodReply};

use crate::{
    proto::{WhodStatusUpdate, WhodUserEntry, finger_protocol::FingerResponse},
    server::rwhod::RwhodStatusStore,
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
    Ruptime,
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
}

// Types for 'no.ntnu.pvv.roowho2.finger'

#[zlink::proxy("no.ntnu.pvv.roowho2.finger")]
pub trait VarlinkFingerClientProxy {
    async fn finger(
        &mut self,
        user_queries: Vec<String>,
    ) -> zlink::Result<Result<VarlinkFingerResponse, VarlinkFingerClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum VarlinkFingerClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.finger.Finger")]
    Finger { user_queries: Vec<String> },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum VarlinkFingerClientResponse {
    Finger(VarlinkFingerResponse),
}

pub type VarlinkFingerResponse = FingerResponse;

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.finger")]
pub enum VarlinkFingerClientError {
    InvalidRequest,
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
    // TODO: handle 'all' parameter
    async fn handle_rwho_request(&self, _all: bool) -> VarlinkRwhoResponse {
        let store = self.whod_status_store.read().await;

        let mut all_user_entries = Vec::with_capacity(store.len());
        for status_update in store.values() {
            all_user_entries.extend_from_slice(
                &status_update
                    .users
                    .iter()
                    .map(|user| (status_update.hostname.clone(), user.clone()))
                    .collect::<Vec<(String, WhodUserEntry)>>(),
            );
        }

        all_user_entries
    }

    async fn handle_ruptime_request(&self) -> VarlinkRuptimeResponse {
        let store = self.whod_status_store.read().await;
        store.values().cloned().collect()
    }
}

impl zlink::Service for VarlinkRoowhoo2ClientServer {
    type MethodCall<'de> = VarlinkMethod;
    type ReplyParams<'se> = VarlinkReply;
    type ReplyStreamParams = ();
    type ReplyStream = futures_util::stream::Empty<zlink::Reply<()>>;
    type ReplyError<'se> = VarlinkReplyError;

    async fn handle<'service, Sock: zlink::connection::Socket>(
        &'service mut self,
        call: &'service zlink::Call<Self::MethodCall<'_>>,
        _conn: &mut zlink::Connection<Sock>,
    ) -> MethodReply<Self::ReplyParams<'service>, Self::ReplyStream, Self::ReplyError<'service>>
    {
        match call.method() {
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Rwho { all }) => {
                MethodReply::Single(Some(VarlinkReply::Rwhod(VarlinkRwhodClientResponse::Rwho(
                    self.handle_rwho_request(*all).await,
                ))))
            }
            VarlinkMethod::Rwhod(VarlinkRwhodClientRequest::Ruptime) => {
                MethodReply::Single(Some(VarlinkReply::Rwhod(
                    VarlinkRwhodClientResponse::Ruptime(self.handle_ruptime_request().await),
                )))
            }
            VarlinkMethod::Finger(VarlinkFingerClientRequest::Finger { user_queries: _ }) => {
                unimplemented!()
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
