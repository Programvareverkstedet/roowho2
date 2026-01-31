use anyhow::Context;
use serde::{Deserialize, Serialize};
use zlink::{ReplyError, service::MethodReply};

use crate::{
    proto::{WhodStatusUpdate, WhodUserEntry, finger_protocol::FingerResponse},
    server::rwhod::RwhodStatusStore,
};

// Types for 'no.ntnu.pvv.roowho2.rwhod'

#[zlink::proxy("no.ntnu.pvv.roowho2.rwhod")]
pub trait RwhodClientProxy {
    async fn rwho(&mut self, all: bool) -> zlink::Result<Result<RwhoResponse, RwhodClientError>>;

    async fn ruptime(&mut self) -> zlink::Result<Result<RuptimeResponse, RwhodClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum RwhodClientRequest {
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
pub enum RwhodClientResponse {
    Rwho(RwhoResponse),
    Ruptime(RuptimeResponse),
}

pub type RwhoResponse = Vec<(String, WhodUserEntry)>;
pub type RuptimeResponse = Vec<WhodStatusUpdate>;

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.rwhod")]
pub enum RwhodClientError {
    InvalidRequest,
}

// Types for 'no.ntnu.pvv.roowho2.finger'

#[zlink::proxy("no.ntnu.pvv.roowho2.finger")]
pub trait FingerClientProxy {
    async fn finger(
        &mut self,
        user_queries: Vec<String>,
    ) -> zlink::Result<Result<ZlinkFingerResponse, FingerClientError>>;
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum FingerClientRequest {
    #[serde(rename = "no.ntnu.pvv.roowho2.finger.Finger")]
    Finger { user_queries: Vec<String> },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum FingerClientResponse {
    Finger(ZlinkFingerResponse),
}

pub type ZlinkFingerResponse = FingerResponse;

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.finger")]
pub enum FingerClientError {
    InvalidRequest,
}

// --------------------

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum Method {
    Rwhod(RwhodClientRequest),
    Finger(FingerClientRequest),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum Reply {
    Rwhod(RwhodClientResponse),
    Finger(FingerClientResponse),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(unused)]
pub enum ReplyError {
    Rwhod(RwhodClientError),
    Finger(FingerClientError),
}

#[derive(Debug, Clone)]
pub struct Roowhoo2ClientServer {
    whod_status_store: RwhodStatusStore,
}

impl Roowhoo2ClientServer {
    pub fn new(whod_status_store: RwhodStatusStore) -> Self {
        Self { whod_status_store }
    }
}

impl Roowhoo2ClientServer {
    // TODO: handle 'all' parameter
    async fn handle_rwho_request(&self, _all: bool) -> RwhoResponse {
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

    async fn handle_ruptime_request(&self) -> RuptimeResponse {
        let store = self.whod_status_store.read().await;
        store.values().cloned().collect()
    }
}

impl zlink::Service for Roowhoo2ClientServer {
    type MethodCall<'de> = Method;
    type ReplyParams<'se> = Reply;
    type ReplyStreamParams = ();
    type ReplyStream = futures_util::stream::Empty<zlink::Reply<()>>;
    type ReplyError<'se> = ReplyError;

    async fn handle<'service, Sock: zlink::connection::Socket>(
        &'service mut self,
        call: &'service zlink::Call<Self::MethodCall<'_>>,
        _conn: &mut zlink::Connection<Sock>,
    ) -> MethodReply<Self::ReplyParams<'service>, Self::ReplyStream, Self::ReplyError<'service>>
    {
        match call.method() {
            Method::Rwhod(RwhodClientRequest::Rwho { all }) => {
                MethodReply::Single(Some(Reply::Rwhod(RwhodClientResponse::Rwho(
                    self.handle_rwho_request(*all).await,
                ))))
            }
            Method::Rwhod(RwhodClientRequest::Ruptime) => MethodReply::Single(Some(Reply::Rwhod(
                RwhodClientResponse::Ruptime(self.handle_ruptime_request().await),
            ))),
            Method::Finger(FingerClientRequest::Finger { user_queries: _ }) => {
                unimplemented!()
            }
        }
    }
}

pub async fn varlink_client_server_task(
    socket: zlink::unix::Listener,
    whod_status_store: RwhodStatusStore,
) -> anyhow::Result<()> {
    let service = Roowhoo2ClientServer::new(whod_status_store);

    let server = zlink::Server::new(socket, service);

    tracing::info!("Starting Rwhod client API server");

    server
        .run()
        .await
        .context("Rwhod client API server failed")?;

    Ok(())
}
