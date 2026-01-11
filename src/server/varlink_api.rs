use anyhow::Context;
use serde::{Deserialize, Serialize};
use zlink::{ReplyError, service::MethodReply};

use crate::{
    proto::{WhodStatusUpdate, WhodUserEntry, finger_protocol::FingerPerson},
    server::rwhod::RwhodStatusStore,
};

// Types for 'no.ntnu.pvv.roowho2.rwhod'

#[zlink::proxy("no.ntnu.pvv.roowho2.rwhod")]
pub trait RwhodClientProxy {
    async fn rwho(
        &mut self,
        all: bool,
    ) -> zlink::Result<Result<Vec<(String, WhodUserEntry)>, RwhodClientError>>;

    async fn ruptime(&mut self) -> zlink::Result<Result<Vec<WhodStatusUpdate>, RwhodClientError>>;
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

#[derive(Debug, Serialize)]
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
    ) -> zlink::Result<Result<Vec<FingerPerson>, FingerClientError>>;
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
    Finger(FingerResponse),
}

pub type FingerResponse = Vec<FingerPerson>;

#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.finger")]
pub enum FingerClientError {
    InvalidRequest,
}

// --------------------

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(unused)]
enum Method {
    Rwhod(RwhodClientRequest),
    Finger(FingerClientRequest),
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(unused)]
enum Reply {
    Rwhod(RwhodClientResponse),
    Finger(FingerClientResponse),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(unused)]
enum ReplyError {
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
    type MethodCall<'de> = RwhodClientRequest;
    type ReplyParams<'se> = RwhodClientResponse;
    type ReplyStreamParams = ();
    type ReplyStream = futures_util::stream::Empty<zlink::Reply<()>>;
    type ReplyError<'se> = RwhodClientError;

    async fn handle<'ser, 'de: 'ser, Sock: zlink::connection::Socket>(
        &'ser mut self,
        call: zlink::Call<Self::MethodCall<'de>>,
        _conn: &mut zlink::Connection<Sock>,
    ) -> MethodReply<Self::ReplyParams<'ser>, Self::ReplyStream, Self::ReplyError<'ser>> {
        match call.method() {
            RwhodClientRequest::Rwho { all } => MethodReply::Single(Some(
                RwhodClientResponse::Rwho(self.handle_rwho_request(*all).await),
            )),
            RwhodClientRequest::Ruptime => MethodReply::Single(Some(RwhodClientResponse::Ruptime(
                self.handle_ruptime_request().await,
            ))),
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
