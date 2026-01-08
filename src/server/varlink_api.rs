use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zlink::{ReplyError, service::MethodReply};

use crate::proto::{WhodStatusUpdate, WhodUserEntry};

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

#[derive(Debug, ReplyError)]
#[zlink(interface = "no.ntnu.pvv.roowho2.rwhod")]
pub enum RwhodClientError {
    InvalidRequest,
}

#[derive(Debug, Clone)]
pub struct RwhodClientServer {
    whod_status_store: Arc<RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
}

impl RwhodClientServer {
    pub fn new(
        whod_status_store: Arc<RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
    ) -> Self {
        Self { whod_status_store }
    }
}

impl zlink::Service for RwhodClientServer {
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
            // TODO: handle 'all' parameter
            RwhodClientRequest::Rwho { .. } => {
                let store = self.whod_status_store.read().await;
                let mut all_user_entries = Vec::new();
                for status_update in store.values() {
                    all_user_entries.extend_from_slice(
                        &status_update
                            .users
                            .iter()
                            .map(|user| (status_update.hostname.clone(), user.clone()))
                            .collect::<Vec<(String, WhodUserEntry)>>(),
                    );
                }
                MethodReply::Single(Some(RwhodClientResponse::Rwho(all_user_entries)))
            }
            RwhodClientRequest::Ruptime => {
                let store = self.whod_status_store.read().await;
                let all_status_updates = store.values().cloned().collect();
                MethodReply::Single(Some(RwhodClientResponse::Ruptime(all_status_updates)))
            }
        }
    }
}

pub async fn varlink_client_server_task(
    socket: zlink::unix::Listener,
    whod_status_store: Arc<RwLock<HashMap<IpAddr, WhodStatusUpdate>>>,
) -> anyhow::Result<()> {
    let service = RwhodClientServer::new(whod_status_store);

    let server = zlink::Server::new(socket, service);

    tracing::info!("Starting Rwhod client API server");

    server
        .run()
        .await
        .context("Rwhod client API server failed")?;

    Ok(())
}
