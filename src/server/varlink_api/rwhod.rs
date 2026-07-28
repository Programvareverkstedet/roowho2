use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zlink::ReplyError;

use crate::{
    proto::{WhodStatusUpdate, WhodUserEntry},
    server::rwhod::RwhodStatusStore,
};

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

pub async fn handle_rwho_request(
    whod_status_store: &RwhodStatusStore,
    max_idle_time: Option<chrono::TimeDelta>,
) -> VarlinkRwhoResponse {
    tracing::debug!(?max_idle_time, "Handling Rwho request");
    let store = whod_status_store.read().await;

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

pub async fn handle_ruptime_request(
    whod_status_store: &RwhodStatusStore,
    max_idle_time: Option<chrono::TimeDelta>,
) -> VarlinkRuptimeResponse {
    tracing::debug!(?max_idle_time, "Handling Ruptime request");
    let store = whod_status_store.read().await;

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
