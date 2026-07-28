use itertools::Itertools;
use serde::{Deserialize, Serialize};
use zlink::ReplyError;

use crate::{
    proto::finger_protocol::FingerResponseUserEntry,
    server::{
        fingerd::{self, FingerRequestInfo, FingerRequestNetworking, finger_utmp_users},
        ignore_list::IgnoreList,
    },
};

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

pub async fn handle_finger_request(
    finger_ignore_list: &Option<IgnoreList>,
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
                    finger_ignore_list.as_ref(),
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

        None => finger_utmp_users(&request_info, finger_ignore_list.as_ref())
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
