mod classic_formatter;
mod parser;
mod time_parser;

use std::path::PathBuf;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    proto::finger_protocol::{
        classic_formatter::classic_format_finger_response_structured_user_entry,
        parser::try_parse_structured_user_entry_from_raw_finger_response,
    },
    util::duration_serde,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerRequest {
    long: bool,
    name: String,
}

impl FingerRequest {
    pub fn new(long: bool, name: String) -> Self {
        Self { long, name }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        if self.long {
            result.extend(b"/W ");
        }

        result.extend(self.name.as_bytes());
        result.extend(b"\r\n");

        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let (long, name) = match bytes.strip_prefix(b"/W ") {
            Some(name) => (true, name),
            None => (false, bytes),
        };

        let name = match name.strip_suffix(b"\r\n") {
            Some(new_name) => new_name,
            None => name,
        };

        Self::new(long, String::from_utf8_lossy(name).to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RawFingerResponse(String);

impl RawFingerResponse {
    pub fn new(content: String) -> Self {
        Self(content)
    }

    pub fn get_inner(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self(String::new());
        }

        fn normalize(c: u8) -> u8 {
            if c == (b'\r' | 0x80) || c == (b'\n' | 0x80) {
                c & 0x7f
            } else {
                c
            }
        }

        let normalized: Vec<u8> = bytes
            .iter()
            .copied()
            .map(normalize)
            .chain(std::iter::once(normalize(*bytes.last().unwrap())))
            .map_windows(|[a, b]| {
                if *a == b'\r' && *b == b'\n' {
                    None
                } else {
                    Some(*a)
                }
            })
            .flatten()
            .collect();

        let result = String::from_utf8_lossy(&normalized).to_string();

        Self(result)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() + 2);

        for &b in self.0.as_bytes() {
            if b == b'\n' {
                out.extend_from_slice(b"\r\n");
            } else {
                out.push(b);
            }
        }

        if !self.0.ends_with('\n') {
            out.extend_from_slice(b"\r\n");
        }

        out
    }
}

impl From<String> for RawFingerResponse {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for RawFingerResponse {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FingerResponseUserEntry {
    Structured(Box<FingerResponseStructuredUserEntry>),
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerResponseStructuredUserEntry {
    /// The unix username of this user, as noted in passwd
    pub username: String,

    /// The full name of this user, as noted in passwd
    pub full_name: String,

    /// The path to the home directory of this user, as noted in passwd
    pub home_dir: PathBuf,

    /// The path to the shell of this user, as noted in passwd
    pub shell: PathBuf,

    /// Office location, if available
    pub office: Option<String>,

    /// Office phone number, if available
    pub office_phone: Option<String>,

    /// Home phone number, if available
    pub home_phone: Option<String>,

    /// Whether the user has never logged in to this host
    pub never_logged_in: bool,

    /// A list of user sessions, sourced from utmp entries
    pub sessions: Vec<FingerResponseUserSession>,

    /// Contents of ~/.forward, if it exists
    pub forward_status: Option<String>,

    /// Whether the user has new or unread mail
    pub mail_status: Option<MailStatus>,

    /// Contents of ~/.pgpkey, if it exists
    pub pgp_key: Option<String>,

    /// Contents of ~/.project, if it exists
    pub project: Option<String>,

    /// Contents of ~/.plan, if it exists
    pub plan: Option<String>,
}

impl FingerResponseStructuredUserEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        username: String,
        full_name: String,
        home_dir: PathBuf,
        shell: PathBuf,
        office: Option<String>,
        office_phone: Option<String>,
        home_phone: Option<String>,
        never_logged_in: bool,
        sessions: Vec<FingerResponseUserSession>,
        forward_status: Option<String>,
        mail_status: Option<MailStatus>,
        pgp_key: Option<String>,
        project: Option<String>,
        plan: Option<String>,
    ) -> Self {
        debug_assert!(
            !never_logged_in || sessions.is_empty(),
            "User cannot be marked as never logged in while having active sessions"
        );

        Self {
            username,
            full_name,
            home_dir,
            shell,
            office,
            office_phone,
            home_phone,
            never_logged_in,
            sessions,
            forward_status,
            mail_status,
            pgp_key,
            project,
            plan,
        }
    }

    /// Try parsing a [FingerResponseUserEntry] from the text format used by bsd-finger.
    pub fn try_from_raw_finger_response(
        response: &RawFingerResponse,
        username: String,
    ) -> anyhow::Result<Self> {
        try_parse_structured_user_entry_from_raw_finger_response(response, username)
    }

    pub fn classic_format(&self) -> String {
        classic_format_finger_response_structured_user_entry(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailStatus {
    NoMail,
    NewMailReceived {
        #[serde(with = "chrono::serde::ts_seconds")]
        received_time: DateTime<Utc>,
        #[serde(with = "chrono::serde::ts_seconds")]
        unread_since: DateTime<Utc>,
    },
    MailLastRead(#[serde(with = "chrono::serde::ts_seconds")] DateTime<Utc>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerResponseUserSession {
    /// The tty on which this session exists
    pub tty: String,

    /// When the user logged in and created this session
    #[serde(with = "chrono::serde::ts_seconds")]
    pub login_time: DateTime<Utc>,

    /// The hostname or address of the machine from which the user is logged in, if available
    pub host: Option<String>,

    /// The amount of time since the use last interacted with the tty
    #[serde(with = "duration_serde::duration_seconds_option")]
    pub idle_time: Option<TimeDelta>,

    /// Whether this tty is writable, and thus can receive messages via `mesg(1)`
    pub messages_on: bool,
}

impl FingerResponseUserSession {
    pub fn new(
        tty: String,
        login_time: DateTime<Utc>,
        host: Option<String>,
        idle_time: Option<TimeDelta>,
        messages_on: bool,
    ) -> Self {
        Self {
            tty,
            login_time,
            host,
            idle_time,
            messages_on,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finger_raw_serialization_roundrip() {
        let request = FingerRequest::new(true, "alice".to_string());
        let bytes = request.to_bytes();
        let deserialized = FingerRequest::from_bytes(&bytes);
        assert_eq!(request, deserialized);

        let request2 = FingerRequest::new(false, "bob".to_string());
        let bytes2 = request2.to_bytes();
        let deserialized2 = FingerRequest::from_bytes(&bytes2);
        assert_eq!(request2, deserialized2);

        let response = RawFingerResponse::new("Hello, World!\nThis is a test.\n".to_string());
        let response_bytes = response.to_bytes();
        let deserialized_response = RawFingerResponse::from_bytes(&response_bytes);
        assert_eq!(response, deserialized_response);

        let response2 = RawFingerResponse::new("Single line response\n".to_string());
        let response_bytes2 = response2.to_bytes();
        let deserialized_response2 = RawFingerResponse::from_bytes(&response_bytes2);
        assert_eq!(response2, deserialized_response2);
    }
}
