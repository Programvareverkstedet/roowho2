use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, TimeDelta, Timelike, Utc};
use nix::sys::stat::stat;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use uucore::utmpx::Utmpx;

use crate::proto::finger_protocol::{FingerRequest, FingerResponse};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerUserEntry {
    pub username: String,
    pub full_name: String,
    pub home_dir: PathBuf,
    pub shell: PathBuf,
    pub sessions: Vec<FingerUserSession>,
    pub forward_status: Option<String>,
    pub mail_status: Option<String>,
    pub plan: Option<String>,
}

impl FingerUserEntry {
    pub fn new(
        username: String,
        full_name: String,
        home_dir: PathBuf,
        shell: PathBuf,
        sessions: Vec<FingerUserSession>,
        forward_status: Option<String>,
        mail_status: Option<String>,
        plan: Option<String>,
    ) -> Self {
        Self {
            username,
            full_name,
            home_dir,
            shell,
            sessions,
            forward_status,
            mail_status,
            plan,
        }
    }

    /// Try parsing a FingerUserEntry from the text format used by the classic finger implementations.
    pub fn try_from_finger_response(
        response: &FingerResponse,
        username: String,
    ) -> anyhow::Result<Self> {
        let content = response.get_inner();
        let lines: Vec<&str> = content.lines().collect();

        if lines.len() < 2 {
            return Err(anyhow::anyhow!(
                "Unexpected finger response format for user {}",
                username
            ));
        }

        let first_line = lines[0];
        let second_line = lines[1];

        let full_name = first_line
            .split("Name:")
            .nth(1)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to parse full name from finger response for user {}",
                    username
                )
            })?
            .trim()
            .to_string();

        let home_dir = second_line
            .split("Directory:")
            .nth(1)
            .and_then(|s| s.split("Shell:").next())
            .map(|s| s.trim())
            .and_then(|s| Some(PathBuf::from(s)))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to parse home directory from finger response for user {}",
                    username
                )
            })?;

        let shell = second_line
            .split("Shell:")
            .nth(1)
            .map(|s| s.trim())
            .and_then(|s| Some(PathBuf::from(s)))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to parse shell from finger response for user {}",
                    username
                )
            })?;

        let sessions = lines
            .iter()
            .skip(2)
            .take_while(|line| line.starts_with("On since"))
            .filter_map(|line| {
                match FingerUserSession::try_from_finger_response_line(line) {
                    Ok(session) => Some(session),
                    // TODO: log warning if parsing fails
                    Err(_) => None,
                }
            })
            .collect();

        // TODO: parse forward_status, mail_status, plan from remaining lines

        Ok(Self::new(
            username, full_name, home_dir, shell, sessions, None, None, None,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerUserSession {
    pub tty: String,
    pub login_time: DateTime<Utc>,
    pub idle_time: TimeDelta,
    pub host: String,
}

impl FingerUserSession {
    pub fn new(tty: String, login_time: DateTime<Utc>, idle_time: TimeDelta, host: String) -> Self {
        Self {
            tty,
            login_time,
            idle_time,
            host,
        }
    }

    /// Try parsing a user session from the text format used by the classic finger implementations.
    pub fn try_from_finger_response_line(line: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(anyhow::anyhow!(
                "Unexpected finger session line format: {}",
                line
            ));
        }

        let tty = parts[2].to_string();

        let login_time_str = format!("{} {} {} {}", parts[4], parts[5], parts[6], parts[7]);
        let login_time = DateTime::parse_from_str(&login_time_str, "%a %b %e %H:%M (%Z)")
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to parse login time from finger session line: {}: {}",
                    line,
                    e
                )
            })?
            .with_timezone(&Utc);

        //

        // let idle_time = if let Some(idle_index) = parts.iter().position(|&s| s == "idle")
        //     && idle_index + 1 < parts.len()
        // {
        //     let idle_str = parts[idle_index + 1];
        //     let idle_parts: Vec<&str> = idle_str.split(':').collect();
        //     if idle_parts.len() == 2 {
        //         let hours: i64 = idle_parts[0].parse().unwrap_or(0);
        //         let minutes: i64 = idle_parts[1].parse().unwrap_or(0);
        //         Duration::hours(hours) + Duration::minutes(minutes)
        //     } else {
        //         Duration::zero()
        //     }
        // } else {
        //     Duration::zero()
        // };

        let host = if parts.len() > 7 {
            parts[7..].join(" ")
        } else {
            "".to_string()
        };

        Ok(Self {
            tty,
            login_time,
            idle_time,
            host,
        })
    }
}

/// Retrieve local user information for the given username.
///
/// Returns None if the user does not exist.
pub fn get_local_user(username: &str) -> anyhow::Result<Option<FingerUserEntry>> {
    let username = username.to_string();
    let user_entry = match nix::unistd::User::from_name(&username) {
        Ok(Some(user)) => user,
        Ok(None) => return Ok(None),
        Err(err) => {
            return Err(anyhow::anyhow!(
                "Failed to get user entry for {}: {}",
                username,
                err
            ));
        }
    };

    let full_name = user_entry.name;
    let home_dir = user_entry.dir.clone();
    let shell = user_entry.shell;

    let now = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());
    let sessions: Vec<FingerUserSession> = Utmpx::iter_all_records()
        .filter(|entry| entry.user() == username)
        .filter(|entry| entry.is_user_process())
        .map(|entry| {
            let login_time = entry
                .login_time()
                .checked_to_utc()
                .and_then(|t| DateTime::<Utc>::from_timestamp_secs(t.unix_timestamp()))?;

            let idle_time = stat(&Path::new("/dev").join(entry.tty_device()))
                .ok()
                .and_then(|st| {
                    let last_active = DateTime::<Utc>::from_timestamp_secs(st.st_atime)?;
                    Some((now - last_active).max(Duration::zero()))
                })
                .unwrap_or(Duration::zero());

            debug_assert!(
                idle_time.num_seconds() >= 0,
                "Idle time should never be negative"
            );

            Some(FingerUserSession::new(
                entry.tty_device(),
                login_time,
                idle_time,
                String::new(), // Host information is not available from local utmpx
            ))
        })
        .flatten()
        .collect();

    let forward_path = user_entry.dir.join(".forward");
    let forward =
        if forward_path.exists() && forward_path.metadata()?.len() > 0 && forward_path.is_file() {
            Some(std::fs::read_to_string(&forward_path)?.trim().to_string())
        } else {
            None
        };

    let plan_path = user_entry.dir.join(".plan");
    let plan = if plan_path.exists() && plan_path.metadata()?.len() > 0 && plan_path.is_file() {
        Some(std::fs::read_to_string(&plan_path)?.trim().to_string())
    } else {
        None
    };

    Ok(Some(FingerUserEntry::new(
        username, full_name, home_dir, shell, sessions, forward, plan, None,
    )))
}

/// Retrieve remote user information for the given username on the specified host.
///
/// Returns None if the user does not exist or no information is available.
async fn get_remote_user(username: &str, host: &str) -> anyhow::Result<Option<FingerResponse>> {
    let addr = format!("{}:79", host);
    let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

    if socket_addrs.is_empty() {
        return Err(anyhow::anyhow!(
            "Could not resolve address for host {}",
            host
        ));
    }

    let socket_addr = socket_addrs[0];

    let mut stream = TcpStream::connect(socket_addr).await?;

    let request = FingerRequest::new(false, username.to_string());
    let request_bytes = request.to_bytes();
    stream.write_all(&request_bytes).await?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await?;

    let response = FingerResponse::from_bytes(&response_bytes);

    if response.is_empty() {
        Ok(None)
    } else {
        Ok(Some(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finger_user_entry_parsing() {
        let response_content = "
Login: alice           			Name: Alice Wonderland
Directory: /home/alice             	Shell: /bin/bash
On since Mon Mar  1 10:00 (UTC) on pts/0, idle 5:00, from host.example.com
No Mail.
No Plan.
"
        .trim();

        let response = FingerResponse::from(response_content.to_string());
        let user_entry =
            FingerUserEntry::try_from_finger_response(&response, "alice".to_string()).unwrap();
        assert_eq!(user_entry.username, "alice");
        assert_eq!(user_entry.full_name, "Alice Wonderland");
        assert_eq!(user_entry.home_dir, PathBuf::from("/home/alice"));
        assert_eq!(user_entry.shell, PathBuf::from("/bin/bash"));
        assert_eq!(user_entry.sessions.len(), 1);
        assert_eq!(user_entry.sessions[0].tty, "pts/0");
        assert_eq!(user_entry.sessions[0].host, "host.example.com");
    }

    // TODO: test serialization roundtrip
}
