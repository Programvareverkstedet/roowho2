use std::{
    net::{SocketAddr, ToSocketAddrs, hostname},
    path::{Path, PathBuf},
};

use chrono::{
    DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeDelta, Timelike, Utc, Weekday,
};
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
    pub pgp_key: Option<String>,
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
        pgp_key: Option<String>,
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
            pgp_key,
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
            .map(PathBuf::from)
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
            .map(PathBuf::from)
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
            username, full_name, home_dir, shell, sessions, None, None, None, None,
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

    fn parse_login_time(time: &str, _timezone: &str) -> anyhow::Result<DateTime<Utc>> {
        let now = Utc::now();
        let mut parts = time.split_whitespace();

        let weekday = match parts.next() {
            Some("Mon") => Weekday::Mon,
            Some("Tue") => Weekday::Tue,
            Some("Wed") => Weekday::Wed,
            Some("Thu") => Weekday::Thu,
            Some("Fri") => Weekday::Fri,
            Some("Sat") => Weekday::Sat,
            Some("Sun") => Weekday::Sun,
            _ => anyhow::bail!("Invalid weekday in login time: {}", time),
        };

        let month = match parts.next() {
            Some("Jan") => 1,
            Some("Feb") => 2,
            Some("Mar") => 3,
            Some("Apr") => 4,
            Some("May") => 5,
            Some("Jun") => 6,
            Some("Jul") => 7,
            Some("Aug") => 8,
            Some("Sep") => 9,
            Some("Oct") => 10,
            Some("Nov") => 11,
            Some("Dec") => 12,
            _ => anyhow::bail!("Invalid month in login time: {}", time),
        };

        let day: u32 = parts
            .next()
            .and_then(|d| d.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid day in login time: {}", time))?;

        let time_part = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing time in login time: {}", time))?;

        let clock = NaiveTime::parse_from_str(time_part, "%H:%M").map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse time component in login time: {}: {}",
                time,
                e
            )
        })?;

        const MAX_YEARS_BACK: i32 = 10;

        for offset in 0..=MAX_YEARS_BACK {
            let year = now.year() - offset;

            let date = match NaiveDate::from_ymd_opt(year, month, day) {
                Some(d) => d,
                None => continue,
            };

            if date.weekday() != weekday {
                continue;
            }

            let dt = date.and_time(clock);

            if dt <= now.naive_utc() {
                // TODO: apply timezone if we are able to parse it.
                //       if not, try to get the local timezone offset.
                //       if not, assume UTC.

                return Ok(DateTime::<Utc>::from_utc(dt, Utc));
            }
        }

        Err(anyhow::anyhow!(
            "Could not infer year for login time {} within {} years",
            time,
            MAX_YEARS_BACK
        ))
    }

    fn parse_idle_time(str: &str) -> anyhow::Result<Duration> {
        // Parse idle time from finger response format.
        // This has four cases: "    ", "MMMMM", "HH:MM", "DDd"
        if str.trim().is_empty() {
            Ok(Duration::zero())
        } else if str.contains(':') {
            let parts: Vec<&str> = str.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid idle time format: {}", str));
            }
            let hours: i64 = parts[0].parse().map_err(|e| {
                anyhow::anyhow!("Failed to parse hours from idle time {}: {}", str, e)
            })?;
            let minutes: i64 = parts[1].parse().map_err(|e| {
                anyhow::anyhow!("Failed to parse minutes from idle time {}: {}", str, e)
            })?;
            Ok(Duration::hours(hours) + Duration::minutes(minutes))
        } else if str.ends_with('d') {
            let days_str = str.trim_end_matches('d');
            let days: i64 = days_str.parse().map_err(|e| {
                anyhow::anyhow!("Failed to parse days from idle time {}: {}", str, e)
            })?;
            Ok(Duration::days(days))
        } else {
            let minutes: i64 = str.parse().map_err(|e| {
                anyhow::anyhow!("Failed to parse minutes from idle time {}: {}", str, e)
            })?;
            Ok(Duration::minutes(minutes))
        }
    }

    /// Try parsing a user session from the text format used by the classic finger implementations.
    pub fn try_from_finger_response_line(line: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        debug_assert!(parts[0] == "On");
        debug_assert!(parts[1] == "since");

        let login_time_parts = parts
            .iter()
            .take_while(|&&s| s != "on")
            .skip(2)
            .cloned()
            .collect::<Vec<&str>>();

        let login_time = Self::parse_login_time(
            &login_time_parts[..login_time_parts.len() - 1].join(" "),
            login_time_parts[login_time_parts.len() - 1],
        )?;

        let tty = parts
            .iter()
            .skip_while(|&&s| s != "on")
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Failed to find tty in finger session line: {line}"))?
            .trim_end_matches(',')
            .to_string();

        let idle_time_str = parts
            .iter()
            .skip_while(|&&s| s != "idle")
            .nth(1)
            .ok_or_else(|| {
                anyhow::anyhow!("Failed to find idle time in finger session line: {line}")
            })?
            .trim_end_matches(',');
        let idle_time = Self::parse_idle_time(idle_time_str)?;

        let host = parts
            .iter()
            .skip_while(|&&s| s != "from")
            .nth(1)
            .unwrap_or(&"")
            .to_string();

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

    let hostname = hostname()?.to_str().unwrap_or("localhost").to_string();

    let now = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());
    let sessions: Vec<FingerUserSession> = Utmpx::iter_all_records()
        .filter(|entry| entry.user() == username)
        .filter(|entry| entry.is_user_process())
        .filter_map(|entry| {
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
                hostname.clone(),
            ))
        })
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
        username, full_name, home_dir, shell, sessions, None, forward, plan, None,
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
    fn test_parse_idle_time() {
        let cases = vec![("    ", 0), ("5", 5), ("1:30", 90), ("2d", 2880)];

        for (input, expected_minutes) in cases {
            let duration = FingerUserSession::parse_idle_time(input).unwrap();
            assert_eq!(
                duration.num_minutes(),
                expected_minutes,
                "Failed on input: {}",
                input
            );
        }
    }

    #[test]
    fn test_finger_user_session_parsing() {
        let line = "On since Mon Mar  1 10:00 (UTC) on pts/0, idle 5:00, from host.example.com";
        let session = FingerUserSession::try_from_finger_response_line(line).unwrap();
        assert_eq!(session.tty, "pts/0");
        assert_eq!(session.host, "host.example.com");
        assert_eq!(session.login_time.weekday(), Weekday::Mon);
        assert_eq!(session.login_time.hour(), 10);
        assert_eq!(session.idle_time.num_minutes(), 300);
    }

    #[test]
    fn test_finger_user_entry_parsing() {
        let response_content = indoc::indoc! {"
              Login: alice           			Name: Alice Wonderland
              Directory: /home/alice             	Shell: /bin/bash
              On since Mon Mar  1 10:00 (UTC) on pts/0, idle 5:00, from host.example.com
              No Mail.
              No Plan.
            "}
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
