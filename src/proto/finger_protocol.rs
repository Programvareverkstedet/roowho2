use std::path::PathBuf;

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeDelta, Utc, Weekday};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

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
        let (long, name) = if &bytes[..3] == b"/W " {
            (true, &bytes[3..])
        } else {
            (false, bytes)
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

/// Parse the time serialization format commonly used by bsd-finger
fn parse_bsd_finger_time(time: &str) -> anyhow::Result<DateTime<Utc>> {
    let time_parts: Vec<_> = time.split_ascii_whitespace().collect();

    let time = &time_parts[..time_parts.len() - 1].join(" ");
    let _timezone = time_parts[time_parts.len() - 1];

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerResponseUserEntry {
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

impl FingerResponseUserEntry {
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

        let mut current_index = 2;

        let mut office: Option<String> = None;
        let mut office_phone: Option<String> = None;
        let mut home_phone: Option<String> = None;

        // TODO: handle case where office details contains comma, use last comma as separator
        if let Some(line) = lines.get(current_index)
            && line.trim().starts_with("Office:")
        {
            let office_line = line.trim().trim_start_matches("Office:").trim();
            if let Some((office_loc, phone)) = office_line.split_once(',') {
                office = Some(office_loc.trim().to_string());
                office_phone = Some(phone.trim().to_string());
            } else {
                office = Some(office_line.to_string());
            }
            current_index += 1;
        }
        if let Some(line) = lines.get(current_index)
            && line.trim().starts_with("Office Phone:")
        {
            let phone = line.trim().trim_start_matches("Office Phone:").trim();
            office_phone = Some(phone.to_string());
            current_index += 1;
        }
        if let Some(line) = lines.get(current_index)
            && line.trim().starts_with("Home Phone:")
        {
            let phone = line.trim().trim_start_matches("Home Phone:").trim();
            home_phone = Some(phone.to_string());
            current_index += 1;
        }

        let never_logged_in = lines
            .iter()
            .skip(current_index)
            .take(1)
            .any(|&line| line.trim() == "Never logged in.");

        let sessions: Vec<_> = lines
            .iter()
            .skip(current_index)
            .take_while(|line| line.starts_with("On since"))
            .filter_map(|line| {
                match FingerResponseUserSession::try_from_finger_response_line(line) {
                    Ok(session) => Some(session),
                    // TODO: log warning if parsing fails
                    Err(_) => None,
                }
            })
            .collect();

        if never_logged_in {
            debug_assert!(
                sessions.is_empty(),
                "User cannot be marked as never logged in while having active sessions"
            );
        }

        current_index += if never_logged_in { 1 } else { sessions.len() };

        let next_line = lines.get(current_index);

        // TODO: handle multi-line case
        let forward_status = if let Some(line) = next_line
            && line.trim().starts_with("Mail forwarded to ")
        {
            Some(line.trim().trim_prefix("Mail forwarded to ").to_string())
        } else {
            None
        };

        // TODO: parse forward_status, mail_status, plan from remaining lines

        Ok(Self::new(
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
            None,
            None,
            None,
            None,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailStatus {
    NoMail,
    NewMailReceived(DateTime<Utc>),
    UnreadSince(DateTime<Utc>),
    MailLastRead(DateTime<Utc>),
}

impl MailStatus {
    pub fn try_from_finger_response_line(str: &str) -> anyhow::Result<Self> {
        if str.trim() == "No mail." {
            Ok(Self::NoMail)
        } else if str.trim().starts_with("New mail received") {
            let datetime = parse_bsd_finger_time(str.trim().trim_prefix("New mail received "))?;
            Ok(Self::NewMailReceived(datetime))
        } else if str.trim().starts_with("Unread since") {
            let datetime = parse_bsd_finger_time(str.trim().trim_prefix("Unread since "))?;
            Ok(Self::UnreadSince(datetime))
        } else if str.trim().starts_with("Mail last read") {
            let datetime = parse_bsd_finger_time(str.trim().trim_prefix("Mail last read "))?;
            Ok(Self::MailLastRead(datetime))
        } else {
            anyhow::bail!("")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerResponseUserSession {
    /// The tty on which this session exists
    pub tty: String,

    /// When the user logged in and created this session
    pub login_time: DateTime<Utc>,

    /// The amount of time since the use last interacted with the tty
    pub idle_time: TimeDelta,

    /// The hostname of the machine where this session is running
    pub host: String,

    /// Whether this tty is writable, and thus can receive messages via `mesg(1)`
    pub messages_on: bool,
}

impl FingerResponseUserSession {
    pub fn new(
        tty: String,
        login_time: DateTime<Utc>,
        idle_time: TimeDelta,
        host: String,
        messages_on: bool,
    ) -> Self {
        Self {
            tty,
            login_time,
            idle_time,
            host,
            messages_on,
        }
    }

    /// Parse the login time from the text string generated by bsd-finger

    /// Parse the idle time from the text string generated by bsd-finger
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

    /// Try parsing a [FingerResponseUserSession] from the text format used by bsd-finger.
    pub fn try_from_finger_response_line(line: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        debug_assert!(parts[0] == "On");
        debug_assert!(parts[1] == "since");

        let login_time_str = parts
            .iter()
            .take_while(|&&s| s != "on")
            .skip(2)
            .cloned()
            .join(" ");

        let login_time = parse_bsd_finger_time(&login_time_str)?;

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

        let messages_on = !line.ends_with("(messages off)");

        Ok(Self {
            tty,
            login_time,
            idle_time,
            host,
            messages_on,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::Timelike;

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

    #[test]
    fn test_parse_bsd_finger_time() {
        let cases = vec![
            "Mon Mar  1 10:00 (UTC)",
            "Tue Feb 28 23:59 (UTC)",
            "Wed Dec 31 00:00 (UTC)",
            "Wed Dec 31 00:00 (GMT)",
        ];

        for input in cases {
            let datetime = parse_bsd_finger_time(input);
            assert!(
                datetime.is_ok(),
                "Failed to parse datetime for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_idle_time() {
        let cases = vec![("    ", 0), ("5", 5), ("1:30", 90), ("2d", 2880)];

        for (input, expected_minutes) in cases {
            let duration = FingerResponseUserSession::parse_idle_time(input).unwrap();
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
        let session = FingerResponseUserSession::try_from_finger_response_line(line).unwrap();
        assert_eq!(session.tty, "pts/0");
        assert_eq!(session.host, "host.example.com");
        assert_eq!(session.login_time.weekday(), Weekday::Mon);
        assert_eq!(session.login_time.hour(), 10);
        assert_eq!(session.idle_time.num_minutes(), 300);
        assert!(session.messages_on);

        let line_off = "On since Mon Mar  1 10:00 (UTC) on pts/1, idle 10, from another.host.com (messages off)";
        let session_off =
            FingerResponseUserSession::try_from_finger_response_line(line_off).unwrap();
        assert_eq!(session_off.tty, "pts/1");
        assert_eq!(session_off.host, "another.host.com");
        assert_eq!(session_off.login_time.weekday(), Weekday::Mon);
        assert_eq!(session_off.login_time.hour(), 10);
        assert_eq!(session_off.idle_time.num_minutes(), 10);
        assert!(!session_off.messages_on);
    }

    #[test]
    fn test_finger_user_entry_parsing_basic() {
        let response_content = indoc::indoc! {"
              Login: alice           			Name: Alice Wonderland
              Directory: /home/alice             	Shell: /bin/bash
              On since Mon Mar  1 10:00 (UTC) on pts/0, idle 5:00, from host.example.com
              No Mail.
              No Plan.
            "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry =
            FingerResponseUserEntry::try_from_raw_finger_response(&response, "alice".to_string())
                .unwrap();
        assert_eq!(user_entry.username, "alice");
        assert_eq!(user_entry.full_name, "Alice Wonderland");
        assert_eq!(user_entry.home_dir, PathBuf::from("/home/alice"));
        assert_eq!(user_entry.shell, PathBuf::from("/bin/bash"));
        assert_eq!(user_entry.sessions.len(), 1);
        assert_eq!(user_entry.sessions[0].tty, "pts/0");
        assert_eq!(user_entry.sessions[0].host, "host.example.com");
    }

    #[test]
    fn test_finger_user_entry_parsing_single_line_office_phone() {
        let response_content = indoc::indoc! {"
              Login: alice           			Name: Alice Wonderland
              Directory: /home/alice             	Shell: /bin/bash
              Office: 123 Main St, 012-345-6789
              Home Phone: +0-123-456-7890
              On since Mon Mar  1 10:00 (UTC) on pts/0, idle 5:00, from host.example.com
              No Mail.
              No Plan.
            "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry =
            FingerResponseUserEntry::try_from_raw_finger_response(&response, "alice".to_string())
                .unwrap();

        assert_eq!(user_entry.office, Some("123 Main St".to_string()));
        assert_eq!(user_entry.office_phone, Some("012-345-6789".to_string()));
        assert_eq!(user_entry.home_phone, Some("+0-123-456-7890".to_string()));
    }

    #[test]
    fn test_finger_user_entry_parsing_multiline_office_phone() {
        let response_content = indoc::indoc! {"
              Login: alice           			Name: Alice Wonderland
              Directory: /home/alice             	Shell: /bin/bash
              Office: 123 Main St
              Office Phone: 012-345-6789
              Home Phone: +0-123-456-7890
              On since Mon Mar  1 10:00 (UTC) on pts/0, idle 5:00, from host.example.com
              No Mail.
              No Plan.
            "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry =
            FingerResponseUserEntry::try_from_raw_finger_response(&response, "alice".to_string())
                .unwrap();

        assert_eq!(user_entry.office, Some("123 Main St".to_string()));
        assert_eq!(user_entry.office_phone, Some("012-345-6789".to_string()));
        assert_eq!(user_entry.home_phone, Some("+0-123-456-7890".to_string()));
    }

    #[test]
    fn test_finger_user_entry_parsing_never_logged_in() {
        let response_content = indoc::indoc! {"
              Login: bob           			Name: Bob Builder
              Directory: /home/bob             	Shell: /bin/zsh
              Never logged in.
              No Mail.
              No Plan.
            "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry =
            FingerResponseUserEntry::try_from_raw_finger_response(&response, "bob".to_string())
                .unwrap();

        assert!(user_entry.never_logged_in);
        assert!(user_entry.sessions.is_empty());
    }
}
