use std::path::PathBuf;

use anyhow::Context;
use chrono::{
    DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeZone, Timelike, Utc, Weekday,
};
use itertools::Itertools;

use crate::proto::finger_protocol::{
    FingerResponseStructuredUserEntry, FingerResponseUserSession, MailStatus, RawFingerResponse,
};

/// Parse the time serialization format commonly used by bsd-finger
fn parse_bsd_finger_time(time: &str) -> anyhow::Result<DateTime<Utc>> {
    let time_parts: Vec<_> = time.split_ascii_whitespace().collect();

    let time_ = &time_parts[..time_parts.len() - 1].join(" ");
    let timezone = time_parts[time_parts.len() - 1]
        .trim_start_matches('(')
        .trim_end_matches(')');

    let tz: chrono_tz::Tz = timezone
        .parse()
        .context(format!("Failed to parse timezone in login time: {}", time))?;

    let mut parts = time_.split_whitespace();

    let weekday = match parts.next() {
        Some("Mon") => Weekday::Mon,
        Some("Tue") => Weekday::Tue,
        Some("Wed") => Weekday::Wed,
        Some("Thu") => Weekday::Thu,
        Some("Fri") => Weekday::Fri,
        Some("Sat") => Weekday::Sat,
        Some("Sun") => Weekday::Sun,
        _ => anyhow::bail!("Invalid weekday in login time: {}", time_),
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
        _ => anyhow::bail!("Invalid month in login time: {}", time_),
    };

    let day: u32 = parts
        .next()
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Invalid day in login time: {}", time_))?;

    let time_part = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing time in login time: {}", time_))?;

    let clock = NaiveTime::parse_from_str(time_part, "%H:%M").map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse time component in login time: {}: {}",
            time_,
            e
        )
    })?;

    let now = Utc::now();
    const MAX_YEARS_BACK: i32 = 10;
    let mut year = None;
    for offset in 0..=MAX_YEARS_BACK {
        let year_ = now.year() - offset;

        let date = match NaiveDate::from_ymd_opt(year_, month, day) {
            Some(d) => d,
            None => continue,
        };

        if date.weekday() != weekday {
            continue;
        }

        year = Some(year_);
    }

    if year.is_none() {
        return Err(anyhow::anyhow!(
            "Could not find a valid year for login time {} within {} years",
            time_,
            MAX_YEARS_BACK
        ));
    }

    tz.with_ymd_and_hms(year.unwrap(), month, day, clock.hour(), clock.minute(), 0)
        .single()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to convert login time to timezone-aware datetime: {}",
                time_
            )
        })
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn try_parse_structured_user_entry_from_raw_finger_response(
    response: &RawFingerResponse,
    username: String,
) -> anyhow::Result<FingerResponseStructuredUserEntry> {
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

    let full_name = parse_full_name(first_line, &username)?;
    let home_dir = parse_home_dir(second_line, &username)?;
    let shell = parse_shell(second_line, &username)?;

    let mut current_index = 2;

    let (office, office_phone, home_phone) = parse_gecos_fields(&lines, &mut current_index)?;

    let never_logged_in = lines[current_index].trim() == "Never logged in.";

    let user_sessions = if never_logged_in {
        current_index += 1;
        vec![]
    } else {
        parse_user_sessions(&lines, &mut current_index)
    };

    let forward_status = parse_forward_status(&lines, &mut current_index);
    let mail_status = parse_mail_status(&lines, &mut current_index)?;
    let pgp_key = parse_pgp_key(&lines, &mut current_index);
    let project = parse_project(&lines, &mut current_index);
    let plan = parse_plan(&lines, &mut current_index);

    debug_assert!(
        current_index == lines.len(),
        "Not all lines in finger response were parsed for user {}. Unparsed lines: {:?}",
        username,
        &lines[current_index..]
    );

    Ok(FingerResponseStructuredUserEntry::new(
        username,
        full_name,
        home_dir,
        shell,
        office,
        office_phone,
        home_phone,
        never_logged_in,
        user_sessions,
        forward_status,
        mail_status,
        pgp_key,
        project,
        plan,
    ))
}

fn parse_full_name(first_line: &str, username: &str) -> anyhow::Result<String> {
    Ok(first_line
        .split("Name:")
        .nth(1)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to parse full name from finger response for user {}",
                username
            )
        })?
        .trim()
        .to_string())
}

fn parse_home_dir(second_line: &str, username: &str) -> anyhow::Result<PathBuf> {
    second_line
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
        })
}

fn parse_shell(second_line: &str, username: &str) -> anyhow::Result<PathBuf> {
    second_line
        .split("Shell:")
        .nth(1)
        .map(|s| s.trim())
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to parse shell from finger response for user {}",
                username
            )
        })
}

fn parse_gecos_fields(
    lines: &[&str],
    current_index: &mut usize,
) -> anyhow::Result<(Option<String>, Option<String>, Option<String>)> {
    let mut office: Option<String> = None;
    let mut office_phone: Option<String> = None;
    let mut home_phone: Option<String> = None;

    // TODO: handle case where office details contains comma, use last comma as separator
    if let Some(line) = lines.get(*current_index)
        && line.trim().starts_with("Office:")
    {
        let office_line = line.trim().trim_start_matches("Office:").trim();
        if let Some((office_loc, phone)) = office_line.split_once(',') {
            office = Some(office_loc.trim().to_string());
            office_phone = Some(phone.trim().to_string());
        } else {
            office = Some(office_line.to_string());
        }
        *current_index += 1;
    }
    if let Some(line) = lines.get(*current_index)
        && line.trim().starts_with("Office Phone:")
    {
        let phone = line.trim().trim_start_matches("Office Phone:").trim();
        office_phone = Some(phone.to_string());
        *current_index += 1;
    }
    if let Some(line) = lines.get(*current_index)
        && line.trim().starts_with("Home Phone:")
    {
        let phone = line.trim().trim_start_matches("Home Phone:").trim();
        home_phone = Some(phone.to_string());
        *current_index += 1;
    }

    Ok((office, office_phone, home_phone))
}

fn parse_user_sessions(
    lines: &[&str],
    current_index: &mut usize,
) -> Vec<FingerResponseUserSession> {
    let mut sessions = Vec::new();

    while let Some(line) = lines.get(*current_index)
        && line.starts_with("On since")
    {
        let line_to_parse = if line.contains("from")
            && let Some(next_line) = lines.get(*current_index + 1)
            && next_line
                .trim_suffix(" (messages off)")
                .strip_suffix("idle")
                .is_some()
        {
            *current_index += 2;
            line.to_string() + "\n" + next_line
        } else {
            *current_index += 1;
            line.to_string()
        };

        match parse_user_session(&line_to_parse) {
            Ok(session) => {
                sessions.push(session);
            }
            Err(err) => {
                tracing::warn!("Failed to parse user session from line: {}\n{}", line, err);
            }
        }
    }

    sessions
}

/// Try parsing a [FingerResponseUserSession] from the text format used by bsd-finger.
pub fn parse_user_session(line: &str) -> anyhow::Result<FingerResponseUserSession> {
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

    let (tty_loc, tty_str) = parts
        .iter()
        .enumerate()
        .skip(2)
        .skip_while(|&(_, &s)| s != "on")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Failed to find tty in finger session line: {line}"))?;
    let tty = tty_str.trim_end_matches(',').to_string();

    let (host_loc, host) = match parts
        .iter()
        .enumerate()
        .skip(tty_loc)
        .skip_while(|&(_, &s)| s != "from")
        .nth(1)
    {
        Some((host_loc, host)) => (host_loc, Some(host.to_string())),
        None => (tty_loc, None),
    };

    let idle_str = parts
        .iter()
        .skip(host_loc + 1)
        .take_while(|&&x| x != "idle")
        .join(" ")
        .trim_end_matches("(messages off)")
        .to_string();

    let idle_time = if idle_str.is_empty() {
        None
    } else {
        Some(parse_user_session_idle_time(&idle_str)?)
    };

    let messages_on = !line.ends_with("(messages off)");

    Ok(FingerResponseUserSession::new(
        tty,
        login_time,
        host,
        idle_time,
        messages_on,
    ))
}

/// Parse the idle time from the text string generated by bsd-finger
fn parse_user_session_idle_time(str: &str) -> anyhow::Result<Duration> {
    let mut total_duration = Duration::zero();

    let parts: Vec<&str> = str.split_whitespace().collect();
    let mut i = 0;
    while i < parts.len() {
        let value_str = parts[i];
        let unit_str = parts
            .get(i + 1)
            .ok_or_else(|| anyhow::anyhow!("Missing time unit in idle time string: {}", str))?;

        let value: i64 = value_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse value from idle time {}: {}", str, e))?;

        match *unit_str {
            "day" | "days" => total_duration += Duration::days(value),
            "hour" | "hours" => total_duration += Duration::hours(value),
            "minute" | "minutes" => total_duration += Duration::minutes(value),
            "second" | "seconds" => total_duration += Duration::seconds(value),
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown time unit '{}' in idle time string: {}",
                    unit_str,
                    str
                ));
            }
        }

        i += 2;
    }

    Ok(total_duration)
}

fn parse_forward_status(lines: &[&str], current_index: &mut usize) -> Option<String> {
    let next_line = lines.get(*current_index);

    // TODO: handle multi-line case
    if let Some(line) = next_line
        && line.trim().starts_with("Mail forwarded to ")
    {
        *current_index += 1;
        Some(line.trim().trim_prefix("Mail forwarded to ").to_string())
    } else {
        None
    }
}

fn parse_mail_status(
    lines: &[&str],
    current_index: &mut usize,
) -> anyhow::Result<Option<MailStatus>> {
    let next_line = lines.get(*current_index);

    if let Some(line) = next_line
        && line.trim().starts_with("New mail received")
    {
        let received_time_line =
            parse_bsd_finger_time(line.trim().trim_start_matches("New mail received "))?;

        let unread_since_line = parse_bsd_finger_time(
            lines
                .get(*current_index + 1)
                .ok_or_else(|| anyhow::anyhow!("Missing unread since line in mail status"))?
                .trim()
                .trim_start_matches("Unread since "),
        )?;

        *current_index += 2;

        Ok(Some(MailStatus::NewMailReceived {
            received_time: received_time_line,
            unread_since: unread_since_line,
        }))
    } else if let Some(line) = next_line
        && (line.trim().starts_with("Mail last read"))
    {
        *current_index += 1;
        let datetime = parse_bsd_finger_time(line.trim().trim_prefix("Mail last read "))?;
        Ok(Some(MailStatus::MailLastRead(datetime)))
    } else if let Some(line) = next_line
        && line.trim() == "No mail."
    {
        *current_index += 1;
        Ok(Some(MailStatus::NoMail))
    } else {
        tracing::warn!("Failed to parse mail status from line: {:?}", next_line);
        Ok(None)
    }
}

fn parse_pgp_key(lines: &[&str], current_index: &mut usize) -> Option<String> {
    let next_line = lines.get(*current_index);

    if let Some(line) = next_line
        && line.trim().starts_with("PGP key:")
    {
        *current_index += 1;
        let mut pgp_lines = Vec::new();
        while let Some(line) = lines.get(*current_index) {
            let trimmed = line.trim();
            if trimmed.starts_with("Project:") || trimmed.starts_with("Plan:") {
                break;
            }
            pgp_lines.push(trimmed);
            *current_index += 1;
        }
        Some(pgp_lines.join("\n"))
    } else {
        None
    }
}

fn parse_project(lines: &[&str], current_index: &mut usize) -> Option<String> {
    let next_line = lines.get(*current_index);

    if let Some(line) = next_line
        && line.trim().starts_with("Project:")
    {
        if line.trim().trim_start_matches("Project:").trim().is_empty() {
            *current_index += 1;

            let mut project_lines = Vec::new();
            while let Some(line) = lines.get(*current_index) {
                let trimmed = line.trim();
                if trimmed.starts_with("Plan:") {
                    break;
                }
                project_lines.push(trimmed);
                *current_index += 1;
            }
            Some(project_lines.join("\n"))
        } else {
            *current_index += 1;
            Some(
                line.trim()
                    .trim_start_matches("Project:")
                    .trim()
                    .to_string(),
            )
        }
    } else {
        None
    }
}

fn parse_plan(lines: &[&str], current_index: &mut usize) -> Option<String> {
    let next_line = lines.get(*current_index);

    if let Some(line) = next_line
        && line.trim().starts_with("Plan:")
    {
        if line.trim().trim_start_matches("Plan:").trim().is_empty() {
            *current_index += 1;
            let mut plan_lines = Vec::new();
            while let Some(line) = lines.get(*current_index) {
                plan_lines.push(line.trim());
                *current_index += 1;
            }
            Some(plan_lines.join("\n"))
        } else {
            *current_index += 1;
            Some(line.trim().trim_start_matches("Plan:").trim().to_string())
        }
    } else if let Some(line) = next_line
        && line.trim() == "No Plan."
    {
        *current_index += 1;
        None
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Timelike};

    use super::*;

    #[test]
    fn test_parse_bsd_finger_time() {
        let cases = vec![
            "Mon Mar  1 10:00 (UTC)",
            "Tue Feb 28 23:59 (UTC)",
            "Wed Dec 31 00:00 (UTC)",
            "Wed Dec 31 00:00 (GMT)",
            "Wed Dec 31 00:00 (Asia/Tokyo)",
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
    fn test_parse_user_session_idle_time() {
        let cases = vec![
            ("1 second", 1),
            ("3 minutes 2 seconds", 3 * 60 + 2),
            (
                "1 day 5 hours 30 minutes",
                1 * 24 * 60 * 60 + 5 * 60 * 60 + 30 * 60,
            ),
            ("1 day 1 second", 1 * 24 * 60 * 60 + 1),
        ];

        for (input, expected_seconds) in cases {
            let duration = parse_user_session_idle_time(input).unwrap();
            assert_eq!(
                duration.num_seconds(),
                expected_seconds,
                "Failed on input: {}",
                input
            );
        }
    }

    #[test]
    fn test_finger_user_session_parsing() {
        let line = "On since Mon Mar  1 10:00 (UTC) on pts/0 from host.example.com";
        let session = parse_user_session(line).unwrap();
        assert_eq!(session.tty, "pts/0");
        assert_eq!(session.host, Some("host.example.com".into()));
        assert_eq!(session.login_time.weekday(), Weekday::Mon);
        assert_eq!(session.login_time.hour(), 10);
        assert_eq!(session.idle_time, None);
        assert!(session.messages_on);

        let line_off =
            "On since Mon Mar  1 10:00 (UTC) on pts/1 from another.host.com (messages off)";
        let session_off = parse_user_session(line_off).unwrap();
        assert_eq!(session_off.tty, "pts/1");
        assert_eq!(session_off.host, Some("another.host.com".into()));
        assert_eq!(session_off.login_time.weekday(), Weekday::Mon);
        assert_eq!(session_off.login_time.hour(), 10);
        assert_eq!(session_off.idle_time, None);
        assert!(!session_off.messages_on);

        let line_idle = "On since Mon Mar  1 10:00 (UTC) on pts/2 1 day 5 hours 30 minutes idle";
        let session_idle = parse_user_session(line_idle).unwrap();
        assert_eq!(session_idle.tty, "pts/2");
        assert_eq!(session_idle.host, None);
        assert_eq!(session_idle.login_time.weekday(), Weekday::Mon);
        assert_eq!(session_idle.login_time.hour(), 10);
        assert_eq!(
            session_idle.idle_time.unwrap().num_minutes(),
            1 * 24 * 60 + 5 * 60 + 30
        );
        assert!(session_idle.messages_on);

        let line_idle_off = "On since Mon Mar  1 10:00 (UTC) on pts/3 from host.example.com 47 minutes 1 second idle (messages off)";
        let session_idle_off = parse_user_session(line_idle_off).unwrap();
        assert_eq!(session_idle_off.tty, "pts/3");
        assert_eq!(session_idle_off.host, Some("host.example.com".into()));
        assert_eq!(session_idle_off.login_time.weekday(), Weekday::Mon);
        assert_eq!(session_idle_off.login_time.hour(), 10);
        assert_eq!(session_idle_off.idle_time.unwrap().num_minutes(), 47);
        assert!(!session_idle_off.messages_on);

        let line_host_and_idle = indoc::indoc! {"
          On since Mon Mar  1 10:00 (UTC) on pts/4 from host.example.com
             2 hours idle
        "}
        .trim();
        let session_host_and_idle = parse_user_session(line_host_and_idle).unwrap();
        assert_eq!(session_host_and_idle.tty, "pts/4");
        assert_eq!(session_host_and_idle.host, Some("host.example.com".into()));
        assert_eq!(session_host_and_idle.login_time.weekday(), Weekday::Mon);
        assert_eq!(session_host_and_idle.login_time.hour(), 10);
        assert_eq!(
            session_host_and_idle.idle_time.unwrap().num_minutes(),
            60 * 2
        );
        assert!(session_host_and_idle.messages_on);

        // FIXME: "CEST" timezone parsing is currently broken
        // let line_cest_timezone = indoc::indoc! {"
        //   On since Thu Apr 30 05:45 (CEST) on pts/4 from 10.0.0.192
        //      6 hours 34 minutes idle
        // "}
        // .trim();
        // let session_cest = parse_user_session(line_cest_timezone).unwrap();
        // assert_eq!(session_cest.tty, "pts/4");
        // assert_eq!(session_cest.host, Some("10.0.0.192".to_string()));
        // assert_eq!(session_cest.login_time.weekday(), Weekday::Thu);
        // assert_eq!(session_cest.login_time.hour(), 5);
        // assert_eq!(session_cest.idle_time.unwrap().num_minutes(), 6 * 60 + 34);
        // assert!(session_cest.messages_on);
    }

    #[test]
    fn test_finger_user_entry_parsing_basic() {
        let response_content = indoc::indoc! {"
          Login: alice           			Name: Alice Wonderland
          Directory: /home/alice             	Shell: /bin/bash
          On since Mon Mar  1 10:00 (UTC) on pts/0 from host.example.com
          No mail.
          No Plan.
        "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "alice".to_string(),
        )
        .unwrap();
        assert_eq!(user_entry.username, "alice");
        assert_eq!(user_entry.full_name, "Alice Wonderland");
        assert_eq!(user_entry.home_dir, PathBuf::from("/home/alice"));
        assert_eq!(user_entry.shell, PathBuf::from("/bin/bash"));
        assert_eq!(user_entry.sessions.len(), 1);
        assert_eq!(user_entry.sessions[0].tty, "pts/0");
        assert_eq!(user_entry.sessions[0].host, Some("host.example.com".into()));
    }

    #[test]
    #[ignore = "CEST timezone parsing is currently broken"]
    fn test_finger_user_entry_parsing_idle_sessions() {
        let response_content = indoc::indoc! {"
        Login: alice           			Name: Alice Wonderland
        Directory: /home/alice             	Shell: /bin/bash
        On since Thu Apr 30 05:45 (CEST) on pts/4 from 10.0.0.192
           6 hours 34 minutes idle
        On since Thu Apr 30 05:46 (CEST) on pts/5 from 10.0.0.192
           6 hours 33 minutes idle
        No mail.
        No Plan.
      "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "alice".to_string(),
        )
        .unwrap();

        assert_eq!(user_entry.sessions.len(), 2);

        assert_eq!(user_entry.sessions[0].tty, "pts/4");
        assert_eq!(user_entry.sessions[0].host, Some("10.0.0.192".into()));
        assert_eq!(
            user_entry.sessions[0].idle_time.unwrap().num_minutes(),
            6 * 60 + 34
        );

        assert_eq!(user_entry.sessions[1].tty, "pts/5");
        assert_eq!(user_entry.sessions[1].host, Some("10.0.0.192".into()));
        assert_eq!(
            user_entry.sessions[1].idle_time.unwrap().num_minutes(),
            6 * 60 + 33
        );
    }

    #[test]
    fn test_finger_user_entry_parsing_single_line_office_phone() {
        let response_content = indoc::indoc! {"
          Login: alice           			Name: Alice Wonderland
          Directory: /home/alice             	Shell: /bin/bash
          Office: 123 Main St, 012-345-6789
          Home Phone: +0-123-456-7890
          On since Mon Mar  1 10:00 (UTC) on pts/0, idle 5:00, from host.example.com
          No mail.
          No Plan.
        "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "alice".to_string(),
        )
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
          No mail.
          No Plan.
        "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "alice".to_string(),
        )
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
          No mail.
          No Plan.
        "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "bob".to_string(),
        )
        .unwrap();

        assert!(user_entry.never_logged_in);
        assert!(user_entry.sessions.is_empty());
    }

    #[test]
    fn test_finger_user_entry_parsing_no_mail() {
        let response_content = indoc::indoc! {"
        Login: bob           			Name: Bob Builder
        Directory: /home/bob             	Shell: /bin/zsh
        Never logged in.
        No mail.
        No Plan.
      "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "bob".to_string(),
        )
        .unwrap();
        assert_eq!(user_entry.mail_status, Some(MailStatus::NoMail));
    }

    #[test]
    fn test_finger_user_entry_parsing_new_mail_received() {
        let response_content = indoc::indoc! {"
        Login: bob           			Name: Bob Builder
        Directory: /home/bob             	Shell: /bin/zsh
        Never logged in.
        New mail received Mon Mar  1 10:00 (UTC)
             Unread since Mon Mar  1 09:00 (UTC)
        No Plan.
      "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "bob".to_string(),
        )
        .unwrap();
        assert_eq!(
            user_entry.mail_status,
            Some(MailStatus::NewMailReceived {
                received_time: Utc.with_ymd_and_hms(2021, 3, 1, 10, 0, 0).unwrap(),
                unread_since: Utc.with_ymd_and_hms(2021, 3, 1, 9, 0, 0).unwrap(),
            })
        );
    }

    #[test]
    fn test_finger_user_entry_parsing_mail_last_read() {
        let response_content = indoc::indoc! {"
        Login: bob           			Name: Bob Builder
        Directory: /home/bob             	Shell: /bin/zsh
        Never logged in.
        Mail last read Mon Mar  1 10:00 (UTC)
        No Plan.
      "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "bob".to_string(),
        )
        .unwrap();
        assert_eq!(
            user_entry.mail_status,
            Some(MailStatus::MailLastRead(
                Utc.with_ymd_and_hms(2021, 3, 1, 10, 0, 0).unwrap()
            ))
        );
    }

    #[test]
    fn test_finger_user_entry_parsing_single_line_plan_project() {
        let response_content = indoc::indoc! {"
        Login: bob           			Name: Bob Builder
        Directory: /home/bob             	Shell: /bin/zsh
        Never logged in.
        Mail last read Mon Mar  1 10:00 (UTC)
        Project: Build a new house.
        Plan: Build a new house.
      "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "bob".to_string(),
        )
        .unwrap();

        assert_eq!(user_entry.project, Some("Build a new house.".to_string()));
        assert_eq!(user_entry.plan, Some("Build a new house.".to_string()));
    }

    #[test]
    fn test_finger_user_entry_parsing_multiline_pgp_plan_project() {
        let response_content = indoc::indoc! {"
        Login: bob           			Name: Bob Builder
        Directory: /home/bob             	Shell: /bin/zsh
        Never logged in.
        Mail last read Mon Mar  1 10:00 (UTC)
        PGP key:
        -----BEGIN PGP KEY-----
        Version: GnuPG v1
        ABCDEFGHIJKLMNOPQRSTUVWXYZ
        -----END PGP KEY-----
        Project:
        Build a new house.

        Need to buy materials.
        Plan:
        Build a new house.

        Need to buy materials.
      "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "bob".to_string(),
        )
        .unwrap();
        assert_eq!(
        user_entry.pgp_key,
        Some("-----BEGIN PGP KEY-----\nVersion: GnuPG v1\nABCDEFGHIJKLMNOPQRSTUVWXYZ\n-----END PGP KEY-----".to_string()),
    );

        assert_eq!(
            user_entry.project,
            Some("Build a new house.\n\nNeed to buy materials.".to_string())
        );
        assert_eq!(
            user_entry.plan,
            Some("Build a new house.\n\nNeed to buy materials.".to_string())
        );
    }

    #[test]
    fn test_finger_user_entry_parsing_plan_keyword_in_plan() {
        let response_content = indoc::indoc! {"
        Login: bob           			Name: Bob Builder
        Directory: /home/bob             	Shell: /bin/zsh
        Never logged in.
        Mail last read Mon Mar  1 10:00 (UTC)
        Project:
        I put an extra Plan: keyword here for kaos.

        :3:3:3
        Plan:
        Build a new house.

        Plan:
        Need to buy materials.

        The plan is to build a new house.
      "}
        .trim();

        let response = RawFingerResponse::from(response_content.to_string());
        let user_entry = FingerResponseStructuredUserEntry::try_from_raw_finger_response(
            &response,
            "bob".to_string(),
        )
        .unwrap();

        assert_eq!(
            user_entry.project,
            Some("I put an extra Plan: keyword here for kaos.\n\n:3:3:3".to_string())
        );
        assert_eq!(
        user_entry.plan,
        Some("Build a new house.\n\nPlan:\nNeed to buy materials.\n\nThe plan is to build a new house.".to_string())
    );
    }
}
