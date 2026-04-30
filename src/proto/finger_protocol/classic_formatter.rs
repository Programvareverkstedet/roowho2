use chrono::{Duration, TimeDelta};

use crate::proto::finger_protocol::{FingerResponseStructuredUserEntry, MailStatus};

pub fn classic_format_finger_response_structured_user_entry(
    entry: &FingerResponseStructuredUserEntry,
) -> String {
    let mut result = String::new();

    result += &format!(
        "Login: {:<16}\t\t\tName: {}\n",
        entry.username, entry.full_name
    );
    result += &format!(
        "Directory: {:<24}\tShell: {}\n",
        entry.home_dir.display(),
        entry.shell.display()
    );

    if let Some(office) = &entry.office {
        result += &format!("Office: {}\n", office);
    }
    if let Some(office_phone) = &entry.office_phone {
        result += &format!("Office Phone: {}\n", office_phone);
    }
    if let Some(home_phone) = &entry.home_phone {
        result += &format!("Home Phone: {}\n", home_phone);
    }

    if entry.never_logged_in {
        result += "Never logged in.\n";
    } else {
        let max_tty_len = entry
            .sessions
            .iter()
            .map(|s| s.tty.len())
            .max()
            .unwrap_or(0);

        for session in &entry.sessions {
            result += &format!(
                "On since {} on {}",
                session.login_time.format("%a %b %e %H:%M (%Z)"),
                session.tty,
            );

            if let Some(ref host) = session.host {
                result += &format!("from {}\n", host);
            }

            if let Some(idle_time) = session.idle_time {
                result += &format!(
                    "   {:<width$}",
                    format_idle_time_for_finger(idle_time),
                    width = max_tty_len + 1
                );
            }

            if !session.messages_on {
                result += " (messages off)"
            }
        }
    }

    if let Some(forward) = &entry.forward_status {
        result += &format!("Mail forwarded to {}\n", forward);
    }

    if let Some(mail_status) = &entry.mail_status {
        match mail_status {
            MailStatus::NoMail => result += "No mail.\n",
            MailStatus::NewMailReceived {
                received_time,
                unread_since,
            } => {
                result += &format!(
                    "New mail received {}\nUnread since {}\n",
                    received_time.format("%a %b %e %H:%M (%Z)"),
                    unread_since.format("%a %b %e %H:%M (%Z)")
                );
            }
            MailStatus::MailLastRead(last_read) => {
                result += &format!(
                    "Mail last read {}\n",
                    last_read.format("%a %b %e %H:%M (%Z)")
                );
            }
        }
    }

    if let Some(pgp_key) = &entry.pgp_key {
        result += &format!("PGP key:\n{}\n", pgp_key);
    }

    if let Some(project) = &entry.project {
        result += &format!("Project:\n{}\n", project);
    }

    if let Some(plan) = &entry.plan {
        result += &format!("Plan:\n{}\n", plan);
    } else {
        result += "No Plan.\n";
    }

    result.trim().to_string()
}

fn format_idle_time_for_finger(idle_time: TimeDelta) -> String {
    debug_assert!(
        idle_time.num_seconds() >= 0,
        "Idle time should never be negative"
    );

    let mut result = String::new();

    let days = idle_time.num_days();
    let hours = (idle_time - Duration::days(days)).num_hours();
    let minutes = (idle_time - Duration::days(days) - Duration::hours(hours)).num_minutes();
    let seconds =
        (idle_time - Duration::days(days) - Duration::hours(hours) - Duration::minutes(minutes))
            .num_seconds();

    if days > 0 {
        result += &format!("{} day{} ", days, if days == 1 { "" } else { "s" });
    }
    if hours > 0 {
        result += &format!("{} hour{} ", hours, if hours == 1 { "" } else { "s" });
    }
    if minutes > 0 && days == 0 {
        result += &format!("{} minute{} ", minutes, if minutes == 1 { "" } else { "s" });
    }
    if seconds > 0 && days == 0 && hours == 0 {
        result += &format!("{} second{} ", seconds, if seconds == 1 { "" } else { "s" });
    }

    result
}
