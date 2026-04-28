use chrono::{TimeZone, Utc};
use std::path::{Path, PathBuf};

use crate::proto::finger_protocol::MailStatus;

pub fn detect_new_mail_for_user(
    username: &str,
    homedir: &Path,
) -> anyhow::Result<Option<MailStatus>> {
    let mail_storage_paths: Vec<PathBuf> = vec![
        homedir.join("Mail"),
        homedir.join("Mailbox"),
        homedir.join("Maildir"),
        PathBuf::from("/var/mail").join(username),
        PathBuf::from("/var/spool/mail").join(username),
        PathBuf::from("/var/maildir").join(username),
        PathBuf::from("/var/spool/maildir").join(username),
    ];

    for path in mail_storage_paths {
        tracing::trace!("Checking for mail at path: {}", path.display());
        if path.is_dir() && path.join("new").is_dir() && path.join("cur").is_dir() {
            tracing::trace!("Detected maildir structure at path: {}", path.display());
            if let Ok(status) = detect_new_mail_by_maildir(&path) {
                return Ok(Some(status));
            }
        } else if path.is_file() {
            tracing::trace!("Detected mailbox file at path: {}", path.display());
            if let Ok(status) = detect_new_mail_by_mailbox(&path) {
                return Ok(Some(status));
            }
        }
    }

    Ok(None)
}

fn detect_new_mail_by_mailbox(mailbox_path: &Path) -> anyhow::Result<MailStatus> {
    let stat = nix::sys::stat::stat(mailbox_path)?;

    let mail_recv = stat.st_mtime;
    let mail_read = stat.st_atime;

    if mail_recv > mail_read {
        Ok(MailStatus::NewMailReceived {
            received_time: Utc
                .timestamp_opt(mail_recv, 0)
                .single()
                .unwrap_or_else(Default::default),
            unread_since: Utc
                .timestamp_opt(mail_read, 0)
                .single()
                .unwrap_or_else(Default::default),
        })
    } else {
        Ok(MailStatus::MailLastRead(
            Utc.timestamp_opt(mail_read, 0)
                .single()
                .unwrap_or_else(Default::default),
        ))
    }
}

fn detect_new_mail_by_maildir(maildir_path: &Path) -> anyhow::Result<MailStatus> {
    let new_mail_path = maildir_path.join("new");
    let cur_mail_path = maildir_path.join("cur");

    let mail_recv = nix::sys::stat::stat(&new_mail_path)?.st_mtime;
    let mail_read = nix::sys::stat::stat(&cur_mail_path)?.st_mtime;

    if new_mail_path.read_dir()?.next().is_none() && cur_mail_path.read_dir()?.next().is_none() {
        Ok(MailStatus::NoMail)
    } else if mail_recv > mail_read {
        Ok(MailStatus::NewMailReceived {
            received_time: Utc
                .timestamp_opt(mail_recv, 0)
                .single()
                .unwrap_or_else(Default::default),
            unread_since: Utc
                .timestamp_opt(mail_read, 0)
                .single()
                .unwrap_or_else(Default::default),
        })
    } else {
        Ok(MailStatus::MailLastRead(
            Utc.timestamp_opt(mail_read, 0)
                .single()
                .unwrap_or_else(Default::default),
        ))
    }
}
