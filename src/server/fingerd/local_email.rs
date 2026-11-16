use chrono::{TimeZone, Utc};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

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

    if stat.st_size == 0 {
        return Ok(MailStatus::NoMail);
    }

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

    let new_mail_times = maildir_message_mtimes(&new_mail_path)?;

    if let (Some(&oldest), Some(&newest)) =
        (new_mail_times.iter().min(), new_mail_times.iter().max())
    {
        return Ok(MailStatus::NewMailReceived {
            received_time: Utc
                .timestamp_opt(newest, 0)
                .single()
                .unwrap_or_else(Default::default),
            unread_since: Utc
                .timestamp_opt(oldest, 0)
                .single()
                .unwrap_or_else(Default::default),
        });
    }

    if maildir_message_mtimes(&cur_mail_path)?.is_empty() {
        return Ok(MailStatus::NoMail);
    }

    let mail_read = nix::sys::stat::stat(&cur_mail_path)?.st_mtime;

    Ok(MailStatus::MailLastRead(
        Utc.timestamp_opt(mail_read, 0)
            .single()
            .unwrap_or_else(Default::default),
    ))
}

/// Returns mtimes of messages in a maildir subdirectory (`new/` or `cur/`).
fn maildir_message_mtimes(dir: &Path) -> anyhow::Result<Vec<i64>> {
    Ok(dir
        .read_dir()?
        .filter_map(Result::ok)
        .filter(|entry| !entry.file_name().as_encoded_bytes().starts_with(b"."))
        .filter_map(|entry| entry.metadata().ok())
        .map(|metadata| metadata.mtime())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::{
        fcntl::AT_FDCWD,
        sys::{stat::UtimensatFlags, time::TimeSpec},
    };
    use std::{fs, os::unix::fs::MetadataExt};
    use tempfile::TempDir;

    fn set_file_times(path: &Path, atime: i64, mtime: i64) {
        nix::sys::stat::utimensat(
            AT_FDCWD,
            path,
            &TimeSpec::new(atime, 0),
            &TimeSpec::new(mtime, 0),
            UtimensatFlags::FollowSymlink,
        )
        .unwrap();
    }

    fn set_dir_mtime(path: &Path, mtime: i64) {
        let metadata = fs::metadata(path).unwrap();
        set_file_times(path, metadata.atime(), mtime);
    }

    #[test]
    fn test_detect_new_mail_by_mailbox_new_mail_received() {
        let tempdir = TempDir::new().unwrap();
        let mailbox = tempdir.path().join("Mailbox");
        fs::write(&mailbox, b"mail").unwrap();
        set_file_times(&mailbox, 1_700_000_000, 1_700_000_100);

        let status = detect_new_mail_by_mailbox(&mailbox).unwrap();

        assert_eq!(
            status,
            MailStatus::NewMailReceived {
                received_time: Utc.timestamp_opt(1_700_000_100, 0).single().unwrap(),
                unread_since: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            }
        );
    }

    #[test]
    fn test_detect_new_mail_by_mailbox_mail_last_read() {
        let tempdir = TempDir::new().unwrap();
        let mailbox = tempdir.path().join("Mailbox");
        fs::write(&mailbox, b"mail").unwrap();
        set_file_times(&mailbox, 1_700_000_100, 1_700_000_000);

        let status = detect_new_mail_by_mailbox(&mailbox).unwrap();

        assert_eq!(
            status,
            MailStatus::MailLastRead(Utc.timestamp_opt(1_700_000_100, 0).single().unwrap())
        );
    }

    #[test]
    fn test_detect_new_mail_by_mailbox_empty_is_no_mail() {
        let tempdir = TempDir::new().unwrap();
        let mailbox = tempdir.path().join("Mailbox");
        fs::write(&mailbox, b"").unwrap();
        set_file_times(&mailbox, 1_700_000_000, 1_700_000_100);

        let status = detect_new_mail_by_mailbox(&mailbox).unwrap();

        assert_eq!(status, MailStatus::NoMail);
    }

    #[test]
    fn test_detect_new_mail_by_maildir_no_mail() {
        let tempdir = TempDir::new().unwrap();
        let maildir = tempdir.path().join("Maildir");
        let new_dir = maildir.join("new");
        let cur_dir = maildir.join("cur");
        fs::create_dir_all(&new_dir).unwrap();
        fs::create_dir_all(&cur_dir).unwrap();

        let status = detect_new_mail_by_maildir(&maildir).unwrap();

        assert_eq!(status, MailStatus::NoMail);
    }

    #[test]
    fn test_detect_new_mail_by_maildir_new_mail_received() {
        let tempdir = TempDir::new().unwrap();
        let maildir = tempdir.path().join("Maildir");
        let new_dir = maildir.join("new");
        let cur_dir = maildir.join("cur");
        fs::create_dir_all(&new_dir).unwrap();
        fs::create_dir_all(&cur_dir).unwrap();
        fs::write(new_dir.join("msg1"), b"mail").unwrap();
        fs::write(new_dir.join("msg2"), b"mail").unwrap();
        set_file_times(&new_dir.join("msg1"), 1_700_000_000, 1_700_000_000);
        set_file_times(&new_dir.join("msg2"), 1_700_000_100, 1_700_000_100);
        // `cur` being newer than `new` should not hide unread mail
        set_dir_mtime(&new_dir, 1_700_000_000);
        set_dir_mtime(&cur_dir, 1_700_000_200);

        let status = detect_new_mail_by_maildir(&maildir).unwrap();

        assert_eq!(
            status,
            MailStatus::NewMailReceived {
                received_time: Utc.timestamp_opt(1_700_000_100, 0).single().unwrap(),
                unread_since: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            }
        );
    }

    #[test]
    fn test_detect_new_mail_by_maildir_empty_new_with_newer_mtime() {
        let tempdir = TempDir::new().unwrap();
        let maildir = tempdir.path().join("Maildir");
        let new_dir = maildir.join("new");
        let cur_dir = maildir.join("cur");
        fs::create_dir_all(&new_dir).unwrap();
        fs::create_dir_all(&cur_dir).unwrap();
        fs::write(cur_dir.join("msg"), b"mail").unwrap();
        set_dir_mtime(&cur_dir, 1_700_000_000);
        set_dir_mtime(&new_dir, 1_700_000_100);

        let status = detect_new_mail_by_maildir(&maildir).unwrap();

        assert_eq!(
            status,
            MailStatus::MailLastRead(Utc.timestamp_opt(1_700_000_000, 0).single().unwrap())
        );
    }

    #[test]
    fn test_detect_new_mail_by_maildir_ignores_dotfiles() {
        let tempdir = TempDir::new().unwrap();
        let maildir = tempdir.path().join("Maildir");
        let new_dir = maildir.join("new");
        let cur_dir = maildir.join("cur");
        fs::create_dir_all(&new_dir).unwrap();
        fs::create_dir_all(&cur_dir).unwrap();
        fs::write(new_dir.join(".hidden"), b"").unwrap();
        fs::write(cur_dir.join(".hidden"), b"").unwrap();

        let status = detect_new_mail_by_maildir(&maildir).unwrap();

        assert_eq!(status, MailStatus::NoMail);
    }

    #[test]
    fn test_detect_new_mail_by_maildir_mail_last_read() {
        let tempdir = TempDir::new().unwrap();
        let maildir = tempdir.path().join("Maildir");
        let new_dir = maildir.join("new");
        let cur_dir = maildir.join("cur");
        fs::create_dir_all(&new_dir).unwrap();
        fs::create_dir_all(&cur_dir).unwrap();
        fs::write(cur_dir.join("msg"), b"mail").unwrap();
        set_dir_mtime(&new_dir, 1_700_000_000);
        set_dir_mtime(&cur_dir, 1_700_000_100);

        let status = detect_new_mail_by_maildir(&maildir).unwrap();

        assert_eq!(
            status,
            MailStatus::MailLastRead(Utc.timestamp_opt(1_700_000_100, 0).single().unwrap())
        );
    }
}
