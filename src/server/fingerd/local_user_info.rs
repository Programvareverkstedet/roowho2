use std::{
    fs::OpenOptions,
    io::{self, Read},
    net::hostname,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use anyhow::Context;
use chrono::{DateTime, Duration, Timelike, Utc};
use itertools::Itertools;
use nix::{libc, sys::stat::stat, unistd::Uid};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use users::all_users;
use uucore::utmpx::{Utmpx, UtmpxRecord};

use crate::{
    proto::finger_protocol::{
        FingerResponseStructuredUserEntry, FingerResponseUserLastLogin, FingerResponseUserSession,
    },
    server::{
        fingerd::{FingerRequestInfo, local_email},
        ignore_list::IgnoreList,
    },
};

const LASTLOG2_DB_PATH: &str = "/var/lib/lastlog/lastlog2.db";

/// Search for users whose username or full name contains the search string.
pub fn search_for_user(
    search_string: &str,
    match_fullnames: bool,
    request_info: &FingerRequestInfo,
    ignore_list: Option<&IgnoreList>,
) -> Vec<anyhow::Result<FingerResponseStructuredUserEntry>> {
    (unsafe { all_users() })
        .filter_map(|user| {
            let user = match nix::unistd::User::from_uid(user.uid().into()) {
                Ok(Some(user)) => user,
                Ok(None) => {
                    tracing::warn!(
                        "User with UID {} exists but could not retrieve user entry",
                        user.uid()
                    );
                    return None;
                }
                Err(e) => {
                    return Some(Err(anyhow::anyhow!(
                        "Failed to get user entry for UID {}: {}",
                        user.uid(),
                        e
                    )));
                }
            };

            let username = user.name;
            let full_name = String::from_utf8_lossy(
                user.gecos
                    .as_bytes()
                    .split(|&b| b == b',')
                    .next()
                    .unwrap_or(&[]),
            )
            .to_string();

            if ignore_list.is_some_and(|ignore_list| ignore_list.ignores_uid(user.uid.as_raw())) {
                return None;
            }

            let matches_username = username.contains(search_string);
            let matches_fullname = match_fullnames && full_name.contains(search_string);
            if matches_username || matches_fullname {
                match get_local_user(&username, None, request_info, ignore_list) {
                    Ok(Some(user_entry)) => Some(Ok(user_entry)),
                    Ok(None) => None, // User exists but has .nofinger, skip
                    Err(err) => Some(Err(err)),
                }
            } else {
                None
            }
        })
        .collect()
}

/// Retrieve information about all users currently logged in, based on utmpx records.
pub fn finger_utmp_users(
    request_info: &FingerRequestInfo,
    ignore_list: Option<&IgnoreList>,
) -> Vec<anyhow::Result<FingerResponseStructuredUserEntry>> {
    Utmpx::iter_all_records()
        .filter(|entry| entry.is_user_process())
        .into_group_map_by(|entry| entry.user())
        .into_iter()
        .filter(|(username, _)| {
            !ignore_list.is_some_and(|ignore_list| ignore_list.ignores_username(username))
        })
        .map(|(username, records)| {
            get_local_user(&username, Some(records), request_info, ignore_list)
        })
        .filter_map(|result| match result {
            Ok(Some(user_entry)) => Some(Ok(user_entry)),
            Ok(None) => None, // User has .nofinger, skip
            Err(err) => Some(Err(err)),
        })
        .collect()
}

/// Max number of bytes read from a user's dotfile (.plan, .project, etc.).
const MAX_USER_FILE_SIZE: u64 = 64 * 1024;

/// Read a dotfile from a user's home directory, if it should be shown.
///
/// The daemon typically runs with CAP_DAC_READ_SEARCH, so all permission
/// checks need to be done manually. Following checks should be done:
///
/// - it is not a symlink
/// - it is a regular file (i.e. not FIFO or device or whatnot)
/// - it is owned by `owner`
fn read_user_file(path: &Path, owner: Uid) -> anyhow::Result<Option<String>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    {
        Ok(file) => file,
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::debug!("Not reading {}: {}", path.display(), err);
            }
            return Ok(None);
        }
    };

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        tracing::debug!("Not reading {}: it's not a regular file", path.display());
        return Ok(None);
    }
    if metadata.uid() != owner.as_raw() {
        tracing::debug!(
            "Not reading {}: owned by uid {}, expected {}",
            path.display(),
            metadata.uid(),
            owner
        );
        return Ok(None);
    }
    if metadata.len() == 0 {
        return Ok(None);
    }

    let mut content = Vec::new();
    file.take(MAX_USER_FILE_SIZE).read_to_end(&mut content)?;

    Ok(Some(String::from_utf8_lossy(&content).trim().to_string()))
}

/// Look up the most recent login for a user in the lastlog2 database, if available.
fn read_lastlog2_entry(
    db_path: &Path,
    username: &str,
) -> anyhow::Result<Option<FingerResponseUserLastLogin>> {
    if !db_path.exists() {
        return Ok(None);
    }

    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("Failed to open {}", db_path.display()))?;

    let row = conn
        .query_row(
            "SELECT Time, TTY, RemoteHost FROM Lastlog2 WHERE Name = ?1",
            [username],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()
        .with_context(|| format!("Failed to query {}", db_path.display()))?;

    let Some((Some(time), tty, host)) = row else {
        return Ok(None);
    };

    let Some(login_time) = DateTime::<Utc>::from_timestamp_secs(time).filter(|_| time > 0) else {
        return Ok(None);
    };

    Ok(Some(FingerResponseUserLastLogin::new(
        tty.unwrap_or_default(),
        login_time,
        host.filter(|host| !host.is_empty()),
    )))
}

/// Retrieve local user information for the given username.
///
/// Returns None if the user does not exist.
fn get_local_user(
    username: &str,
    utmp_records: Option<Vec<UtmpxRecord>>,
    _request_info: &FingerRequestInfo,
    ignore_list: Option<&IgnoreList>,
) -> anyhow::Result<Option<FingerResponseStructuredUserEntry>> {
    tracing::trace!(
        "Retrieving local user information for username: {}",
        username
    );
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

    if ignore_list.is_some_and(|ignore_list| ignore_list.ignores_uid(user_entry.uid.as_raw())) {
        return Ok(None);
    }

    let nofinger_path = user_entry.dir.join(".nofinger");
    if nofinger_path.exists() {
        return Ok(None);
    }

    let full_name = user_entry.name;
    let home_dir = user_entry.dir.clone();
    let shell = user_entry.shell;

    let gecos_fields: Vec<&str> = full_name.split(',').collect();

    let office = gecos_fields.get(1).map(|s| s.to_string());
    let office_phone = gecos_fields.get(2).map(|s| s.to_string());
    let home_phone = gecos_fields.get(3).map(|s| s.to_string());

    let hostname = hostname()?.to_str().unwrap_or("localhost").to_string();

    let utmpx_records = match utmp_records {
        Some(records) => records,
        None => Utmpx::iter_all_records()
            .filter(|entry| entry.user() == username)
            .filter(|entry| entry.is_user_process())
            .collect::<Vec<_>>(),
    };

    let last_login = if utmpx_records.is_empty() {
        read_lastlog2_entry(Path::new(LASTLOG2_DB_PATH), &username).unwrap_or_else(|err| {
            tracing::warn!("Failed to read last login for {}: {:#}", username, err);
            None
        })
    } else {
        None
    };

    let user_never_logged_in = utmpx_records.is_empty() && last_login.is_none();

    let now = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());
    let sessions: Vec<FingerResponseUserSession> = utmpx_records
        .into_iter()
        .filter_map(|entry| {
            let login_time = entry
                .login_time()
                .checked_to_utc()
                .and_then(|t| DateTime::<Utc>::from_timestamp_secs(t.unix_timestamp()))?;

            let tty_device_path = Path::new("/dev").join(entry.tty_device());
            let tty_device_stat = stat(&tty_device_path).ok();

            let tty_is_x_console = entry.tty_device().starts_with(':');

            let idle_time = if tty_is_x_console {
                None
            } else {
                tty_device_stat.and_then(|st| {
                    let last_active = DateTime::<Utc>::from_timestamp_secs(st.st_atime)?;
                    let result = (now - last_active).max(Duration::zero());
                    if result == Duration::zero() {
                        None
                    } else {
                        debug_assert!(
                            result.num_seconds() >= 0,
                            "Idle time should never be negative"
                        );

                        Some(result)
                    }
                })
            };

            let messages_on =
              // X console logins does not show the tty, so messages should be considered off in that case
              !tty_is_x_console &&
              // Check if the user has write permissions to the tty device,
              // indicating whether messages are on or off
              tty_device_stat
                .map(|st| st.st_mode & 0o220 == 0o220)
                .unwrap_or(false);

            Some(FingerResponseUserSession::new(
                entry.tty_device(),
                login_time,
                Some(hostname.clone()),
                idle_time,
                messages_on,
            ))
        })
        .collect();

    let email_status = local_email::detect_new_mail_for_user(&username, &home_dir)?;

    let uid = user_entry.uid;

    let forward_path = user_entry.dir.join(".forward");
    let forward = read_user_file(&forward_path, uid)?;

    let pgpkey_path = user_entry.dir.join(".pgpkey");
    let pgpkey = read_user_file(&pgpkey_path, uid)?;

    let project_path = user_entry.dir.join(".project");
    let project = read_user_file(&project_path, uid)?;

    let plan_path = user_entry.dir.join(".plan");
    let plan = read_user_file(&plan_path, uid)?;

    Ok(Some(FingerResponseStructuredUserEntry::new(
        username,
        full_name,
        home_dir,
        shell,
        office,
        office_phone,
        home_phone,
        user_never_logged_in,
        sessions,
        last_login,
        forward,
        email_status,
        pgpkey,
        project,
        plan,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finger_root() {
        let user_entry = get_local_user(
            "root",
            None,
            &FingerRequestInfo::Long {
                prevent_files: false,
            },
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(user_entry.username, "root");
    }

    mod read_user_file {
        use std::{
            fs::{self, Permissions},
            os::unix::fs::{PermissionsExt, symlink},
            path::PathBuf,
        };

        use nix::{sys::stat::Mode, unistd::getuid};
        use tempfile::TempDir;

        use super::super::read_user_file;

        fn write_file(dir: &TempDir, name: &str, content: &[u8], mode: u32) -> PathBuf {
            let path = dir.path().join(name);
            fs::write(&path, content).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
            path
        }

        #[test]
        fn accepts_world_readable_file_owned_by_user() {
            let dir = TempDir::new().unwrap();
            let path = write_file(&dir, ".plan", b"  my plan\n", 0o644);

            let content = read_user_file(&path, getuid()).unwrap();
            assert_eq!(content, Some("my plan".to_string()));
        }

        #[test]
        fn missing_file_is_none() {
            let dir = TempDir::new().unwrap();
            let content = read_user_file(&dir.path().join(".plan"), getuid()).unwrap();
            assert_eq!(content, None);
        }

        #[test]
        fn empty_file_is_none() {
            let dir = TempDir::new().unwrap();
            let path = write_file(&dir, ".plan", b"", 0o644);
            assert_eq!(read_user_file(&path, getuid()).unwrap(), None);
        }

        #[test]
        fn rejects_symlinks() {
            let dir = TempDir::new().unwrap();
            let target = write_file(&dir, "secret", b"secret", 0o644);
            let link = dir.path().join(".plan");
            symlink(&target, &link).unwrap();

            assert_eq!(read_user_file(&link, getuid()).unwrap(), None);
        }

        #[test]
        fn rejects_file_owned_by_other_user() {
            let dir = TempDir::new().unwrap();
            let path = write_file(&dir, ".plan", b"plan", 0o644);
            let other_uid = nix::unistd::Uid::from_raw(getuid().as_raw().wrapping_add(1));

            assert_eq!(read_user_file(&path, other_uid).unwrap(), None);
        }

        #[test]
        fn accepts_non_world_readable_file() {
            let dir = TempDir::new().unwrap();
            let path = write_file(&dir, ".plan", b"plan", 0o600);
            assert_eq!(
                read_user_file(&path, getuid()).unwrap(),
                Some("plan".to_string())
            );
        }

        #[test]
        fn rejects_fifo() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join(".plan");
            nix::unistd::mkfifo(&path, Mode::from_bits_truncate(0o644)).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();

            assert_eq!(read_user_file(&path, getuid()).unwrap(), None);
        }

        #[test]
        fn rejects_directory() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join(".plan");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();

            assert_eq!(read_user_file(&path, getuid()).unwrap(), None);
        }
    }

    mod read_lastlog2_entry {
        use chrono::{TimeZone, Utc};
        use rusqlite::Connection;
        use tempfile::TempDir;

        use super::super::read_lastlog2_entry;

        fn create_db(dir: &TempDir) -> std::path::PathBuf {
            let path = dir.path().join("lastlog2.db");
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT);
                 INSERT INTO Lastlog2 VALUES ('alice', 1700000000, 'pts/3', 'host.example.com', 'sshd');
                 INSERT INTO Lastlog2 VALUES ('bob', 1700000000, 'tty2', '', 'login');
                 INSERT INTO Lastlog2 VALUES ('carol', 0, 'tty1', '', 'login');
                 INSERT INTO Lastlog2 VALUES ('dave', NULL, NULL, NULL, NULL);",
            )
            .unwrap();
            path
        }

        #[test]
        fn entry_with_host() {
            let dir = TempDir::new().unwrap();
            let path = create_db(&dir);
            let last_login = read_lastlog2_entry(&path, "alice").unwrap().unwrap();
            assert_eq!(last_login.tty, "pts/3");
            assert_eq!(last_login.host, Some("host.example.com".to_string()));
            assert_eq!(
                last_login.login_time,
                Utc.timestamp_opt(1700000000, 0).unwrap()
            );
        }

        #[test]
        fn empty_host_is_none() {
            let dir = TempDir::new().unwrap();
            let path = create_db(&dir);
            let last_login = read_lastlog2_entry(&path, "bob").unwrap().unwrap();
            assert_eq!(last_login.tty, "tty2");
            assert_eq!(last_login.host, None);
        }

        #[test]
        fn zero_or_null_time_is_none() {
            let dir = TempDir::new().unwrap();
            let path = create_db(&dir);
            assert_eq!(read_lastlog2_entry(&path, "carol").unwrap(), None);
            assert_eq!(read_lastlog2_entry(&path, "dave").unwrap(), None);
        }

        #[test]
        fn missing_user_is_none() {
            let dir = TempDir::new().unwrap();
            let path = create_db(&dir);
            assert_eq!(read_lastlog2_entry(&path, "eve").unwrap(), None);
        }

        #[test]
        fn missing_db_is_none() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("lastlog2.db");
            assert_eq!(read_lastlog2_entry(&path, "alice").unwrap(), None);
            assert!(!path.exists(), "a missing database should not be created");
        }
    }

    // TODO: test serialization roundtrip
}
