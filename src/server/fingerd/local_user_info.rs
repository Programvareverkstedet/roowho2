use std::{
    net::hostname,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use chrono::{DateTime, Duration, Timelike, Utc};
use itertools::Itertools;
use nix::sys::stat::stat;
use users::all_users;
use uucore::utmpx::{Utmpx, UtmpxRecord};

use crate::{
    proto::finger_protocol::{FingerResponseStructuredUserEntry, FingerResponseUserSession},
    server::{
        fingerd::{FingerRequestInfo, local_email},
        ignore_list::IgnoreList,
    },
};

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

/// Helper function to read the content of a file if it exists and is readable,
/// returning None if the file does not exist or is not readable.
fn read_file_content_if_exists(path: &Path) -> anyhow::Result<Option<String>> {
    let file_is_readable = path.exists()
        && path.is_file()
        && (((path.metadata()?.permissions().mode() & 0o400 != 0
            && nix::unistd::geteuid().as_raw() == path.metadata()?.uid())
            || (path.metadata()?.permissions().mode() & 0o040 != 0
                && nix::unistd::getegid().as_raw() == path.metadata()?.gid())
            || (path.metadata()?.permissions().mode() & 0o004 != 0))
            || caps::has_cap(
                None,
                caps::CapSet::Effective,
                caps::Capability::CAP_DAC_READ_SEARCH,
            )?)
        && path.metadata()?.len() > 0;

    if file_is_readable {
        Ok(Some(std::fs::read_to_string(path)?.trim().to_string()))
    } else {
        Ok(None)
    }
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

    // TODO: Don't use utmp entries for this, read from lastlog instead
    let user_never_logged_in = utmpx_records.is_empty();

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

    let forward_path = user_entry.dir.join(".forward");
    let forward = read_file_content_if_exists(&forward_path)?;

    let pgpkey_path = user_entry.dir.join(".pgpkey");
    let pgpkey = read_file_content_if_exists(&pgpkey_path)?;

    let project_path = user_entry.dir.join(".project");
    let project = read_file_content_if_exists(&project_path)?;

    let plan_path = user_entry.dir.join(".plan");
    let plan = read_file_content_if_exists(&plan_path)?;

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

    // TODO: test serialization roundtrip
}
