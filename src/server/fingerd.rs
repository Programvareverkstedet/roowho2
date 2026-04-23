use std::{
    net::hostname,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use chrono::{DateTime, Duration, Timelike, Utc};
use nix::sys::stat::stat;
use users::all_users;
use uucore::utmpx::Utmpx;

use crate::proto::finger_protocol::{FingerResponseUserEntry, FingerResponseUserSession};

/// Search for users whose username or full name contains the search string.
pub fn search_for_user(
    search_string: &str,
    dont_search_fullnames: bool,
) -> Vec<anyhow::Result<FingerResponseUserEntry>> {
    (unsafe { all_users() })
        .filter_map(|user| {
            let user = match nix::unistd::User::from_uid(user.uid().into()) {
                Ok(Some(user)) => user,
                Ok(None) => return None, // User disappeared, skip
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
                &user
                    .gecos
                    .as_bytes()
                    .split(|&b| b == b',')
                    .next()
                    .unwrap_or(&[]),
            )
            .to_string();

            let matches_username = username.contains(search_string);
            let matches_fullname = !dont_search_fullnames && full_name.contains(search_string);
            if matches_username || matches_fullname {
                match get_local_user(&username) {
                    Ok(Some(user_entry)) => Some(Ok(user_entry)),
                    Ok(None) => None, // User exists but has .nofinger, skip
                    Err(err) => Some(Err(err.into())),
                }
            } else {
                None
            }
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
fn get_local_user(username: &str) -> anyhow::Result<Option<FingerResponseUserEntry>> {
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

    let mut utmpx_records = Utmpx::iter_all_records()
        .filter(|entry| entry.user() == username)
        .filter(|entry| entry.is_user_process())
        .peekable();

    // TODO: Don't use utmp entries for this, read from lastlog instead
    let user_never_logged_in = utmpx_records.peek().is_none();

    let now = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());
    let sessions: Vec<FingerResponseUserSession> = utmpx_records
        .filter_map(|entry| {
            let login_time = entry
                .login_time()
                .checked_to_utc()
                .and_then(|t| DateTime::<Utc>::from_timestamp_secs(t.unix_timestamp()))?;

            let tty_device_stat = stat(&Path::new("/dev").join(entry.tty_device())).ok();

            let idle_time = tty_device_stat
                .and_then(|st| {
                    let last_active = DateTime::<Utc>::from_timestamp_secs(st.st_atime)?;
                    Some((now - last_active).max(Duration::zero()))
                })
                .unwrap_or(Duration::zero());

            // Check if the write permission for "others" is set
            let messages_on = tty_device_stat
                .map(|st| st.st_mode & 0o002 != 0)
                .unwrap_or(false);

            debug_assert!(
                idle_time.num_seconds() >= 0,
                "Idle time should never be negative"
            );

            Some(FingerResponseUserSession::new(
                entry.tty_device(),
                login_time,
                idle_time,
                hostname.clone(),
                messages_on,
            ))
        })
        .collect();

    let forward_path = user_entry.dir.join(".forward");
    let forward = read_file_content_if_exists(&forward_path)?;

    let pgpkey_path = user_entry.dir.join(".pgpkey");
    let pgpkey = read_file_content_if_exists(&pgpkey_path)?;

    let project_path = user_entry.dir.join(".project");
    let project = read_file_content_if_exists(&project_path)?;

    let plan_path = user_entry.dir.join(".plan");
    let plan = read_file_content_if_exists(&plan_path)?;

    Ok(Some(FingerResponseUserEntry::new(
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
        None,
        pgpkey,
        project,
        plan,
    )))
}

// /// Retrieve remote user information for the given username on the specified host.
// ///
// /// Returns None if the user does not exist or no information is available.
// async fn get_remote_user(username: &str, host: &str) -> anyhow::Result<Option<RawFingerResponse>> {
//     let addr = format!("{}:79", host);
//     let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

//     if socket_addrs.is_empty() {
//         return Err(anyhow::anyhow!(
//             "Could not resolve address for host {}",
//             host
//         ));
//     }

//     let socket_addr = socket_addrs[0];

//     let mut stream = TcpStream::connect(socket_addr).await?;

//     let request = FingerRequest::new(false, username.to_string());
//     let request_bytes = request.to_bytes();
//     stream.write_all(&request_bytes).await?;

//     let mut response_bytes = Vec::new();
//     stream.read_to_end(&mut response_bytes).await?;

//     let response = RawFingerResponse::from_bytes(&response_bytes);

//     if response.is_empty() {
//         Ok(None)
//     } else {
//         Ok(Some(response))
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finger_root() {
        let user_entry = get_local_user("root").unwrap().unwrap();
        assert_eq!(user_entry.username, "root");
    }

    // TODO: test serialization roundtrip
}
