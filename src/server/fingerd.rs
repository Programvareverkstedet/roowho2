use std::{net::hostname, path::Path};

use chrono::{DateTime, Duration, Timelike, Utc};
use nix::sys::stat::stat;
use uucore::utmpx::Utmpx;

use crate::proto::finger_protocol::{FingerResponseUserEntry, FingerResponseUserSession};

/// Retrieve local user information for the given username.
///
/// Returns None if the user does not exist.
pub fn get_local_user(username: &str) -> anyhow::Result<Option<FingerResponseUserEntry>> {
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
    let sessions: Vec<FingerResponseUserSession> = Utmpx::iter_all_records()
        .filter(|entry| entry.user() == username)
        .filter(|entry| entry.is_user_process())
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

    Ok(Some(FingerResponseUserEntry::new(
        username, full_name, home_dir, shell, None, None, None, false, sessions, forward, None,
        None, None, plan,
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
