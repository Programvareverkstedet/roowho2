use std::path::Path;

use chrono::{DateTime, Duration, Timelike, Utc};
use nix::{
    sys::{stat::stat, sysinfo::sysinfo},
    unistd::gethostname,
};
use uucore::utmpx::Utmpx;

use crate::proto::{WhodStatusUpdate, WhodUserEntry};

/// Reads utmp entries to determine currently logged-in users.
pub fn generate_rwhod_user_entries(now: DateTime<Utc>) -> anyhow::Result<Vec<WhodUserEntry>> {
    Utmpx::iter_all_records()
        .filter(|entry| entry.is_user_process())
        .map(|entry| {
            let login_time = entry
                .login_time()
                .checked_to_utc()
                .and_then(|t| DateTime::<Utc>::from_timestamp_secs(t.unix_timestamp()))
                .ok_or_else(|| anyhow::anyhow!("Failed to convert login time to UTC"))?;

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

            Ok(WhodUserEntry::new(
                entry.tty_device(),
                entry.user(),
                login_time,
                idle_time,
            ))
        })
        .collect()
}

/// Generate a rwhod status update packet representing the current system state.
pub fn generate_rwhod_status_update() -> anyhow::Result<WhodStatusUpdate> {
    let sysinfo = sysinfo().unwrap();
    let load_average = sysinfo.load_average();
    let uptime = sysinfo.uptime();
    let hostname = gethostname()?.to_str().unwrap().to_string();
    let now = Utc::now().with_nanosecond(0).unwrap_or(Utc::now());

    let result = WhodStatusUpdate::new(
        now,
        None,
        hostname,
        (
            (load_average.0 * 100.0).abs() as i32,
            (load_average.1 * 100.0).abs() as i32,
            (load_average.2 * 100.0).abs() as i32,
        ),
        now - uptime,
        generate_rwhod_user_entries(now)?,
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rwhod_status_update() {
        let status_update = generate_rwhod_status_update().unwrap();
        println!("{:?}", status_update);
    }
}
