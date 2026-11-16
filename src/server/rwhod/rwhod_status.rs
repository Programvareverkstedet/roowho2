use std::path::Path;

use chrono::{DateTime, Duration, Timelike, Utc};
use nix::{
    sys::{stat::stat, sysinfo::sysinfo},
    unistd::gethostname,
};
use uucore::utmpx::Utmpx;

use crate::{
    proto::{WhodStatusUpdate, WhodUserEntry},
    server::ignore_list::IgnoreList,
};

/// Reads utmp entries to determine currently logged-in users.
pub fn generate_rwhod_user_entries(
    now: DateTime<Utc>,
    ignore_list: Option<&IgnoreList>,
) -> anyhow::Result<Vec<WhodUserEntry>> {
    let result = Utmpx::iter_all_records()
        .filter(|entry| entry.is_user_process())
        .filter(|entry| {
            !ignore_list.is_some_and(|ignore_list| ignore_list.ignores_username(&entry.user()))
        })
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
        .filter_map(|result: anyhow::Result<WhodUserEntry>| {
            result
                .inspect_err(|err| tracing::warn!("Skipping utmp entry: {err:#}"))
                .ok()
        })
        .collect();
    Ok(result)
}

/// Generate a rwhod status update packet representing the current system state.
pub fn generate_rwhod_status_update(
    ignore_list: Option<&IgnoreList>,
) -> anyhow::Result<WhodStatusUpdate> {
    let sysinfo = sysinfo()?;
    let load_average = sysinfo.load_average();
    let uptime = sysinfo.uptime();
    let hostname = gethostname()?.to_string_lossy().into_owned();
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
        generate_rwhod_user_entries(now, ignore_list)?,
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rwhod_status_update() {
        let status_update = generate_rwhod_status_update(None).unwrap();
        println!("{:?}", status_update);
    }
}
