//! The original rwhod protocol uses 32-bit integers for timestamps,
//!  which will cause overflow issues after 2038-01-19. To mitigate this,
//!  we decode timestamps by looking at the time the packet was received,
//!  comparing it to the current time or the time the packet was received,
//!  and ensuring any overflowed timestamps are corrected accordingly.

use chrono::{DateTime, Utc};

const RWHOD_TIMESTAMP_CORRECTION_WINDOW: i64 = 0x40000000_i64;
const RWHOD_TIMESTAMP_WRAP_INCREMENT: i64 = 0x70000000_i64 + 0x70000000_i64 + 0x20000000_i64;

/// Decodes a raw rwhod timestamp (i32) into a DateTime<Utc>,
/// adding a correction value to count for any detected overflows.
pub fn decode_rwhod_timestamp(raw: i32, correction: i64) -> Result<DateTime<Utc>, String> {
    DateTime::from_timestamp_secs(i64::from(raw) + correction).ok_or(format!(
        "Invalid timestamp: {} with correction {}",
        raw, correction
    ))
}

/// Calculates the correction value for a received rwhod timestamp (i32),
/// based on the current time (now) and the received timestamp (recvtime).
pub fn rwhod_time_correction(now: DateTime<Utc>, recvtime: i32) -> i64 {
    let delta = now.timestamp() - i64::from(recvtime);

    if delta <= RWHOD_TIMESTAMP_CORRECTION_WINDOW {
        return 0;
    }

    let wraps = (delta - RWHOD_TIMESTAMP_CORRECTION_WINDOW - 1)
        .div_euclid(RWHOD_TIMESTAMP_WRAP_INCREMENT)
        + 1;

    wraps * RWHOD_TIMESTAMP_WRAP_INCREMENT
}

/// Decodes a raw rwhod timestamp (i32) into a DateTime<Utc>,
/// by adding a correction value to count for any detected overflows,
/// while ensuring the decoded timestamp is not after the specified upper bound.
pub fn decode_rwhod_timestamp_not_after(
    raw: i32,
    base_correction: i64,
    upper_bound: DateTime<Utc>,
) -> Result<DateTime<Utc>, String> {
    let upper_bound = upper_bound.timestamp();

    for offset in [1_i64, 0, -1] {
        let correction = base_correction + offset * RWHOD_TIMESTAMP_WRAP_INCREMENT;
        let candidate = i64::from(raw) + correction;
        if candidate <= upper_bound {
            return DateTime::from_timestamp_secs(candidate).ok_or(format!(
                "Invalid timestamp: {} with correction {}",
                raw, correction
            ));
        }
    }

    decode_rwhod_timestamp(raw, base_correction - RWHOD_TIMESTAMP_WRAP_INCREMENT)
}

/// Decodes a raw rwhod timestamp (i32) into a DateTime<Utc>,
/// by adding a correction value to count for any detected overflows.
/// The correction value is calculated based on the provided `time` argument,
/// choosing the timestamp closest to `time` among the possible candidates.
pub fn decode_rwhod_timestamp_near_time(
    raw: i32,
    time: DateTime<Utc>,
) -> Result<DateTime<Utc>, String> {
    let base_correction = rwhod_time_correction(time, raw);
    let mut best_candidate = None;

    for offset in [1_i64, 0, -1] {
        let correction = base_correction + offset * RWHOD_TIMESTAMP_WRAP_INCREMENT;
        let candidate = i64::from(raw) + correction;
        let distance = (time.timestamp() - candidate).abs();

        match best_candidate {
            Some((best_distance, _, _)) if best_distance <= distance => {}
            _ => best_candidate = Some((distance, candidate, correction)),
        }
    }

    let (_, candidate, correction) = best_candidate.expect("candidate list should not be empty");
    DateTime::from_timestamp_secs(candidate).ok_or(format!(
        "Invalid timestamp: {} with correction {}",
        raw, correction
    ))
}

/// Encodes a DateTime<Utc> into a raw rwhod timestamp (i32).
pub fn encode_rwhod_timestamp(timestamp: DateTime<Utc>) -> i32 {
    timestamp.timestamp() as i32
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn test_rwhod_timestamp_correction_for_received_packets() {
        let now = Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap();
        let corrected_recvtime = now - chrono::Duration::days(1);
        let raw_recvtime = corrected_recvtime.timestamp() as i32;
        let correction = rwhod_time_correction(now, raw_recvtime);

        assert_eq!(correction, 1i64 << 32);
        assert_eq!(
            decode_rwhod_timestamp(raw_recvtime, correction).unwrap(),
            corrected_recvtime
        );
    }

    #[test]
    fn test_decode_rwhod_timestamp_near_time() {
        let now = Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap();
        let corrected_recvtime = now - chrono::Duration::days(1);
        let raw_recvtime = corrected_recvtime.timestamp() as i32;

        let decoded = decode_rwhod_timestamp_near_time(raw_recvtime, now).unwrap();
        assert_eq!(decoded, corrected_recvtime);
    }

    #[test]
    fn test_decode_rwhod_timestamp_not_after() {
        let now = Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap();
        let corrected_recvtime = now - chrono::Duration::days(1);
        let raw_recvtime = corrected_recvtime.timestamp() as i32;
        let base_correction = rwhod_time_correction(now, raw_recvtime);

        let decoded = decode_rwhod_timestamp_not_after(raw_recvtime, base_correction, now).unwrap();
        assert_eq!(decoded, corrected_recvtime);
    }

    #[test]
    fn test_decode_rwhod_timestamp_not_after_prefers_latest_plausible_pre_wrap_candidate() {
        let now = Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap();
        let recvtime = now - chrono::Duration::minutes(1);
        let boot_time = recvtime - chrono::Duration::days(100);

        let raw_recvtime = recvtime.timestamp() as i32;
        let raw_boot_time = boot_time.timestamp() as i32;
        let recvtime_correction = rwhod_time_correction(now, raw_recvtime);

        let decoded_boot_time =
            decode_rwhod_timestamp_not_after(raw_boot_time, recvtime_correction, recvtime).unwrap();

        assert_eq!(decoded_boot_time, boot_time);
    }

    #[test]
    fn test_encode_rwhod_timestamp_wraps_like_i32_cast() {
        let timestamp = Utc.with_ymd_and_hms(2045, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(
            encode_rwhod_timestamp(timestamp),
            timestamp.timestamp() as i32
        );
    }
}
