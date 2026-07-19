//! The original rwhod protocol uses 32-bit integers for timestamps,
//!  which will cause overflow issues after 2038-01-19. To mitigate this,
//!  we decode timestamps by looking at the time the packet was received,
//!  comparing it to the current time or the time the packet was received,
//!  and ensuring any overflowed timestamps are corrected accordingly.

use chrono::{DateTime, Utc};

const RWHOD_TIMESTAMP_CORRECTION_WINDOW: i64 = 0x40000000_i64;
const RWHOD_TIMESTAMP_WRAP_INCREMENT: i64 = 0x1_0000_0000_i64;

const RWHOD_TIMESTAMP_FORWARD_ALLOWANCE: i64 = RWHOD_TIMESTAMP_CORRECTION_WINDOW;

/// Decodes a raw rwhod timestamp (i32) into a DateTime<Utc>,
/// adding a correction value to count for any detected overflows.
#[allow(dead_code)]
pub fn decode_rwhod_timestamp(raw: i32, correction: i64) -> Result<DateTime<Utc>, String> {
    DateTime::from_timestamp_secs(i64::from(raw) + correction).ok_or(format!(
        "Invalid timestamp: {} with correction {}",
        raw, correction
    ))
}

/// Calculates the correction value for a received rwhod timestamp (i32),
/// based on the current time (now) and the received timestamp (recvtime).
///
/// If the difference between the current time and the received timestamp is
/// above a certain threshold (`RWHOD_TIMESTAMP_CORRECTION_WINDOW`),
/// this function attempts to determine how many times the timestamp has
/// wrapped around and returns the appropriate additional correction value
/// to account for the overflow.
///
/// This function is roughly equivalent to the logic used in the original
/// program to handle timestamp overflows, but please consider using
/// `decode_rwhod_timestamp_near_time` for most use cases, as it is designed
/// to be more robust.
#[allow(dead_code)]
pub fn rwhod_time_correction(now: DateTime<Utc>, recvtime: i32) -> i64 {
    let delta = now.timestamp() - i64::from(recvtime);

    if delta <= RWHOD_TIMESTAMP_CORRECTION_WINDOW {
        return 0;
    }

    let wrap_count = (delta - RWHOD_TIMESTAMP_CORRECTION_WINDOW - 1)
        .div_euclid(RWHOD_TIMESTAMP_WRAP_INCREMENT)
        + 1;

    wrap_count * RWHOD_TIMESTAMP_WRAP_INCREMENT
}

/// Decodes a raw rwhod timestamp (i32) into a DateTime<Utc> using a wrap-sized
/// interval around the provided `time` reference.
///
/// You can think of this function as looking at the current timestamp and choosing
/// the closest valid timestamp behind it for the given raw value, while also allowing
/// it to be a certain amount of time in the future (forward allowance) to account for
/// clock skew or other synchronization issues.
pub fn decode_rwhod_timestamp_near_time_with_forward_allowance(
    raw: i32,
    time: DateTime<Utc>,
    forward_allowance: i64,
) -> Result<DateTime<Utc>, String> {
    debug_assert!(forward_allowance >= 0);
    debug_assert!(forward_allowance <= RWHOD_TIMESTAMP_WRAP_INCREMENT);

    let raw = i64::from(raw);
    let candidate = raw
        + (time.timestamp() + forward_allowance - raw).div_euclid(RWHOD_TIMESTAMP_WRAP_INCREMENT)
            * RWHOD_TIMESTAMP_WRAP_INCREMENT;

    DateTime::from_timestamp_secs(candidate).ok_or(format!(
        "Invalid timestamp: {} near {} with forward allowance {}",
        raw, time, forward_allowance
    ))
}

/// Decodes a raw rwhod timestamp (i32) into a DateTime<Utc> using the default
/// wrap-sized interval around the reference time.
pub fn decode_rwhod_timestamp_near_time(
    raw: i32,
    time: DateTime<Utc>,
) -> Result<DateTime<Utc>, String> {
    decode_rwhod_timestamp_near_time_with_forward_allowance(
        raw,
        time,
        RWHOD_TIMESTAMP_FORWARD_ALLOWANCE,
    )
}

pub struct RwhodTimestamps {
    pub boottime: DateTime<Utc>,
    pub sendtime: DateTime<Utc>,
    pub recvtime: Option<DateTime<Utc>>,
}

pub fn decode_rwhod_timestamps(
    wd_boottime: i32,
    wd_sendtime: i32,
    wd_recvtime: i32,
    now: DateTime<Utc>,
) -> Result<RwhodTimestamps, String> {
    let recvtime = if wd_recvtime == 0 {
        None
    } else {
        Some(decode_rwhod_timestamp_near_time(wd_recvtime, now)?)
    };

    let sendtime = decode_rwhod_timestamp_near_time(wd_sendtime, now)?;
    let boottime = decode_rwhod_timestamp_near_time(wd_boottime, now)?;

    Ok(RwhodTimestamps {
        boottime,
        sendtime,
        recvtime,
    })
}

/// Encodes a DateTime<Utc> into a raw rwhod timestamp (i32).
pub fn encode_rwhod_timestamp(timestamp: DateTime<Utc>) -> i32 {
    timestamp.timestamp() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rwhod_time_correction_no_wrap() {
        let now = DateTime::from_timestamp(i32::MAX as i64 + 1, 0).unwrap();
        let recvtime = i32::MAX;
        let correction = rwhod_time_correction(now, recvtime);

        assert_eq!(correction, 0);
    }

    #[test]
    fn test_rwhod_time_correction_with_single_wrap() {
        let now = DateTime::from_timestamp(i32::MAX as i64 + 2, 0).unwrap();
        let recvtime = i32::MAX.wrapping_add(1);
        let correction = rwhod_time_correction(now, recvtime);

        assert_eq!(correction, RWHOD_TIMESTAMP_WRAP_INCREMENT * 1);
    }

    #[test]
    fn test_rwhod_time_correction_with_multiple_wraps() {
        let now = DateTime::from_timestamp(i32::MAX as i64 + RWHOD_TIMESTAMP_WRAP_INCREMENT + 1, 0)
            .unwrap();
        let recvtime = i32::MAX.wrapping_add(1);
        let correction = rwhod_time_correction(now, recvtime);

        assert_eq!(correction, RWHOD_TIMESTAMP_WRAP_INCREMENT * 2);
    }

    #[test]
    fn test_rwhod_time_correction_with_negative_delta() {
        let now = DateTime::from_timestamp(i32::MAX as i64 - 1, 0).unwrap();
        let recvtime = i32::MAX;
        let correction = rwhod_time_correction(now, recvtime);

        assert_eq!(correction, 0);
    }

    #[test]
    fn test_rwhod_time_correction_with_large_negative_delta() {
        let now = DateTime::from_timestamp(i32::MIN as i64 - 1, 0).unwrap();
        let recvtime = i32::MIN;
        let correction = rwhod_time_correction(now, recvtime);

        assert_eq!(correction, 0);
    }

    #[test]
    fn test_decode_rwhod_timestamp_near_time_no_wrap() {
        let now = DateTime::from_timestamp(i32::MAX as i64 + 1, 0).unwrap();
        let expected = now - chrono::Duration::days(1);
        let raw = expected.timestamp() as i32;

        let decoded = decode_rwhod_timestamp_near_time(raw, now).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_rwhod_timestamp_near_time_with_wrap() {
        let now = DateTime::from_timestamp(i32::MAX as i64 + RWHOD_TIMESTAMP_WRAP_INCREMENT + 1, 0)
            .unwrap();
        let expected = now - chrono::Duration::days(1);
        let raw = expected.timestamp() as i32;

        let decoded = decode_rwhod_timestamp_near_time(raw, now).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_rwhod_timestamp_near_time_with_negative_delta() {
        let time = DateTime::from_timestamp(-(RWHOD_TIMESTAMP_WRAP_INCREMENT / 2) - 10, 0).unwrap();
        let raw = 0;

        let decoded = decode_rwhod_timestamp_near_time_with_forward_allowance(
            raw,
            time,
            RWHOD_TIMESTAMP_WRAP_INCREMENT / 2,
        )
        .unwrap();
        assert_eq!(
            decoded,
            DateTime::from_timestamp(-RWHOD_TIMESTAMP_WRAP_INCREMENT, 0).unwrap()
        );
    }

    #[test]
    fn test_decode_rwhod_timestamp_near_time_uses_forward_allowance() {
        let time = DateTime::from_timestamp(i32::MAX as i64 + 1, 0).unwrap();
        let expected = time + chrono::Duration::seconds(5);
        let raw = expected.timestamp() as i32;

        let decoded =
            decode_rwhod_timestamp_near_time_with_forward_allowance(raw, time, 5).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_rwhod_timestamp_near_time_small_forward_allowance_prefers_previous_wrap() {
        let time = DateTime::from_timestamp(i32::MAX as i64 + 1, 0).unwrap();
        let future = time + chrono::Duration::seconds(RWHOD_TIMESTAMP_WRAP_INCREMENT / 4);
        let raw = future.timestamp() as i32;

        let decoded = decode_rwhod_timestamp_near_time_with_forward_allowance(
            raw,
            time,
            RWHOD_TIMESTAMP_WRAP_INCREMENT / 10,
        )
        .unwrap();
        assert_eq!(
            decoded,
            future - chrono::Duration::seconds(RWHOD_TIMESTAMP_WRAP_INCREMENT)
        );
    }

    #[test]
    fn test_encode_rwhod_timestamp_no_wrap() {
        let timestamp = DateTime::from_timestamp(i32::MAX as i64, 0).unwrap();
        let encoded = encode_rwhod_timestamp(timestamp);
        assert_eq!(encoded, i32::MAX);
    }

    #[test]
    fn test_encode_rwhod_timestamp_with_wrap() {
        let timestamp = DateTime::from_timestamp(i32::MAX as i64 + 1, 0).unwrap();
        let encoded = encode_rwhod_timestamp(timestamp);
        assert_eq!(encoded, i32::MIN);
    }
}
