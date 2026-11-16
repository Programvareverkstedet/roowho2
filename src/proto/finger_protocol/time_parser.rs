use anyhow::Context;
use chrono::{
    DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveTime, TimeZone, Timelike, Utc,
    Weekday,
};

const MAX_YEARS_BACK: i32 = 10;

/// Find the closest year, starting at `current_year` going backwards,
/// in which `month`/`day` falls on `weekday`.
fn guess_year_from_weekday(
    weekday: Weekday,
    month: u32,
    day: u32,
    current_year: i32,
) -> Option<i32> {
    (0..=MAX_YEARS_BACK)
        .map(|offset| current_year - offset)
        .find(|&year| {
            NaiveDate::from_ymd_opt(year, month, day).is_some_and(|d| d.weekday() == weekday)
        })
}

/// Parse the time serialization format commonly used by bsd-finger
pub(super) fn parse_bsd_finger_time(time: &str) -> anyhow::Result<DateTime<Utc>> {
    parse_bsd_finger_time_at(time, Utc::now())
}

/// Testable variant of [`parse_bsd_finger_time`].
fn parse_bsd_finger_time_at(time: &str, now: DateTime<Utc>) -> anyhow::Result<DateTime<Utc>> {
    let time_parts: Vec<_> = time.split_ascii_whitespace().collect();

    let Some((timezone, time_parts)) = time_parts.split_last() else {
        anyhow::bail!("Empty login time");
    };

    let time_ = &time_parts.join(" ");
    let timezone = timezone.trim_start_matches('(').trim_end_matches(')');

    let tz = parse_timezone(timezone)
        .context(format!("Failed to parse timezone in login time: {}", time))?;

    let mut parts = time_.split_whitespace();

    let weekday = match parts.next() {
        Some("Mon") => Weekday::Mon,
        Some("Tue") => Weekday::Tue,
        Some("Wed") => Weekday::Wed,
        Some("Thu") => Weekday::Thu,
        Some("Fri") => Weekday::Fri,
        Some("Sat") => Weekday::Sat,
        Some("Sun") => Weekday::Sun,
        _ => anyhow::bail!("Invalid weekday in login time: {}", time_),
    };

    let month = match parts.next() {
        Some("Jan") => 1,
        Some("Feb") => 2,
        Some("Mar") => 3,
        Some("Apr") => 4,
        Some("May") => 5,
        Some("Jun") => 6,
        Some("Jul") => 7,
        Some("Aug") => 8,
        Some("Sep") => 9,
        Some("Oct") => 10,
        Some("Nov") => 11,
        Some("Dec") => 12,
        _ => anyhow::bail!("Invalid month in login time: {}", time_),
    };

    let day: u32 = parts
        .next()
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Invalid day in login time: {}", time_))?;

    let time_part = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing time in login time: {}", time_))?;

    let clock = NaiveTime::parse_from_str(time_part, "%H:%M").map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse time component in login time: {}: {}",
            time_,
            e
        )
    })?;

    let year = guess_year_from_weekday(weekday, month, day, now.year()).ok_or_else(|| {
        anyhow::anyhow!(
            "Could not find a valid year for login time {} within {} years",
            time_,
            MAX_YEARS_BACK
        )
    })?;

    tz.ymd_hm_to_utc(year, month, day, clock.hour(), clock.minute())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to convert login time to timezone-aware datetime: {}",
                time_
            )
        })
}

/// A time zone printed by `strftime("%Z")` in bsd-finger output.
#[derive(Debug, Clone, Copy, PartialEq)]
enum FingerTimeZone {
    /// A fixed UTC offset from a numeric zone name like `+03`.
    Fixed(FixedOffset),
    /// A named IANA time zone, e.g. `UTC` or `Europe/Oslo`.
    Named(chrono_tz::Tz),
}

impl FingerTimeZone {
    fn ymd_hm_to_utc(
        &self,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
    ) -> Option<DateTime<Utc>> {
        match self {
            Self::Fixed(offset) => offset
                .with_ymd_and_hms(year, month, day, hour, minute, 0)
                .single()
                .map(|dt| dt.with_timezone(&Utc)),
            Self::Named(tz) => tz
                .with_ymd_and_hms(year, month, day, hour, minute, 0)
                .single()
                .map(|dt| dt.with_timezone(&Utc)),
        }
    }
}

fn parse_timezone(timezone: &str) -> anyhow::Result<FingerTimeZone> {
    if let Some(offset) = parse_numeric_timezone(timezone) {
        return Ok(FingerTimeZone::Fixed(offset));
    }

    timezone
        .parse::<chrono_tz::Tz>()
        .map(FingerTimeZone::Named)
        .map_err(|e| anyhow::anyhow!("Unknown time zone {:?}: {}", timezone, e))
}

/// Parse numeric time zone abbreviationsused by tzdata
fn parse_numeric_timezone(timezone: &str) -> Option<FixedOffset> {
    let (sign, digits) = timezone.as_bytes().split_first()?;
    let sign = match sign {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };

    if !matches!(digits.len(), 2 | 4 | 6) || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }

    let mut fields = [0i32; 3];
    for (field, [tens, ones]) in fields.iter_mut().zip(digits.as_chunks::<2>().0) {
        *field = i32::from(tens - b'0') * 10 + i32::from(ones - b'0');
    }
    let [hours, minutes, seconds] = fields;

    if hours > 24 || minutes > 59 || seconds > 59 {
        return None;
    }

    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60 + seconds))
}

/// Parse the idle time from the text string generated by bsd-finger
pub(super) fn parse_user_session_idle_time(str: &str) -> anyhow::Result<Duration> {
    let mut total_duration = Duration::zero();

    let parts: Vec<&str> = str.split_whitespace().collect();
    let mut i = 0;
    while let Some(value_str) = parts.get(i) {
        let unit_str = parts
            .get(i + 1)
            .ok_or_else(|| anyhow::anyhow!("Missing time unit in idle time string: {}", str))?;

        let value: i64 = value_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse value from idle time {}: {}", str, e))?;

        match *unit_str {
            "day" | "days" => total_duration += Duration::days(value),
            "hour" | "hours" => total_duration += Duration::hours(value),
            "minute" | "minutes" => total_duration += Duration::minutes(value),
            "second" | "seconds" => total_duration += Duration::seconds(value),
            _ => {
                return Err(anyhow::anyhow!(
                    "Unknown time unit '{}' in idle time string: {}",
                    unit_str,
                    str
                ));
            }
        }

        i += 2;
    }

    Ok(total_duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 16, 12, 0, 0).unwrap()
    }

    #[test]
    fn test_parse_bsd_finger_time() {
        let cases = [
            ("Mon Mar  1 10:00 (UTC)", (2021, 3, 1, 10, 0)),
            ("Tue Feb 28 23:59 (UTC)", (2023, 2, 28, 23, 59)),
            ("Wed Dec 31 00:00 (UTC)", (2025, 12, 31, 0, 0)),
            ("Wed Dec 31 00:00 (GMT)", (2025, 12, 31, 0, 0)),
            ("Wed Dec 31 00:00 (Asia/Tokyo)", (2025, 12, 30, 15, 0)),
            ("Wed Dec 31 00:00 (+03)", (2025, 12, 30, 21, 0)),
            ("Wed Dec 31 00:00 (-0330)", (2025, 12, 31, 3, 30)),
        ];

        for (input, (y, mo, d, h, mi)) in cases {
            let expected = Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap();
            let datetime = parse_bsd_finger_time_at(input, fixed_now())
                .unwrap_or_else(|e| panic!("Failed to parse datetime for input {input:?}: {e}"));
            assert_eq!(datetime, expected, "Wrong datetime for input {input:?}");
        }
    }

    #[test]
    fn test_parse_bsd_finger_time_errors_on_bad_input() {
        let cases = [
            "",
            "   ",
            "(UTC)",
            "Mon (UTC)",
            "Mon Mar (UTC)",
            "Mon Mar  1 (UTC)",
            "Mon Mar  1 10:00",
            "Foo Mar  1 10:00 (UTC)",
            "Mon Foo  1 10:00 (UTC)",
            "Mon Mar 32 10:00 (UTC)",
            "Mon Mar  1 25:00 (UTC)",
            "Mon Mar  1 10:00 (Not/AZone)",
            "Mon Mar  1 10:00 (+3)",
        ];

        for input in cases {
            assert!(
                parse_bsd_finger_time_at(input, fixed_now()).is_err(),
                "Expected error for input {input:?}"
            );
        }
    }

    #[test]
    fn test_guess_year_from_weekday_picks_most_recent_year() {
        // Mar 1 is Sunday for both 2026 and 2020.
        assert_eq!(
            guess_year_from_weekday(Weekday::Sun, 3, 1, 2026),
            Some(2026)
        );
        // Jun 15 is Monday for both 2026 and 2020.
        assert_eq!(
            guess_year_from_weekday(Weekday::Mon, 6, 15, 2025),
            Some(2020)
        );
        // Feb 29 only exists in leap years. Mon Feb 29 was in 2016.
        assert_eq!(
            guess_year_from_weekday(Weekday::Mon, 2, 29, 2026),
            Some(2016)
        );
        // Feb 30 doesn't exist.
        assert_eq!(guess_year_from_weekday(Weekday::Mon, 2, 30, 2026), None);
    }

    #[test]
    fn test_parse_user_session_idle_time() {
        let cases = vec![
            ("1 second", 1),
            ("3 minutes 2 seconds", 3 * 60 + 2),
            (
                "1 day 5 hours 30 minutes",
                1 * 24 * 60 * 60 + 5 * 60 * 60 + 30 * 60,
            ),
            ("1 day 1 second", 1 * 24 * 60 * 60 + 1),
        ];

        for (input, expected_seconds) in cases {
            let duration = parse_user_session_idle_time(input).unwrap();
            assert_eq!(
                duration.num_seconds(),
                expected_seconds,
                "Failed on input: {}",
                input
            );
        }
    }
}
