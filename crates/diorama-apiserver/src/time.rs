//! RFC 3339 timestamps at second precision, as Kubernetes metadata uses them.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix time in seconds.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current time as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn now_rfc3339() -> String {
    rfc3339_seconds(now_unix())
}

/// Formats a Unix timestamp in seconds as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn rfc3339_seconds(unix_secs: u64) -> String {
    let days = unix_secs / 86400;
    let rem = unix_secs % 86400;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fraction]Z` into Unix seconds; the fraction is dropped.
#[must_use]
pub fn parse_rfc3339_seconds(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let time = time.split_once('.').map_or(time, |(whole, _)| whole);
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u64 = date_parts.next()?.parse().ok()?;
    let day: u64 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn days_to_ymd(days: u64) -> (i64, u64, u64) {
    let z = (days as i64) + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn days_from_civil(year: i64, month: u64, day: u64) -> Option<u64> {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    u64::try_from(days).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_known_timestamps() {
        assert_eq!(rfc3339_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_seconds(1_791_146_364), "2026-10-04T20:39:24Z");
        assert_eq!(
            parse_rfc3339_seconds("2026-10-04T20:39:24Z"),
            Some(1_791_146_364)
        );
        assert_eq!(
            parse_rfc3339_seconds("2026-10-04T20:39:24.123456Z"),
            Some(1_791_146_364)
        );
        for secs in [0u64, 951_782_400, 1_709_164_800, 4_102_444_800] {
            assert_eq!(parse_rfc3339_seconds(&rfc3339_seconds(secs)), Some(secs));
        }
        assert_eq!(parse_rfc3339_seconds("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_seconds("not a time"), None);
    }
}
