//! Parses `mkit log --since`/`--until` date arguments.
//!
//! Deliberately **not** git's full natural-language `approxidate` grammar
//! (issue #712's implementation notes point at the CLI's existing small,
//! explicit parsers — e.g. `HEAD~n` in `revspec.rs` — as the model to
//! follow, rather than adding a new date-parsing dependency or a large
//! grammar). Supported forms, tried in this order:
//!
//! - `@<unix-seconds>` — an exact Unix timestamp (git's own spelling).
//! - `now` / `today` — the current instant.
//! - `yesterday` — 24 hours before the current instant.
//! - `<N> <unit> ago` — `second`/`minute`/`hour`/`day`/`week`/`month`/
//!   `year`, singular or plural (e.g. `2 weeks ago`); `month`/`year` use
//!   git's own 30-/365-day approximation.
//! - `YYYY-MM-DD` — midnight UTC on that date.
//! - `YYYY-MM-DD HH:MM:SS` / `YYYY-MM-DDTHH:MM:SS[Z]` — an exact UTC
//!   instant.

const SECS_PER_MIN: u64 = 60;
const SECS_PER_HOUR: u64 = 60 * SECS_PER_MIN;
const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;
const SECS_PER_WEEK: u64 = 7 * SECS_PER_DAY;
/// git's `approxidate` uses a flat 30-day month; matched here for the same
/// "close enough" relative-date behavior.
const SECS_PER_MONTH: u64 = 30 * SECS_PER_DAY;
/// git's `approxidate` uses a flat 365-day year; matched here likewise.
const SECS_PER_YEAR: u64 = 365 * SECS_PER_DAY;

/// Parse a `--since`/`--until` value to Unix seconds. `now` is the current
/// instant (Unix seconds), injected so relative forms (`yesterday`, `2
/// days ago`) are deterministically testable.
pub(super) fn parse_date(s: &str, now: u64) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty date".to_string());
    }
    if let Some(rest) = s.strip_prefix('@') {
        return rest
            .parse::<u64>()
            .map_err(|_| format!("invalid date '{s}': expected a Unix timestamp after '@'"));
    }
    match s.to_ascii_lowercase().as_str() {
        "now" | "today" => return Ok(now),
        "yesterday" => return Ok(now.saturating_sub(SECS_PER_DAY)),
        _ => {}
    }
    if let Some(secs) = parse_relative_ago(s) {
        return Ok(now.saturating_sub(secs));
    }
    parse_absolute(s).ok_or_else(|| {
        format!(
            "invalid date '{s}': expected @<unix-seconds>, now/today/yesterday, \
             '<N> <unit> ago', YYYY-MM-DD, or YYYY-MM-DD HH:MM:SS"
        )
    })
}

/// `<N> <unit>(s) ago` → seconds before now. `None` if `s` doesn't match
/// the shape (falls through to absolute-date parsing).
fn parse_relative_ago(s: &str) -> Option<u64> {
    let rest = s.strip_suffix("ago")?.trim();
    let mut parts = rest.splitn(2, char::is_whitespace);
    let n: u64 = parts.next()?.trim().parse().ok()?;
    let unit = parts.next()?.trim().trim_end_matches('s');
    let per = match unit {
        "second" | "sec" => 1,
        "minute" | "min" => SECS_PER_MIN,
        "hour" => SECS_PER_HOUR,
        "day" => SECS_PER_DAY,
        "week" => SECS_PER_WEEK,
        "month" => SECS_PER_MONTH,
        "year" => SECS_PER_YEAR,
        _ => return None,
    };
    n.checked_mul(per)
}

/// `YYYY-MM-DD[ HH:MM:SS]` or `YYYY-MM-DDTHH:MM:SS[Z]` → Unix seconds
/// (UTC). `None` if `s` doesn't match the shape or a field is out of range.
fn parse_absolute(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date, time) = match s.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let mut it = date.splitn(4, '-');
    let year: i64 = it.next()?.parse().ok()?;
    let month: u32 = it.next()?.parse().ok()?;
    let day: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (hour, minute, second) = match time {
        None => (0, 0, 0),
        Some(t) => {
            let mut it = t.splitn(4, ':');
            let h: u32 = it.next()?.parse().ok()?;
            let m: u32 = it.next().unwrap_or("0").parse().ok()?;
            let sec: u32 = it.next().unwrap_or("0").parse().ok()?;
            if it.next().is_some() || h > 23 || m > 59 || sec > 60 {
                return None;
            }
            (h, m, sec)
        }
    };
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(i64::try_from(SECS_PER_DAY).ok()?)?
        .checked_add(i64::from(hour) * i64::try_from(SECS_PER_HOUR).ok()?)?
        .checked_add(i64::from(minute) * i64::try_from(SECS_PER_MIN).ok()?)?
        .checked_add(i64::from(second))?;
    u64::try_from(secs).ok()
}

/// Civil date → days-since-epoch (Howard Hinnant's `days_from_civil`,
/// exact over the proleptic Gregorian calendar). Inverse of
/// `git_tools::civil_from_days`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 }); // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000; // 2023-11-14 22:13:20 UTC

    #[test]
    fn epoch_spelling() {
        assert_eq!(parse_date("@1700000000", NOW), Ok(1_700_000_000));
    }

    #[test]
    fn now_today_yesterday() {
        assert_eq!(parse_date("now", NOW), Ok(NOW));
        assert_eq!(parse_date("Today", NOW), Ok(NOW));
        assert_eq!(parse_date("yesterday", NOW), Ok(NOW - 86_400));
    }

    #[test]
    fn relative_ago_units() {
        assert_eq!(parse_date("30 seconds ago", NOW), Ok(NOW - 30));
        assert_eq!(parse_date("5 minutes ago", NOW), Ok(NOW - 300));
        assert_eq!(parse_date("2 hours ago", NOW), Ok(NOW - 7_200));
        assert_eq!(parse_date("1 day ago", NOW), Ok(NOW - 86_400));
        assert_eq!(parse_date("2 weeks ago", NOW), Ok(NOW - 2 * 604_800));
        assert_eq!(parse_date("1 month ago", NOW), Ok(NOW - 2_592_000));
        assert_eq!(parse_date("1 year ago", NOW), Ok(NOW - 31_536_000));
    }

    #[test]
    fn absolute_date_only_is_midnight_utc() {
        assert_eq!(parse_date("1970-01-01", NOW), Ok(0));
        // 2023-11-14 00:00:00 UTC.
        assert_eq!(parse_date("2023-11-14", NOW), Ok(1_699_920_000));
    }

    #[test]
    fn absolute_date_time_space_and_t_separator() {
        assert_eq!(parse_date("2023-11-14 22:13:20", NOW), Ok(1_700_000_000));
        assert_eq!(parse_date("2023-11-14T22:13:20", NOW), Ok(1_700_000_000));
        assert_eq!(parse_date("2023-11-14T22:13:20Z", NOW), Ok(1_700_000_000));
    }

    #[test]
    fn leap_day_round_trips() {
        // 2020-02-29 00:00:00 UTC.
        assert_eq!(parse_date("2020-02-29", NOW), Ok(1_582_934_400));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_date("not-a-date", NOW).is_err());
        assert!(parse_date("2023-13-01", NOW).is_err());
        assert!(parse_date("2023-11-32", NOW).is_err());
        assert!(parse_date("", NOW).is_err());
        assert!(parse_date("@nope", NOW).is_err());
    }
}
