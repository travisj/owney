//! Minimal date formatting.
//!
//! Just enough to emit RFC 5322 `Date:`/`Received:` stamps (always UTC)
//! without pulling a calendar crate into every dependent.

/// Format a unix timestamp as an RFC 5322 date-time, e.g.
/// `Fri, 11 Jul 2026 03:54:35 +0000`.
pub fn rfc2822_utc(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday (weekday index 4 with Sunday = 0).
    let weekday = ((days + 4).rem_euclid(7)) as usize;

    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        WEEKDAYS[weekday],
        day,
        MONTHS[(month - 1) as usize],
        year,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
    )
}

/// Format a unix timestamp as JMAP `UTCDate`, e.g. `2026-07-11T14:38:29Z`.
pub fn iso8601_utc(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
    )
}

/// Days-since-epoch to (year, month, day) in the proleptic Gregorian calendar.
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(rfc2822_utc(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        // date -u -r 1783137275
        assert_eq!(
            rfc2822_utc(1_783_137_275),
            "Sat, 04 Jul 2026 03:54:35 +0000"
        );
        // leap day
        assert_eq!(
            rfc2822_utc(1_709_164_800),
            "Thu, 29 Feb 2024 00:00:00 +0000"
        );
        // pre-epoch
        assert_eq!(rfc2822_utc(-86_400), "Wed, 31 Dec 1969 00:00:00 +0000");
    }
}
