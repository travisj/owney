//! Minimal RFC 5545 extraction for calendar-invite detection.
//!
//! Deliberately not a full iCalendar parser: the detector only needs the
//! calendar-level METHOD and the headline fields of the first VEVENT to
//! surface "this email carries an invite" to clients. Recurrence, timezones
//! beyond literal UTC, and multi-event calendars are out of scope; the raw
//! DTSTART/DTEND values are passed through so a client can do better.

use serde_json::{Value, json};

/// Extract invite data from one `text/calendar` body, or `None` when no
/// VEVENT is present.
pub fn parse_invite(ics: &str) -> Option<Value> {
    let lines = unfold(ics);

    let mut method = None;
    let mut in_event = false;
    let mut uid = None;
    let mut summary = None;
    let mut location = None;
    let mut organizer = None;
    let mut dtstart = None;
    let mut dtend = None;
    let mut saw_event = false;

    for line in &lines {
        let Some((name, params, value)) = split_property(line) else {
            continue;
        };
        match (in_event, name.as_str()) {
            (false, "BEGIN") if value.eq_ignore_ascii_case("VEVENT") => {
                if saw_event {
                    break; // only the first VEVENT
                }
                in_event = true;
                saw_event = true;
            }
            (false, "METHOD") => method = Some(value.to_ascii_uppercase()),
            (true, "END") if value.eq_ignore_ascii_case("VEVENT") => in_event = false,
            (true, "UID") => uid = Some(value),
            (true, "SUMMARY") => summary = Some(unescape(&value)),
            (true, "LOCATION") => location = Some(unescape(&value)),
            (true, "ORGANIZER") => organizer = Some(value),
            (true, "DTSTART") => dtstart = Some((value, params)),
            (true, "DTEND") => dtend = Some((value, params)),
            _ => {}
        }
    }
    if !saw_event {
        return None;
    }

    let (start, start_at) = dtstart.map(|(v, _)| (v.clone(), utc_epoch(&v))).unzip();
    let (end, end_at) = dtend.map(|(v, _)| (v.clone(), utc_epoch(&v))).unzip();

    Some(json!({
        "method": method,
        "uid": uid,
        "summary": summary,
        "location": location,
        "organizer": organizer,
        "start": start,
        "end": end,
        "startAt": start_at.flatten(),
        "endAt": end_at.flatten(),
    }))
}

/// RFC 5545 §3.1: a line starting with SPACE or HTAB continues the previous
/// one (drop the CRLF and the single leading whitespace char).
fn unfold(ics: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in ics.split(['\r', '\n']).filter(|l| !l.is_empty()) {
        if let Some(rest) = raw.strip_prefix([' ', '\t'])
            && let Some(last) = lines.last_mut()
        {
            last.push_str(rest);
            continue;
        }
        lines.push(raw.to_owned());
    }
    lines
}

/// `NAME;PARAM=X;PARAM=Y:VALUE` → (NAME, params, VALUE). The colon separator
/// must be found outside a double-quoted param value (RFC 5545 §3.2).
fn split_property(line: &str) -> Option<(String, String, String)> {
    let mut in_quotes = false;
    let colon = line.char_indices().find_map(|(i, c)| match c {
        '"' => {
            in_quotes = !in_quotes;
            None
        }
        ':' if !in_quotes => Some(i),
        _ => None,
    })?;
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let (name, params) = head.split_once(';').unwrap_or((head, ""));
    Some((
        name.trim().to_ascii_uppercase(),
        params.to_owned(),
        value.trim().to_owned(),
    ))
}

/// RFC 5545 §3.3.11 TEXT unescaping.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') | Some('N') => out.push('\n'),
            Some(escaped) => out.push(escaped),
            None => out.push('\\'),
        }
    }
    out
}

/// Best-effort epoch seconds for the unambiguous UTC form
/// `YYYYMMDDTHHMMSSZ` (and all-day `YYYYMMDD` as midnight UTC). Local or
/// TZID-qualified times return `None` — the raw value is surfaced instead.
fn utc_epoch(value: &str) -> Option<i64> {
    let (date, time) = match value.len() {
        8 => (value, "000000"),
        16 if value.as_bytes()[8] == b'T' && value.ends_with('Z') => (&value[..8], &value[9..15]),
        _ => return None,
    };
    if !date.bytes().all(|b| b.is_ascii_digit()) || !time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i64 = date[..4].parse().ok()?;
    let month: i64 = date[4..6].parse().ok()?;
    let day: i64 = date[6..8].parse().ok()?;
    let hour: i64 = time[..2].parse().ok()?;
    let minute: i64 = time[2..4].parse().ok()?;
    let second: i64 = time[4..6].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// (year, month, day) to days-since-epoch; Howard Hinnant's `days_from_civil`
/// (the inverse of `owney_core::time::civil_from_days`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_request_with_folded_summary() {
        let ics = "BEGIN:VCALENDAR\r\n\
                   METHOD:REQUEST\r\n\
                   BEGIN:VEVENT\r\n\
                   UID:abc-123@cal.test\r\n\
                   SUMMARY:Team\r\n  sync about Q3\\, part one\r\n\
                   LOCATION:Room 4\r\n\
                   ORGANIZER;CN=\"Bob: The Organizer\":mailto:bob@example.com\r\n\
                   DTSTART:20260720T150000Z\r\n\
                   DTEND:20260720T160000Z\r\n\
                   END:VEVENT\r\n\
                   END:VCALENDAR\r\n";
        let invite = parse_invite(ics).expect("invite");
        assert_eq!(invite["method"], "REQUEST");
        assert_eq!(invite["uid"], "abc-123@cal.test");
        assert_eq!(invite["summary"], "Team sync about Q3, part one");
        assert_eq!(invite["location"], "Room 4");
        assert_eq!(invite["organizer"], "mailto:bob@example.com");
        assert_eq!(invite["start"], "20260720T150000Z");
        // date -u -d "2026-07-20T15:00:00Z" +%s
        assert_eq!(invite["startAt"], 1_784_559_600);
        assert_eq!(invite["endAt"], 1_784_563_200);
    }

    #[test]
    fn tzid_times_pass_through_without_epoch() {
        let ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:u\n\
                   DTSTART;TZID=America/New_York:20260720T110000\n\
                   END:VEVENT\nEND:VCALENDAR\n";
        let invite = parse_invite(ics).expect("invite");
        assert_eq!(invite["start"], "20260720T110000");
        assert_eq!(invite["startAt"], Value::Null);
    }

    #[test]
    fn all_day_date_becomes_midnight_utc() {
        let ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:u\n\
                   DTSTART;VALUE=DATE:20260101\nEND:VEVENT\nEND:VCALENDAR\n";
        let invite = parse_invite(ics).expect("invite");
        assert_eq!(invite["startAt"], 1_767_225_600); // 2026-01-01T00:00:00Z
    }

    #[test]
    fn no_vevent_means_no_invite() {
        assert!(parse_invite("BEGIN:VCALENDAR\nMETHOD:PUBLISH\nEND:VCALENDAR\n").is_none());
    }
}
