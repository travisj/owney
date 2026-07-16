//! Minimal iCalendar (RFC 5545) serialization for booking confirmations.
//! The reverse of `owney-ai`'s parser: only what a METHOD:REQUEST invite
//! with one VEVENT needs.

use chrono::{TimeZone, Utc};

#[derive(Debug)]
pub struct IcsInvite<'a> {
    pub uid: &'a str,
    pub dtstamp: i64,
    pub start: i64,
    pub end: i64,
    pub summary: &'a str,
    pub description: Option<&'a str>,
    pub organizer_name: &'a str,
    pub organizer_email: &'a str,
    pub attendee_name: &'a str,
    pub attendee_email: &'a str,
}

pub fn render(invite: &IcsInvite<'_>) -> String {
    let mut out = String::new();
    let mut line = |content: &str| {
        out.push_str(&fold(content));
        out.push_str("\r\n");
    };
    line("BEGIN:VCALENDAR");
    line("VERSION:2.0");
    line("PRODID:-//Owney//Scheduling//EN");
    line("METHOD:REQUEST");
    line("BEGIN:VEVENT");
    line(&format!("UID:{}", invite.uid));
    line(&format!("DTSTAMP:{}", utc_stamp(invite.dtstamp)));
    line(&format!("DTSTART:{}", utc_stamp(invite.start)));
    line(&format!("DTEND:{}", utc_stamp(invite.end)));
    line(&format!("SUMMARY:{}", escape_text(invite.summary)));
    if let Some(description) = invite.description {
        line(&format!("DESCRIPTION:{}", escape_text(description)));
    }
    line(&format!(
        "ORGANIZER;CN={}:mailto:{}",
        quote_param(invite.organizer_name),
        invite.organizer_email
    ));
    line(&format!(
        "ATTENDEE;CN={};ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:{}",
        quote_param(invite.attendee_name),
        invite.attendee_email
    ));
    line("END:VEVENT");
    line("END:VCALENDAR");
    out
}

/// Unix seconds -> `YYYYMMDDTHHMMSSZ`.
fn utc_stamp(unix: i64) -> String {
    match Utc.timestamp_opt(unix, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y%m%dT%H%M%SZ").to_string(),
        _ => "19700101T000000Z".to_string(),
    }
}

/// RFC 5545 §3.3.11 TEXT escaping.
fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// Param values with reserved chars get DQUOTE-quoting (RFC 5545 §3.2);
/// double quotes themselves cannot appear and are dropped.
fn quote_param(value: &str) -> String {
    let cleaned: String = value.chars().filter(|c| *c != '"').collect();
    if cleaned.contains([';', ':', ',']) {
        format!("\"{cleaned}\"")
    } else {
        cleaned
    }
}

/// RFC 5545 §3.1 content-line folding at 75 octets, UTF-8 boundary safe.
fn fold(line: &str) -> String {
    if line.len() <= 75 {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len() + line.len() / 60);
    let mut budget = 75usize;
    let mut used = 0usize;
    for c in line.chars() {
        let width = c.len_utf8();
        if used + width > budget {
            out.push_str("\r\n ");
            budget = 74; // continuation lines lose one octet to the space
            used = 0;
        }
        out.push(c);
        used += width;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite<'a>(summary: &'a str, name: &'a str) -> IcsInvite<'a> {
        IcsInvite {
            uid: "booking-1@test.local",
            dtstamp: 1_784_559_600,
            start: 1_784_559_600,
            end: 1_784_561_400,
            summary,
            description: Some("Booked via the scheduling page.\nSee you there; bring snacks."),
            organizer_name: name,
            organizer_email: "alice@alice.local",
            attendee_name: "Bob",
            attendee_email: "bob@bob.local",
        }
    }

    #[test]
    fn renders_a_valid_request() {
        let ics = render(&invite("Meeting: Bob & Alice", "Alice"));
        assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ics.contains("METHOD:REQUEST\r\n"));
        assert!(ics.contains("DTSTART:20260720T150000Z\r\n"));
        assert!(ics.contains("DTEND:20260720T153000Z\r\n"));
        assert!(ics.contains("SUMMARY:Meeting: Bob & Alice\r\n"));
        assert!(ics.contains("\\nSee you there\\; bring snacks"));
        assert!(ics.contains("ORGANIZER;CN=Alice:mailto:alice@alice.local"));
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
        // Round-trips through the detector-side parser.
        let parsed = owney_ai::ics::parse_invite(&ics).expect("parses");
        assert_eq!(parsed["method"], "REQUEST");
        assert_eq!(parsed["startAt"], 1_784_559_600);
    }

    #[test]
    fn folds_long_multibyte_lines_on_char_boundaries() {
        let long = "café ".repeat(40); // 240 chars, 6 octets per repeat
        let ics = render(&invite(&long, "Alice"));
        for line in ics.split("\r\n") {
            assert!(line.len() <= 75, "line too long: {line:?}");
        }
        // Unfolding restores the original (modulo the escaping, none here).
        let unfolded = ics.replace("\r\n ", "");
        assert!(
            unfolded.contains(&format!("SUMMARY:{}", long.trim_end_matches(' ')))
                || unfolded.contains(&long)
        );
        assert!(std::str::from_utf8(ics.as_bytes()).is_ok());
    }

    #[test]
    fn quotes_params_with_reserved_chars() {
        let ics = render(&invite("x", "Smith, Alice"));
        assert!(ics.contains("ORGANIZER;CN=\"Smith, Alice\":mailto:"));
    }
}
