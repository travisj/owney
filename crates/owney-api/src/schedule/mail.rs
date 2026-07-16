//! Booking confirmation email: multipart/mixed with a text/plain body and a
//! text/calendar (METHOD:REQUEST) attachment, as complete RFC 5322 bytes fit
//! for `Submitter::submit` or direct `ingest_email`.

use owney_core::time::rfc2822_utc;

#[derive(Debug)]
pub struct Confirmation<'a> {
    pub host: &'a str,
    pub from_name: Option<&'a str>,
    pub from_email: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub text_body: &'a str,
    pub ics: &'a str,
}

pub fn compose(c: &Confirmation<'_>) -> Vec<u8> {
    let boundary = format!("owney-{}", uuid::Uuid::new_v4().simple());
    let message_id = format!("<{}@{}>", uuid::Uuid::new_v4().simple(), c.host);
    let from = match c.from_name {
        // Quoted display-name; strip quotes/CRLF to keep the header sane.
        Some(name) => format!(
            "\"{}\" <{}>",
            name.replace(['"', '\r', '\n'], ""),
            c.from_email
        ),
        None => format!("<{}>", c.from_email),
    };

    let mut out = String::new();
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: <{}>\r\n", c.to));
    out.push_str(&format!(
        "Subject: {}\r\n",
        c.subject.replace(['\r', '\n'], " ")
    ));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    out.push_str(&format!("Date: {}\r\n", rfc2822_utc(now)));
    out.push_str(&format!("Message-ID: {message_id}\r\n"));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!(
        "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
    ));
    out.push_str("\r\n");

    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    out.push_str(c.text_body);
    out.push_str("\r\n");

    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/calendar; charset=utf-8; method=REQUEST\r\n");
    out.push_str("Content-Disposition: attachment; filename=\"invite.ics\"\r\n\r\n");
    out.push_str(c.ics);
    out.push_str(&format!("--{boundary}--\r\n"));

    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_round_trips_through_mail_parser() {
        let ics = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
                   DTSTART:20260720T150000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let raw = compose(&Confirmation {
            host: "alice.local",
            from_name: Some("Alice"),
            from_email: "alice@alice.local",
            to: "bob@bob.local",
            subject: "Confirmed: Meeting with Alice",
            text_body: "You're booked for 2026-07-20 09:00 (America/Denver).",
            ics,
        });

        let message = mail_parser::MessageParser::default()
            .parse(&raw)
            .expect("parses");
        assert_eq!(
            message.subject().expect("subject"),
            "Confirmed: Meeting with Alice"
        );
        assert!(
            message
                .body_text(0)
                .expect("text part")
                .contains("You're booked")
        );

        use mail_parser::MimeHeaders;
        let calendar_part = message
            .parts
            .iter()
            .find(|part| {
                part.content_type().is_some_and(|ct| {
                    ct.ctype().eq_ignore_ascii_case("text")
                        && ct
                            .subtype()
                            .is_some_and(|s| s.eq_ignore_ascii_case("calendar"))
                })
            })
            .expect("calendar part present");
        match &calendar_part.body {
            mail_parser::PartType::Text(text) => assert!(text.contains("METHOD:REQUEST")),
            other => panic!("unexpected part body {other:?}"),
        }
    }
}
