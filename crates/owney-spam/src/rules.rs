//! Heuristic spam detection rules (traditional SpamAssassin-style).

#[derive(Debug)]
pub struct RulesVerdict {
    pub score: f32,
    pub matched_rules: Vec<String>,
}

/// Check a message against heuristic rules.
pub fn check_message(raw: &[u8]) -> RulesVerdict {
    let mut score: f32 = 0.0;
    let mut matched_rules = Vec::new();

    let msg_str = String::from_utf8_lossy(raw);

    // Missing critical headers
    if !msg_str.contains("\nDate:") && !msg_str.contains("\r\nDate:") {
        score += 0.15;
        matched_rules.push("MISSING_DATE".to_string());
    }

    if !msg_str.contains("\nMessage-ID:") && !msg_str.contains("\r\nMessage-ID:") {
        score += 0.10;
        matched_rules.push("MISSING_MESSAGE_ID".to_string());
    }

    // Extract subject header
    if let Some(subj) = extract_header(&msg_str, "Subject") {
        // ALL CAPS subject (with some minimum length to avoid short words like "RE")
        if subj.len() > 10
            && subj
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(|c| c.is_uppercase())
        {
            score += 0.15;
            matched_rules.push("ALL_CAPS_SUBJECT".to_string());
        }

        // Excessive punctuation/exclamation marks
        let punct_count = subj.chars().filter(|c| matches!(c, '!' | '?')).count();
        if punct_count > 3 {
            score += 0.10;
            matched_rules.push("EXCESSIVE_PUNCTUATION".to_string());
        }
    }

    // Check for executable attachment extensions in Content-Disposition
    let executable_exts = [".exe", ".bat", ".scr", ".vbs", ".js", ".zip"];
    for ext in executable_exts {
        if msg_str
            .to_lowercase()
            .contains(&format!("filename=\"{}", &ext[1..]))
        {
            score += 0.20;
            matched_rules.push(format!("EXECUTABLE_ATTACHMENT{}", ext));
            break; // Only count once
        }
    }

    // Suspicious "Received" chain (very short chain suggests spoofing)
    let received_count =
        msg_str.matches("\nReceived:").count() + msg_str.matches("\r\nReceived:").count();
    if received_count == 0 {
        score += 0.10;
        matched_rules.push("NO_RECEIVED_HEADERS".to_string());
    }

    // Check for common phishing patterns in Subject/From
    if let Some(subject) = extract_header(&msg_str, "Subject")
        && contains_phishing_keyword(&subject)
    {
        score += 0.20;
        matched_rules.push("PHISHING_SUBJECT".to_string());
    }

    RulesVerdict {
        score: score.min(1.0),
        matched_rules,
    }
}

fn extract_header(msg: &str, header_name: &str) -> Option<String> {
    let needle_cr = format!("\r\n{}:", header_name);
    let needle_lf = format!("\n{}:", header_name);

    let start = msg
        .find(&needle_cr)
        .map(|i| i + needle_cr.len())
        .or_else(|| msg.find(&needle_lf).map(|i| i + needle_lf.len()))?;

    // Skip leading whitespace
    let start = msg[start..]
        .chars()
        .position(|c| !c.is_whitespace())
        .unwrap_or(0)
        + start;

    // Find end of header (next line that doesn't start with space/tab)
    let end = msg[start..]
        .find("\n")
        .map(|i| start + i)
        .unwrap_or(msg.len());

    Some(msg[start..end].trim().to_string())
}

fn contains_phishing_keyword(text: &str) -> bool {
    let phishing_patterns = [
        "verify account",
        "confirm password",
        "update payment",
        "click here",
        "urgent action",
        "limited time",
    ];

    let lower = text.to_lowercase();
    phishing_patterns.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_missing_date() {
        let msg = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody";
        let verdict = check_message(msg);
        assert!(verdict.matched_rules.iter().any(|r| r == "MISSING_DATE"));
    }

    #[test]
    fn detects_all_caps_subject() {
        let msg = b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: THIS IS SPAM!!!\r\n\r\nBody";
        let verdict = check_message(msg);
        assert!(
            verdict
                .matched_rules
                .iter()
                .any(|r| r == "ALL_CAPS_SUBJECT")
        );
    }
}
