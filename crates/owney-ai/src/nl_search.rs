//! Natural language search: translate "unread from my boss" to JMAP filters.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::AiError;
use crate::provider::{AiProvider, StructuredRequest};

/// The structured output from NL→JMAP translation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JmapFilter {
    /// Mailboxes to search (inbox, sent, archive, etc.). Empty = all mailboxes.
    pub mailboxes: Vec<String>,
    /// Sender email address filter (exact or partial match).
    pub from: Option<String>,
    /// Subject filter (substring match).
    pub subject: Option<String>,
    /// Recipient filter.
    pub to: Option<String>,
    /// Timestamp: Unix seconds. Messages since this time.
    pub since: Option<i64>,
    /// Timestamp: Unix seconds. Messages before this time.
    pub before: Option<i64>,
    /// Flags to filter: $Seen (read), $Flagged, $Draft, etc.
    /// Example: {$Seen: false} means unread messages.
    pub flags: Option<std::collections::HashMap<String, bool>>,
    /// Free-text search in body.
    pub text: Option<String>,
    /// Thread ID to restrict to (single thread).
    pub thread_id: Option<String>,
}

impl Default for JmapFilter {
    fn default() -> Self {
        Self {
            mailboxes: vec![],
            from: None,
            subject: None,
            to: None,
            since: None,
            before: None,
            flags: None,
            text: None,
            thread_id: None,
        }
    }
}

/// Translate natural language query to JMAP filter using Claude.
pub async fn translate_to_filter(
    provider: &dyn AiProvider,
    query: &str,
) -> Result<JmapFilter, AiError> {
    let system_prompt = "You are an email search translator. Convert natural language queries into JMAP filter objects.\n\n\
        Examples:\n\
        - 'unread from alice' → {\"from\": \"alice\", \"flags\": {\"$Seen\": false}}\n\
        - 'important emails last week' → {\"flags\": {\"$Flagged\": true}, \"since\": <7-days-ago>}\n\
        - 'drafts' → {\"mailboxes\": [\"drafts\"], \"flags\": {\"$Draft\": true}}\n\
        - 'from boss before:2024' → {\"from\": \"boss\", \"before\": 1704067200}\n\n\
        Common mailboxes: inbox, sent, archive, drafts, junk, trash, screener.\n\
        Unix timestamps: use current time minus duration for 'last X' queries.\n\
        Flags: $Seen (read), $Flagged, $Draft, $Junk, $Trash, $HasAttachment.\n\
        Return valid JSON only, no explanations.";

    let request = StructuredRequest {
        system: system_prompt.to_string(),
        user: format!("Translate this email search to JMAP filter: \"{}\"", query),
        schema: json!({
            "type": "object",
            "properties": {
                "mailboxes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Mailbox roles to search"
                },
                "from": {"type": ["string", "null"], "description": "Sender filter"},
                "subject": {"type": ["string", "null"], "description": "Subject filter"},
                "to": {"type": ["string", "null"], "description": "Recipient filter"},
                "since": {"type": ["integer", "null"], "description": "Unix timestamp"},
                "before": {"type": ["integer", "null"], "description": "Unix timestamp"},
                "flags": {
                    "type": ["object", "null"],
                    "description": "Flag filters: $Seen, $Flagged, $Draft, etc."
                },
                "text": {"type": ["string", "null"], "description": "Body text search"},
                "thread_id": {"type": ["string", "null"], "description": "Single thread ID"}
            }
        }),
        max_tokens: 256,
    };

    let response = provider.structured(request).await?;
    serde_json::from_value::<JmapFilter>(response)
        .map_err(|e| AiError::Provider(format!("filter parse failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmap_filter_defaults() {
        let filter = JmapFilter::default();
        assert!(filter.mailboxes.is_empty());
        assert!(filter.from.is_none());
    }

    #[test]
    fn jmap_filter_serialization() {
        let mut filter = JmapFilter::default();
        filter.from = Some("alice@example.com".to_string());
        filter.flags = {
            let mut m = std::collections::HashMap::new();
            m.insert("$Seen".to_string(), false);
            Some(m)
        };

        let json = serde_json::to_string(&filter).expect("serialize");
        let restored: JmapFilter = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.from, Some("alice@example.com".to_string()));
    }
}
