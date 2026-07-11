//! The on-arrival skills. Deterministic ones (screener, unsubscribe
//! detection) always run; model-backed ones (categorize, summarize) run when
//! a provider is configured. Every mutation records an undoable action.

use ms_core::{AccountId, EmailId};
use ms_storage::{EmailRow, Storage};
use serde_json::{Value, json};

use crate::AiError;
use crate::provider::{AiProvider, StructuredRequest};

/// Parsed once per message, shared by every skill.
#[derive(Debug)]
pub struct EmailContext {
    pub email_id: EmailId,
    pub row: EmailRow,
    pub body_text: String,
    pub list_unsubscribe: Option<String>,
    pub list_unsubscribe_post: bool,
}

impl EmailContext {
    pub async fn load(
        storage: &Storage,
        account_id: AccountId,
        email_id: EmailId,
    ) -> Result<Option<Self>, AiError> {
        let rows = storage.emails_by_ids(account_id, vec![email_id]).await?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let blob_id = row
            .blob_id
            .parse()
            .map_err(|_| AiError::Provider("bad blob id".into()))?;
        let raw = storage.get_blob(blob_id).await?;

        let mut body_text = String::new();
        let mut list_unsubscribe = None;
        let mut list_unsubscribe_post = false;
        if let Some(message) = mail_parser::MessageParser::default().parse(&raw) {
            body_text = message.body_text(0).unwrap_or_default().into_owned();
            // mail-parser models List-Unsubscribe's <target> list as addresses.
            list_unsubscribe = message
                .header("List-Unsubscribe")
                .and_then(|h| match h {
                    mail_parser::HeaderValue::Text(text) => Some(text.to_string()),
                    mail_parser::HeaderValue::Address(address) => Some(
                        address
                            .iter()
                            .filter_map(|a| a.address())
                            .map(|target| format!("<{target}>"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                    _ => None,
                })
                .filter(|value| !value.is_empty());
            list_unsubscribe_post = message
                .header("List-Unsubscribe-Post")
                .and_then(|h| h.as_text())
                .is_some_and(|v| v.to_lowercase().contains("one-click"));
        }

        Ok(Some(Self {
            email_id,
            row,
            body_text,
            list_unsubscribe,
            list_unsubscribe_post,
        }))
    }
}

/// HEY-style screener: a first-time sender's mail goes to the Screener
/// mailbox instead of the inbox. Deterministic — no model involved.
pub async fn screen(
    storage: &Storage,
    account_id: AccountId,
    ctx: &EmailContext,
) -> Result<bool, AiError> {
    let Some(from_addr) = &ctx.row.from_addr else {
        return Ok(false);
    };
    // The message being processed is already stored, so first contact == 1.
    if storage.sender_message_count(account_id, from_addr).await? > 1 {
        return Ok(false);
    }

    let Some(inbox_id) = storage.mailbox_id_by_role(account_id, "inbox").await? else {
        return Ok(false);
    };
    if !ctx.row.mailbox_ids.contains(&inbox_id) {
        return Ok(false); // not inbox mail (sent copy, draft, ...)
    }
    let Some(screener_id) = storage.mailbox_id_by_role(account_id, "screener").await? else {
        return Ok(false);
    };

    let screener: ms_core::MailboxId = screener_id
        .parse()
        .map_err(|_| AiError::Provider("bad mailbox id".into()))?;
    storage
        .update_email(account_id, ctx.email_id, None, Some(vec![screener]))
        .await?;
    storage
        .record_ai_action(
            account_id,
            Some(ctx.email_id),
            "screener",
            &format!("First-time sender {from_addr} routed to Screener"),
            Some(json!({ "mailboxIds": ctx.row.mailbox_ids }).to_string()),
        )
        .await?;
    Ok(true)
}

/// RFC 8058 / RFC 2369 unsubscribe affordance detection. Stores what a
/// client (or the unsubscribe agent, later) needs for one-click freedom.
pub async fn detect_unsubscribe(
    storage: &Storage,
    account_id: AccountId,
    ctx: &EmailContext,
) -> Result<bool, AiError> {
    let Some(header) = &ctx.list_unsubscribe else {
        return Ok(false);
    };

    let mut http_url = None;
    let mut mailto = None;
    for target in header.split(',') {
        let target = target.trim().trim_start_matches('<').trim_end_matches('>');
        if target.starts_with("https://") || target.starts_with("http://") {
            http_url = Some(target.to_owned());
        } else if let Some(address) = target.strip_prefix("mailto:") {
            mailto = Some(address.to_owned());
        }
    }
    if http_url.is_none() && mailto.is_none() {
        return Ok(false);
    }

    let content = json!({
        "http": http_url,
        "mailto": mailto,
        // RFC 8058: safe to POST without confirmation.
        "oneClick": ctx.list_unsubscribe_post && http_url.is_some(),
    });
    storage
        .insert_annotation(
            account_id,
            ctx.email_id,
            "unsubscribe",
            &content.to_string(),
        )
        .await?;
    Ok(true)
}

const CATEGORIES: [&str; 5] = [
    "personal",
    "transactional",
    "newsletter",
    "notification",
    "promotional",
];

/// Model-backed category keyword (`ai:<category>`), undoable.
pub async fn categorize(
    storage: &Storage,
    provider: &dyn AiProvider,
    account_id: AccountId,
    ctx: &EmailContext,
    max_body_chars: usize,
) -> Result<Option<String>, AiError> {
    let body: String = ctx.body_text.chars().take(max_body_chars).collect();
    let request = StructuredRequest {
        system: "You categorize a single email for a personal mail server. \
                 personal = written by a human to this user; transactional = receipts, \
                 confirmations, account notices; newsletter = periodic editorial content; \
                 notification = automated app/service updates; promotional = marketing."
            .into(),
        user: format!(
            "From: {}\nSubject: {}\n\n{}",
            ctx.row.from_addr.as_deref().unwrap_or("unknown"),
            ctx.row.subject.as_deref().unwrap_or(""),
            body,
        ),
        schema: json!({
            "type": "object",
            "properties": {
                "category": {"type": "string", "enum": CATEGORIES},
            },
            "required": ["category"],
        }),
        max_tokens: 64,
    };

    let answer = provider.structured(request).await?;
    let Some(category) = answer["category"].as_str() else {
        return Err(AiError::Provider(format!("no category in {answer}")));
    };
    if !CATEGORIES.contains(&category) {
        return Err(AiError::Provider(format!("invalid category {category}")));
    }

    let mut keywords = ctx.row.keywords.clone();
    keywords.push(format!("ai:{category}"));
    storage
        .update_email(account_id, ctx.email_id, Some(keywords), None)
        .await?;
    storage
        .record_ai_action(
            account_id,
            Some(ctx.email_id),
            "categorizer",
            &format!("Categorized as {category}"),
            Some(json!({ "keywords": ctx.row.keywords }).to_string()),
        )
        .await?;
    Ok(Some(category.to_owned()))
}

/// Model-backed summary annotation for long messages.
pub async fn summarize(
    storage: &Storage,
    provider: &dyn AiProvider,
    account_id: AccountId,
    ctx: &EmailContext,
    min_chars: usize,
    max_body_chars: usize,
) -> Result<bool, AiError> {
    if ctx.body_text.chars().count() < min_chars {
        return Ok(false);
    }
    let body: String = ctx.body_text.chars().take(max_body_chars).collect();
    let request = StructuredRequest {
        system: "Summarize this email in at most two sentences, plus any action items.".into(),
        user: format!(
            "Subject: {}\n\n{}",
            ctx.row.subject.as_deref().unwrap_or(""),
            body
        ),
        schema: json!({
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "actionItems": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary"],
        }),
        max_tokens: 300,
    };

    let answer: Value = provider.structured(request).await?;
    if answer["summary"].as_str().is_none() {
        return Err(AiError::Provider(format!("no summary in {answer}")));
    }
    storage
        .insert_annotation(account_id, ctx.email_id, "summary", &answer.to_string())
        .await?;
    storage
        .record_ai_action(
            account_id,
            Some(ctx.email_id),
            "summarizer",
            "Summarized message",
            None,
        )
        .await?;
    Ok(true)
}
