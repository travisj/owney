//! The AI layer (M5).
//!
//! Everything here follows three rules from the founding plan:
//! 1. Expensive AI runs *after* acceptance, off the event stream — never in
//!    the SMTP hot path.
//! 2. Every AI mutation goes through the same storage layer as humans and is
//!    recorded in `ai_actions` with an inverse patch — visible and undoable.
//! 3. Fail open: an AI error never loses or blocks mail; it just means less
//!    enrichment.

pub mod ics;
pub mod nl_search;
pub mod provider;
pub mod skills;
pub mod worker;

use owney_core::AccountId;
use owney_storage::Storage;
use uuid::Uuid;

pub use provider::{AiProvider, ClaudeProvider, MockProvider, OpenAiCompatProvider};

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("transport: {0}")]
    Transport(String),

    #[error("provider: {0}")]
    Provider(String),

    #[error("storage: {0}")]
    Storage(#[from] owney_storage::StorageError),
}

/// Undo one recorded action by applying its inverse patch.
pub async fn undo_action(
    storage: &Storage,
    account_id: AccountId,
    action_id: Uuid,
) -> Result<(), AiError> {
    let action = storage
        .ai_action(account_id, action_id)
        .await?
        .ok_or_else(|| AiError::Provider(format!("no action {action_id}")))?;
    if action.undone {
        return Ok(());
    }
    let Some(inverse) = &action.inverse_patch else {
        return Err(AiError::Provider("action is not undoable".into()));
    };
    let patch: serde_json::Value = serde_json::from_str(inverse)
        .map_err(|err| AiError::Provider(format!("bad inverse patch: {err}")))?;

    let email_id: owney_core::EmailId =
        action
            .email_id
            .as_deref()
            .and_then(|id| id.parse().ok())
            .ok_or_else(|| AiError::Provider("action has no email".into()))?;

    let keywords = patch["keywords"].as_array().map(|list| {
        list.iter()
            .filter_map(|k| k.as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    });
    let mailbox_ids = patch["mailboxIds"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|m| m.as_str().and_then(|s| s.parse().ok()))
                .collect::<Vec<owney_core::MailboxId>>()
        })
        .filter(|ids| !ids.is_empty());

    storage
        .update_email(account_id, email_id, keywords, mailbox_ids)
        .await?;
    storage.mark_action_undone(action_id).await?;
    Ok(())
}
