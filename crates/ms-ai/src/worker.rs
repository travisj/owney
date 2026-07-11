//! The enrichment worker: a durable cursor over the Email modseq stream.
//! At-least-once, resumable across restarts, woken by the event bus.

use std::sync::Arc;

use ms_core::{AccountId, DataType};
use ms_events::EventBus;
use ms_storage::Storage;

use crate::provider::AiProvider;
use crate::{AiError, skills};

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub screener: bool,
    pub categorizer: bool,
    pub summarizer: bool,
    pub unsubscribe: bool,
    /// Body prefix sent to the model.
    pub max_body_chars: usize,
    /// Minimum body length before a summary is worth it.
    pub summarize_min_chars: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            screener: true,
            categorizer: true,
            summarizer: true,
            unsubscribe: true,
            max_body_chars: 4_000,
            summarize_min_chars: 800,
        }
    }
}

/// One enrichment pass for one account. Returns how many messages were
/// processed. Callable directly (tests, CLI) or from the worker loop.
pub async fn process_new_mail(
    storage: &Storage,
    provider: Option<&dyn AiProvider>,
    account_id: AccountId,
    config: &AiConfig,
) -> Result<usize, AiError> {
    let cursor = storage.ai_cursor(account_id).await?;
    let changes = storage
        .changes_since(account_id, DataType::Email, cursor, 64)
        .await?;

    let mut processed = 0;
    for id in &changes.created {
        let Ok(email_id) = id.parse() else { continue };
        let Some(ctx) = skills::EmailContext::load(storage, account_id, email_id).await? else {
            continue;
        };

        // Skip our own sent copies and drafts.
        let sent = storage.mailbox_id_by_role(account_id, "sent").await?;
        let drafts = storage.mailbox_id_by_role(account_id, "drafts").await?;
        if ctx
            .row
            .mailbox_ids
            .iter()
            .any(|m| Some(m) == sent.as_ref() || Some(m) == drafts.as_ref())
        {
            continue;
        }

        // Deterministic skills always run; failures are logged, never fatal.
        if config.screener
            && let Err(err) = skills::screen(storage, account_id, &ctx).await
        {
            tracing::warn!(%err, email = %email_id, "screener failed");
        }
        if config.unsubscribe
            && let Err(err) = skills::detect_unsubscribe(storage, account_id, &ctx).await
        {
            tracing::warn!(%err, email = %email_id, "unsubscribe detection failed");
        }

        // Model-backed skills run when a provider exists; fail open.
        if let Some(provider) = provider {
            if config.categorizer
                && let Err(err) =
                    skills::categorize(storage, provider, account_id, &ctx, config.max_body_chars)
                        .await
            {
                tracing::warn!(%err, email = %email_id, "categorizer failed");
            }
            if config.summarizer
                && let Err(err) = skills::summarize(
                    storage,
                    provider,
                    account_id,
                    &ctx,
                    config.summarize_min_chars,
                    config.max_body_chars,
                )
                .await
            {
                tracing::warn!(%err, email = %email_id, "summarizer failed");
            }
        }
        processed += 1;
    }

    storage
        .set_ai_cursor(account_id, changes.new_state.0)
        .await?;
    if changes.has_more {
        // More than one batch pending; the loop will call again immediately.
        return Ok(processed + 1);
    }
    Ok(processed)
}

/// Spawn the enrichment loop: woken by StateChange events, with a slow tick
/// as backstop. Abort the handle to stop.
pub fn spawn_worker(
    storage: Arc<Storage>,
    events: EventBus,
    provider: Option<Arc<dyn AiProvider>>,
    config: AiConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut bus = events.subscribe();
        loop {
            let accounts = match storage.accounts().await {
                Ok(accounts) => accounts,
                Err(err) => {
                    tracing::error!(%err, "ai worker: account listing failed");
                    Vec::new()
                }
            };
            for account in accounts {
                match process_new_mail(&storage, provider.as_deref(), account.id, &config).await {
                    Ok(0) => {}
                    Ok(count) => {
                        tracing::info!(account = %account.email, count, "ai enrichment pass");
                    }
                    Err(err) => tracing::warn!(%err, "ai enrichment failed"),
                }
            }

            tokio::select! {
                event = bus.recv() => {
                    match event {
                        // Only email changes matter; drain quickly either way.
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        }
    })
}
