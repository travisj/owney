//! The queue worker: claim due items, attempt delivery, record outcomes,
//! bounce on permanent failure.

use std::sync::Arc;

use ms_events::{DeliveryStatus, Event, EventBus};
use ms_storage::{AttemptOutcome, QueueItem, Storage};
use tokio::sync::Notify;

use crate::{BACKOFF, DeliveryError, DeliveryParams, Relay, Router};

const BATCH: usize = 16;

/// Spawn the delivery loop. Aborting the returned handle stops it; in-flight
/// attempts either complete (row updated) or are retried after restart —
/// at-least-once, never lost.
pub fn spawn_worker<R: Router>(
    storage: Arc<Storage>,
    events: EventBus,
    router: Arc<R>,
    params: DeliveryParams,
    wake: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    // mail-send's TLS connector needs a process-level provider; harmless if
    // one is already installed.
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    tokio::spawn(async move {
        // Claims abandoned by a previous run go back to 'queued'.
        match storage.reset_stale_claims().await {
            Ok(0) => {}
            Ok(reset) => tracing::info!(reset, "recovered stale delivery claims"),
            Err(err) => tracing::error!(%err, "failed to reset stale claims"),
        }
        loop {
            let due = match storage.due_queue_items(BATCH).await {
                Ok(due) => due,
                Err(err) => {
                    tracing::error!(%err, "queue poll failed");
                    Vec::new()
                }
            };

            if due.is_empty() {
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(params.poll_interval) => {}
                }
                continue;
            }

            for item in due {
                process_item(&storage, &events, router.as_ref(), &params, item).await;
            }
        }
    })
}

async fn process_item<R: Router>(
    storage: &Storage,
    events: &EventBus,
    router: &R,
    params: &DeliveryParams,
    item: QueueItem,
) {
    let outcome = match attempt(storage, router, params, &item).await {
        Ok(()) => AttemptOutcome::Delivered,
        Err(DeliveryError::Permanent(error)) => AttemptOutcome::Failed { error },
        Err(err) => {
            let attempts = item.attempts as usize;
            match BACKOFF.get(attempts) {
                Some(delay) => AttemptOutcome::Retry {
                    error: err.to_string(),
                    next_attempt: unix_now() + delay,
                },
                // Schedule exhausted (~48h of trying).
                None => AttemptOutcome::Failed {
                    error: format!("retries exhausted: {err}"),
                },
            }
        }
    };

    if let Err(err) = storage.record_attempt(item.id, &outcome).await {
        tracing::error!(%err, id = %item.id, "failed to record delivery attempt");
        return;
    }

    let status = match &outcome {
        AttemptOutcome::Delivered => {
            tracing::info!(recipient = %item.recipient, "delivered");
            DeliveryStatus::Delivered {
                recipient: item.recipient.clone(),
            }
        }
        AttemptOutcome::Retry {
            error,
            next_attempt,
        } => {
            tracing::warn!(
                recipient = %item.recipient,
                attempt = item.attempts + 1,
                retry_at = next_attempt,
                %error,
                "delivery deferred"
            );
            DeliveryStatus::TemporaryFailure {
                recipient: item.recipient.clone(),
                reply: error.clone(),
            }
        }
        AttemptOutcome::Failed { error } => {
            tracing::warn!(recipient = %item.recipient, %error, "delivery failed permanently");
            bounce(storage, params, &item, error).await;
            DeliveryStatus::PermanentFailure {
                recipient: item.recipient.clone(),
                reply: error.clone(),
            }
        }
    };
    events.publish(Event::Delivery {
        account_id: item.account_id,
        submission_id: item.id,
        status,
    });
}

/// One delivery attempt: resolve relays, try each in order.
async fn attempt<R: Router>(
    storage: &Storage,
    router: &R,
    params: &DeliveryParams,
    item: &QueueItem,
) -> Result<(), DeliveryError> {
    let raw = storage.get_blob(item.blob_id).await?;
    let relays = router.resolve(&item.domain).await?;
    if relays.is_empty() {
        return Err(DeliveryError::Temporary(format!(
            "no relays for {}",
            item.domain
        )));
    }

    let mut last_error = None;
    for relay in relays {
        match deliver_to(params, &relay, item, &raw).await {
            Ok(()) => return Ok(()),
            Err(err @ DeliveryError::Permanent(_)) => return Err(err),
            Err(err) => {
                tracing::debug!(host = %relay.host, %err, "relay attempt failed");
                last_error = Some(err);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| DeliveryError::Temporary("no relay reachable".into())))
}

async fn deliver_to(
    params: &DeliveryParams,
    relay: &Relay,
    item: &QueueItem,
    raw: &[u8],
) -> Result<(), DeliveryError> {
    let mut builder = mail_send::SmtpClientBuilder::new(relay.host.clone(), relay.port)
        .map_err(DeliveryError::Dns)?
        .implicit_tls(false)
        .helo_host(params.hostname.clone())
        .timeout(std::time::Duration::from_secs(60));
    if params.allow_invalid_certs {
        builder = builder.allow_invalid_certs();
    }

    let message = || {
        mail_send::smtp::message::Message::empty()
            .from(item.mail_from.as_str())
            .to(item.recipient.as_str())
            .body(raw)
    };

    // Opportunistic TLS: prefer STARTTLS, fall back to plaintext when the
    // relay doesn't offer it (MTA-STS enforcement arrives with the policy
    // engine).
    match builder.connect().await {
        Ok(mut client) => {
            client.send(message()).await.map_err(map_send_error)?;
            let _ = client.quit().await;
            Ok(())
        }
        Err(mail_send::Error::UnexpectedReply(reply)) if reply.code() >= 500 => {
            Err(DeliveryError::Permanent(format!("rejected: {reply:?}")))
        }
        Err(tls_err) => {
            tracing::debug!(host = %relay.host, %tls_err, "TLS unavailable, retrying plaintext");
            let mut client = builder.connect_plain().await.map_err(map_send_error)?;
            client.send(message()).await.map_err(map_send_error)?;
            let _ = client.quit().await;
            Ok(())
        }
    }
}

/// 5xx replies are permanent; everything else (connect errors, 4xx,
/// timeouts, TLS trouble) is worth retrying.
fn map_send_error(err: mail_send::Error) -> DeliveryError {
    match &err {
        mail_send::Error::UnexpectedReply(reply) if reply.code() >= 500 => {
            DeliveryError::Permanent(err.to_string())
        }
        mail_send::Error::AuthenticationFailed(_) => DeliveryError::Permanent(err.to_string()),
        _ => DeliveryError::Temporary(err.to_string()),
    }
}

/// Deliver a DSN into the local sender's inbox. Never bounce outward for
/// inbound mail — that's backscatter; this is only for locally submitted
/// messages whose sender is one of our accounts.
async fn bounce(storage: &Storage, params: &DeliveryParams, item: &QueueItem, error: &str) {
    let dsn = format!(
        "From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
         To: <{sender}>\r\n\
         Subject: Undelivered Mail Returned to Sender\r\n\
         Date: {date}\r\n\
         Auto-Submitted: auto-replied\r\n\
         \r\n\
         Your message to <{recipient}> could not be delivered.\r\n\
         \r\n\
         Final reason: {error}\r\n\
         Attempts made: {attempts}\r\n",
        hostname = params.hostname,
        sender = item.mail_from,
        recipient = item.recipient,
        attempts = item.attempts + 1,
        date = ms_core::time::rfc2822_utc(unix_now()),
    );
    match storage
        .ingest_email(item.account_id, dsn.into_bytes(), "inbox", None)
        .await
    {
        Ok(_) => {}
        Err(err) => tracing::error!(%err, "failed to deliver bounce DSN locally"),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
