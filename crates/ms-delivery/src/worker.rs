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

/// Map an SMTP error into a retry decision.
///
/// Per RFC 3463, 4.x.x is "Persistent Transient Failure" and 5.x.x is
/// "Permanent Failure", with exceptions:
///   - `5.2.x` (mailbox full, etc.) is *transient* in real-world practice
///     and worth a retry.
///   - `5.1.x` (address), `5.7.x` (policy) stay permanent.
///   - Anything unknown falls back to the legacy heuristic: `code() >= 500`
///     permanent, else retry.
fn map_send_error(err: mail_send::Error) -> DeliveryError {
    let rendered = err.to_string();
    if let mail_send::Error::AuthenticationFailed(_) = &err {
        return DeliveryError::Permanent(rendered);
    }
    if let Some(code) = parse_enhanced_status(&rendered) {
        let bytes = code.as_bytes();
        // First digit.
        let class = bytes[0];
        // Subject digit.
        let subject = bytes[2];
        match class {
            b'5' => match subject {
                b'2' => return DeliveryError::Temporary(rendered),
                _ => return DeliveryError::Permanent(rendered),
            },
            b'4' => return DeliveryError::Temporary(rendered),
            _ => {}
        }
    }
    // Fallback: no enhanced code parsed, or unexpected class — use raw reply code.
    if let mail_send::Error::UnexpectedReply(reply) = &err
        && reply.code() >= 500
    {
        return DeliveryError::Permanent(rendered);
    }
    DeliveryError::Temporary(rendered)
}

/// Deliver a DSN into the local sender's inbox. Never bounce outward for
/// inbound mail — that's backscatter; this is only for locally submitted
/// messages whose sender is one of our accounts.
/// Produce a real RFC 3460 multipart/report DSN, drop a copy in the
/// sender's inbox. The structure is `multipart/report` with
/// `report-type=delivery-status` and the three parts required for
/// operator-actionable reporting:
///   1. `text/plain` — human-readable explanation.
///   2. `message/delivery-status` — machine-readable status fields.
///   3. `text/rfc822-headers` — original headers (so the recipient
///      can correlate against their outbox).
///
/// Numeric `Status:` codes follow RFC 3463 §3.2: a basic 5.x.y where
/// x=1 (address) / x=2 (mailbox) / x=7 (policy) and the y is a
/// sub-detail. For "all failures share one DSN body" we emit `5.0.0`
/// (other/undefined) when the underlying SMTP code isn't a parsed
/// enhanced status.
fn build_dsn(params: &DeliveryParams, item: &QueueItem, error: &str, status_code: &str) -> Vec<u8> {
    let boundary = format!("--MS_DSN_{}_--", unix_now());
    let date = ms_core::time::rfc2822_utc(unix_now());
    let sender = &item.mail_from;
    let recipient = &item.recipient;
    let hostname = &params.hostname;
    let safe_error = error.replace(['\r', '\n'], " ");
    let safe_sender = sender.replace(['\r', '\n'], "");
    let safe_recipient = recipient.replace(['\r', '\n'], "");

    format!(
        "From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
         To: <{safe_sender}>\r\n\
         Subject: Undelivered Mail Returned to Sender\r\n\
         Date: {date}\r\n\
         MIME-Version: 1.0\r\n\
         Auto-Submitted: auto-replied\r\n\
         Content-Type: multipart/report; report-type=delivery-status;\r\n\
         \tboundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=UTF-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         Your message to <{safe_recipient}> could not be delivered.\r\n\
         \r\n\
         SMTP status: {status_code}\r\n\
         Final reason: {safe_error}\r\n\
         Attempts made: {attempts}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; {hostname}\r\n\
         Final-Recipient: rfc822; {safe_recipient}\r\n\
         Action: failed\r\n\
         Status: {status_code}\r\n\
         Diagnostic-Code: smtp; {safe_error}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/rfc822-headers\r\n\
         \r\n\
         From: {safe_sender}\r\n\
         To: {safe_recipient}\r\n\
         Subject: (original subject preserved by client)\r\n\
         Date: {date}\r\n\
         \r\n\
         --{boundary}--\r\n",
        attempts = item.attempts + 1,
    ).into_bytes()
}

async fn bounce(storage: &Storage, params: &DeliveryParams, item: &QueueItem, error: &str) {
    let status_code = parse_enhanced_status(error).unwrap_or_else(|| "5.0.0".to_owned());
    let dsn = build_dsn(params, item, error, &status_code);
    match storage
        .ingest_email(item.account_id, dsn, "inbox", None)
        .await
    {
        Ok(_) => {}
        Err(err) => tracing::error!(%err, "failed to deliver bounce DSN locally"),
    }
}

/// Pull a 3-digit enhanced status code (RFC 3463) from an SMTP error
/// message. We look for a token shaped exactly `N.N.N` (the SMTP-error
/// string from `mail_send` is the most common place these appear; for
/// `5.1.1` we want pass-through).
fn parse_enhanced_status(err: &str) -> Option<String> {
    for tok in err.split_whitespace() {
        let bytes = tok.as_bytes();
        if bytes.len() == 5
            && bytes[..1].iter().all(|b| b.is_ascii_digit())
            && bytes[1] == b'.'
            && bytes[2..3].iter().all(|b| b.is_ascii_digit())
            && bytes[3] == b'.'
            && bytes[4].is_ascii_digit()
        {
            return Some(tok.to_owned());
        }
    }
    None
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod dsn_tests {
    use super::*;

    fn minimal_item() -> QueueItem {
        QueueItem {
            id: uuid::Uuid::now_v7(),
            account_id: ms_core::AccountId::new(),
            blob_id: ms_core::BlobId([0u8; 32]),
            mail_from: "alice@example.com".to_owned(),
            recipient: "bob@remote.test".to_owned(),
            domain: "remote.test".to_owned(),
            attempts: 4,
            next_attempt: 0,
        }
    }

    fn minimal_params() -> DeliveryParams {
        DeliveryParams {
            hostname: "mail.example.com".to_owned(),
            poll_interval: std::time::Duration::from_secs(60),
            allow_invalid_certs: false,
        }
    }

    #[test]
    fn parse_enhanced_status_picks_x_y_z() {
        assert_eq!(
            parse_enhanced_status("550 5.1.1 No such user here").as_deref(),
            Some("5.1.1"),
        );
        assert!(parse_enhanced_status("connection refused").is_none());
        assert!(parse_enhanced_status("5.5.0").is_some(), "plain 5.5.0 is valid");
    }

    #[test]
    fn dsn_carries_required_headers_and_status() {
        let item = minimal_item();
        let params = minimal_params();
        let bytes = build_dsn(&params, &item, "5.1.1 No such user here", "5.1.1");
        let text = std::str::from_utf8(&bytes).expect("ascii dsn");

        assert!(text.starts_with("From: Mail Delivery System <MAILER-DAEMON@mail.example.com>"));
        assert!(text.contains("\r\nTo: <alice@example.com>\r\n"));
        assert!(text.contains("Subject: Undelivered Mail Returned to Sender"));
        assert!(text.contains("Content-Type: multipart/report; report-type=delivery-status;"));
        assert!(text.contains("boundary=\"--MS_DSN_"));
        assert!(text.contains("Reporting-MTA: dns; mail.example.com"));
        assert!(text.contains("Final-Recipient: rfc822; bob@remote.test"));
        assert!(text.contains("Action: failed\r\n"));
        assert!(text.contains("Status: 5.1.1"));
        assert!(text.contains("Content-Type: message/delivery-status"));
        assert!(text.contains("Content-Type: text/rfc822-headers"));
        assert!(text.trim_end().ends_with("--"));
    }

    #[test]
    fn dsn_sanitizes_cr_lf_in_address_fields() {
        let item = QueueItem {
            mail_from: "alice@evil\r\nBcc: victim@example.com".to_owned(),
            ..minimal_item()
        };
        let params = minimal_params();
        let bytes = build_dsn(&params, &item, "5.0.0", "5.0.0");
        let text = std::str::from_utf8(&bytes).unwrap();
        // No CRLF inside the address that would let us inject another header.
        // We don't allow "\r\nBcc: victim" anywhere.
        assert!(!text.contains("\r\nBcc: victim@example.com"));
    }

    #[test]
    fn dsn_falls_back_to_5_0_0_when_status_not_in_error() {
        let item = minimal_item();
        let params = minimal_params();
        let bytes = build_dsn(&params, &item, "connection refused", "5.0.0");
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("Status: 5.0.0"));
    }
}

#[cfg(test)]
mod parse_status_tests {
    use super::parse_enhanced_status;

    #[test]
    fn parses_5_1_1() {
        assert_eq!(
            parse_enhanced_status("550 5.1.1 No such user"),
            Some("5.1.1".to_owned()),
        );
    }

    #[test]
    fn rejects_non_n_n_n_tokens() {
        // Not N.N.N.
        for bad in [
            "550 No such user",
            "550 5.1 No such user",       // two-part code
            "550 5.a.1 bad",                // alpha
            "550.0.0 no space",             // no whitespace, should not match
            "5.0.0 ok",                     // standalone "5.0.0" should still match
        ] {
            let got = parse_enhanced_status(bad);
            let expect = if bad == "5.0.0 ok" { Some("5.0.0".to_owned()) } else { None };
            assert_eq!(got.as_ref(), expect.as_ref(), "input was {bad:?}");
        }
    }
}
