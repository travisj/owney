//! Outbound mail.
//!
//! [`DeliveryService::submit`] is the single entry point every submission
//! surface (CLI now; JMAP EmailSubmission and MCP `send_email` later)
//! converges on: DKIM-sign, store the Sent copy through the same ingest path
//! as inbound mail (searchable, threaded, AI-visible), enqueue one row per
//! recipient, wake the worker.
//!
//! The worker owns retries: exponential backoff per the schedule below, a DSN
//! bounce into the sender's inbox when an address permanently fails, and
//! `DeliveryEvent`s on the bus at every transition.

pub mod dkim;
pub mod router;
mod worker;

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::future::Future;

use owney_events::EventBus;
use owney_storage::Storage;
use tokio::sync::Notify;

pub use dkim::DkimKeys;
pub use router::{AnyRouter, MxRouter, Relay, Router, StaticRouter};
pub use worker::spawn_worker;

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("refused: {0}")]
    Refused(String),
}

/// Firewall trait: hand a composed message to the outbound pipeline.
/// Implemented by ms-delivery; consumed by the JMAP/REST/MCP surfaces so they
/// never depend on delivery internals.
pub trait Submitter: Send + Sync + 'static {
    /// Sign, store the Sent copy, and enqueue for each recipient. Returns the
    /// queue ids.
    fn submit(
        &self,
        account_id: owney_core::AccountId,
        mail_from: String,
        recipients: Vec<String>,
        raw: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<uuid::Uuid>, SubmitError>> + Send + '_>>;

    /// Submit with chat_mode priority. Default implementation ignores chat_mode
    /// and calls submit(). Implementations should override for priority support.
    fn submit_with_priority(
        &self,
        account_id: owney_core::AccountId,
        mail_from: String,
        recipients: Vec<String>,
        raw: Vec<u8>,
        chat_mode: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<uuid::Uuid>, SubmitError>> + Send + '_>> {
        // Default: ignore chat_mode and call submit()
        let _ = chat_mode;
        self.submit(account_id, mail_from, recipients, raw)
    }
}

/// Retry schedule in seconds after attempt N (RFC 5321-ish, ≤ ~48h total).
pub const BACKOFF: [i64; 9] = [60, 300, 1800, 7200, 14400, 14400, 28800, 43200, 61200];

/// Chat mode backoff: expedited for real-time delivery (30s → 2m → 10m → 1h, ≤ ~8h total).
pub const CHAT_BACKOFF: [i64; 9] = [30, 120, 600, 3600, 3600, 3600, 3600, 3600, 3600];

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("io error on {0}")]
    Io(PathBuf, #[source] std::io::Error),

    #[error("dkim: {0}")]
    Dkim(String),

    #[error("dns: {0}")]
    Dns(String),

    #[error("storage: {0}")]
    Storage(#[from] owney_storage::StorageError),

    #[error("permanent failure: {0}")]
    Permanent(String),

    #[error("temporary failure: {0}")]
    Temporary(String),
}

#[derive(Debug, Clone)]
pub struct DeliveryParams {
    /// Our FQDN for EHLO and DSN headers.
    pub hostname: String,
    /// Poll interval for the queue when idle.
    pub poll_interval: std::time::Duration,
    /// Skip TLS certificate verification on outbound connections
    /// (tests/smarthost-on-localhost only — never for real MX delivery).
    pub allow_invalid_certs: bool,
}

/// Shared handle: submit messages and wake the worker.
pub struct DeliveryService<R: Router> {
    pub storage: Arc<Storage>,
    pub events: EventBus,
    pub dkim: DkimKeys,
    pub router: Arc<R>,
    pub params: DeliveryParams,
    pub wake: Arc<Notify>,
}

impl<R: Router> std::fmt::Debug for DeliveryService<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryService")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl<R: Router> DeliveryService<R> {
    /// Sign, store the Sent copy, and queue for every recipient.
    /// `raw` must already contain all headers (From/To/Subject/Date/Message-ID).
    pub async fn submit(
        &self,
        account_id: owney_core::AccountId,
        mail_from: &str,
        recipients: &[String],
        raw: Vec<u8>,
    ) -> Result<Vec<uuid::Uuid>, DeliveryError> {
        self.submit_with_priority(account_id, mail_from, recipients, raw, false)
            .await
    }

    pub async fn submit_with_priority(
        &self,
        account_id: owney_core::AccountId,
        mail_from: &str,
        recipients: &[String],
        raw: Vec<u8>,
        chat_mode: bool,
    ) -> Result<Vec<uuid::Uuid>, DeliveryError> {
        // PGP first (Autocrypt header on everything; encrypt when every
        // recipient has a key), then DKIM over the final bytes.
        let raw = owney_pgp::pipeline::outbound(&self.storage, account_id, mail_from, recipients, raw)
            .await
            .map_err(|err| DeliveryError::Temporary(format!("pgp: {err}")))?;

        // DKIM signature covers the message as sent.
        let mut signed = self.dkim.sign(&raw)?.into_bytes();
        signed.extend_from_slice(&raw);

        // Sent copy goes through the normal ingest path (threading, events).
        let ingested = self
            .storage
            .ingest_email(account_id, signed.clone(), "sent", None)
            .await?;

        let priority = if chat_mode { 1 } else { 0 };
        let mut queued = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let item = self
                .storage
                .enqueue_with_priority(account_id, ingested.blob_id, mail_from, recipient, priority)
                .await?;
            self.events.publish(owney_events::Event::Delivery {
                account_id,
                submission_id: item.id,
                status: owney_events::DeliveryStatus::Queued,
            });
            queued.push(item.id);
        }
        self.wake.notify_one();
        Ok(queued)
    }
}

impl<R: Router> Submitter for DeliveryService<R> {
    fn submit(
        &self,
        account_id: owney_core::AccountId,
        mail_from: String,
        recipients: Vec<String>,
        raw: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<uuid::Uuid>, SubmitError>> + Send + '_>> {
        Box::pin(async move {
            DeliveryService::submit(self, account_id, &mail_from, &recipients, raw)
                .await
                .map_err(|err| match err {
                    DeliveryError::Permanent(msg) => SubmitError::Refused(msg),
                    DeliveryError::Temporary(msg)
                    | DeliveryError::Dkim(msg)
                    | DeliveryError::Dns(msg) => SubmitError::Transport(msg),
                    DeliveryError::Storage(msg) => SubmitError::Transport(msg.to_string()),
                    DeliveryError::Io(path, _) => {
                        SubmitError::Transport(format!("io error on {}", path.display()))
                    }
                })
        })
    }

    fn submit_with_priority(
        &self,
        account_id: owney_core::AccountId,
        mail_from: String,
        recipients: Vec<String>,
        raw: Vec<u8>,
        chat_mode: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<uuid::Uuid>, SubmitError>> + Send + '_>> {
        Box::pin(async move {
            DeliveryService::submit_with_priority(self, account_id, &mail_from, &recipients, raw, chat_mode)
                .await
                .map_err(|err| match err {
                    DeliveryError::Permanent(msg) => SubmitError::Refused(msg),
                    DeliveryError::Temporary(msg)
                    | DeliveryError::Dkim(msg)
                    | DeliveryError::Dns(msg) => SubmitError::Transport(msg),
                    DeliveryError::Storage(msg) => SubmitError::Transport(msg.to_string()),
                    DeliveryError::Io(path, _) => {
                        SubmitError::Transport(format!("io error on {}", path.display()))
                    }
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct StubSubmitter;
    impl Submitter for StubSubmitter {
        fn submit(
            &self,
            _account_id: owney_core::AccountId,
            _mail_from: String,
            _recipients: Vec<String>,
            _raw: Vec<u8>,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<Vec<uuid::Uuid>, SubmitError>> + Send + '_>,
        > {
            Box::pin(async { Err(SubmitError::Refused("test stub".into())) })
        }
    }

    #[tokio::test]
    async fn stub_returns_refused_error() {
        let s = StubSubmitter;
        let err = s
            .submit(
                owney_core::AccountId::new(),
                "alice@example.com".into(),
                vec![],
                vec![],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SubmitError::Refused(_)));
    }
}
