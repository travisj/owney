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
use std::sync::Arc;

use ms_events::EventBus;
use ms_storage::Storage;
use tokio::sync::Notify;

pub use dkim::DkimKeys;
pub use router::{AnyRouter, MxRouter, Relay, Router, StaticRouter};
pub use worker::spawn_worker;

/// Retry schedule in seconds after attempt N (RFC 5321-ish, ≤ ~48h total).
pub const BACKOFF: [i64; 9] = [60, 300, 1800, 7200, 14400, 14400, 28800, 43200, 61200];

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("io error on {0}")]
    Io(PathBuf, #[source] std::io::Error),

    #[error("dkim: {0}")]
    Dkim(String),

    #[error("dns: {0}")]
    Dns(String),

    #[error("storage: {0}")]
    Storage(#[from] ms_storage::StorageError),

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
        account_id: ms_core::AccountId,
        mail_from: &str,
        recipients: &[String],
        raw: Vec<u8>,
    ) -> Result<Vec<uuid::Uuid>, DeliveryError> {
        // PGP first (Autocrypt header on everything; encrypt when every
        // recipient has a key), then DKIM over the final bytes.
        let raw = ms_pgp::pipeline::outbound(&self.storage, account_id, mail_from, recipients, raw)
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

        let mut queued = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let item = self
                .storage
                .enqueue(account_id, ingested.blob_id, mail_from, recipient)
                .await?;
            self.events.publish(ms_events::Event::Delivery {
                account_id,
                submission_id: item.id,
                status: ms_events::DeliveryStatus::Queued,
            });
            queued.push(item.id);
        }
        self.wake.notify_one();
        Ok(queued)
    }
}

impl<R: Router> ms_core::Submitter for DeliveryService<R> {
    fn submit(
        &self,
        account_id: ms_core::AccountId,
        mail_from: String,
        recipients: Vec<String>,
        raw: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<uuid::Uuid>, String>> + Send + '_>> {
        Box::pin(async move {
            DeliveryService::submit(self, account_id, &mail_from, &recipients, raw)
                .await
                .map_err(|err| err.to_string())
        })
    }
}
