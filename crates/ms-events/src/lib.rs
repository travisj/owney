//! The in-process event bus.
//!
//! A single `tokio::sync::broadcast` channel of typed events. Producers (the
//! storage layer, the delivery queue, AI workers) publish; consumers (JMAP
//! push, webhooks, AI enrichment, metrics) each hold their own receiver.
//!
//! Delivery is intentionally lossy under lag: a slow consumer misses events
//! rather than stalling the server. That is safe because push is only ever a
//! hint — clients recover the truth via `/changes` from their last state
//! token, and internal consumers re-scan from the database.

use std::sync::Arc;

use ms_core::{AccountId, DataType, EmailId, ModSeq};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Everything that can happen inside the server that someone else may care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// One or more synchronizable data types changed for an account.
    /// This is the event JMAP push and client realtime updates are built on.
    StateChange {
        account_id: AccountId,
        /// The new modseq for each type that changed in this mutation.
        changed: Vec<(DataType, ModSeq)>,
    },

    /// An outbound submission progressed through the delivery queue.
    Delivery {
        account_id: AccountId,
        submission_id: uuid::Uuid,
        status: DeliveryStatus,
    },

    /// An AI skill acted (or declined to act) on something.
    Ai {
        account_id: AccountId,
        skill: String,
        action_id: uuid::Uuid,
        summary: String,
    },

    /// Something security-relevant happened (key change for a known peer,
    /// repeated auth failures, DMARC report anomaly, ...).
    Security {
        account_id: Option<AccountId>,
        kind: SecurityEventKind,
        detail: String,
    },

    /// A health check completed (DNS, certificate, queue, database, ...).
    DoctorCheck(DoctorCheck),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Name of the check (e.g., "dns_drift", "cert_expiry", "queue_health")
    pub check: String,
    /// "ok", "warning", "error"
    pub status: String,
    /// Human-readable message
    pub message: String,
    /// Unix timestamp when check ran
    pub checked_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Queued,
    Delivered { recipient: String },
    TemporaryFailure { recipient: String, reply: String },
    PermanentFailure { recipient: String, reply: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventKind {
    PeerKeyChanged { email_id: EmailId },
    AuthFailure,
    Other,
}

/// Cloneable handle to the bus. Cheap to pass everywhere.
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Arc<Event>>,
}

impl EventBus {
    /// `capacity` is the per-receiver lag buffer; slow consumers beyond it
    /// observe `RecvError::Lagged` and must resynchronize from storage.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    /// Publish an event. It is not an error for no one to be listening.
    pub fn publish(&self, event: Event) {
        let receivers = self.tx.receiver_count();
        tracing::trace!(?event, receivers, "publish");
        let _ = self.tx.send(Arc::new(event));
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn events_reach_all_subscribers() {
        let bus = EventBus::new(8);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let account_id = AccountId::new();
        bus.publish(Event::StateChange {
            account_id,
            changed: vec![(DataType::Email, ModSeq(1))],
        });

        for rx in [&mut rx1, &mut rx2] {
            let event = rx.recv().await.expect("event delivered");
            match &*event {
                Event::StateChange {
                    account_id: got,
                    changed,
                } => {
                    assert_eq!(*got, account_id);
                    assert_eq!(changed, &[(DataType::Email, ModSeq(1))]);
                }
                other => panic!("unexpected event {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn publish_without_subscribers_is_fine() {
        let bus = EventBus::new(8);
        bus.publish(Event::Security {
            account_id: None,
            kind: SecurityEventKind::AuthFailure,
            detail: "test".into(),
        });
    }
}
