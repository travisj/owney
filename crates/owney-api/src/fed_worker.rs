//! Realtime federation push: fan out signed "calendar changed" notifications to
//! subscribed peers, backed by a durable outbox with retry/backoff. The peer
//! responds by pulling the delta over the authenticated serve path, so the
//! notification itself carries no secrets — only a federation id.
//!
//! The outbox makes delivery at-least-once; the periodic `SyncWorker` pull is
//! the reconciliation safety net for anything a notification misses.

use owney_core::CalendarId;
use owney_storage::Storage;
use std::sync::Arc;
use std::time::Duration;

use crate::fed_sig::FederationConfig;
use crate::federation;

/// Max delivery attempts before an outbox item is parked as `failed`.
const MAX_ATTEMPTS: i64 = 8;

/// Enqueue a change notification for every peer subscribed to `calendar_id`.
/// Call this whenever the calendar's events change; delivery happens
/// asynchronously via [`NotifyWorker`].
pub async fn notify_calendar_changed(
    storage: &Storage,
    calendar_id: CalendarId,
) -> Result<usize, String> {
    let peers = storage
        .outbound_federations_for_calendar(calendar_id)
        .await
        .map_err(|e| e.to_string())?;
    let mut n = 0;
    for (federation_id, peer_domain) in peers {
        let payload = serde_json::json!({ "federation_id": federation_id })
            .to_string()
            .into_bytes();
        storage
            .fed_enqueue(&federation_id, &peer_domain, payload)
            .await
            .map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

/// Drains the federation outbox, delivering signed notifications to peers.
#[derive(Debug)]
pub struct NotifyWorker {
    storage: Arc<Storage>,
    public_url: String,
    config: FederationConfig,
    interval: Duration,
    batch: usize,
}

impl NotifyWorker {
    pub fn new(storage: Arc<Storage>, public_url: String, config: FederationConfig) -> Self {
        Self {
            storage,
            public_url,
            config,
            interval: Duration::from_secs(2),
            batch: 32,
        }
    }

    /// Deliver one batch of due notifications. Returns how many were delivered.
    pub async fn drain_once(&self) -> Result<usize, String> {
        let items = self
            .storage
            .fed_due_items(self.batch)
            .await
            .map_err(|e| e.to_string())?;
        if items.is_empty() {
            return Ok(0);
        }

        let client = federation::build_client(&self.storage, &self.public_url, &self.config)
            .await
            .map_err(|e| e.to_string())?;

        let mut delivered = 0;
        for item in items {
            let peer = match self
                .storage
                .federation_peer(&item.peer_domain)
                .await
                .map_err(|e| e.to_string())?
            {
                Some(p) => p,
                None => {
                    self.storage
                        .fed_record_attempt(
                            &item.id,
                            false,
                            Some("peer not pinned".into()),
                            MAX_ATTEMPTS,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    continue;
                }
            };
            let url = format!("{}/.well-known/owney/calendar/notify", peer.server_url);
            let result = client
                .post_json(&url, &item.peer_domain, &item.payload)
                .await;
            let (ok, err) = match result {
                Ok(resp) if resp.status().is_success() => (true, None),
                Ok(resp) => (false, Some(format!("status {}", resp.status()))),
                Err(e) => (false, Some(e.to_string())),
            };
            if ok {
                delivered += 1;
            }
            self.storage
                .fed_record_attempt(&item.id, ok, err, MAX_ATTEMPTS)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(delivered)
    }

    /// Run the drain loop forever.
    pub async fn run(self) -> ! {
        // Recover any deliveries stuck mid-send from a previous crash.
        if let Err(e) = self.storage.fed_reset_stale_claims().await {
            tracing::error!("failed to reset stale federation outbox claims: {e}");
        }
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(e) = self.drain_once().await {
                tracing::error!("federation notify drain failed: {e}");
            }
        }
    }
}
