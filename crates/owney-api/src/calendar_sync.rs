//! Background sync of federated calendars (the subscriber side).
//!
//! Pulls sealed event pages from each accepted **inbound** federation over a
//! signed, capability-bearing request, decrypts and verifies them, and applies
//! them read-only into the local mirror calendar. Reconciliation runs on an
//! interval; the realtime push path (`fed_worker`) triggers an immediate pull.

use owney_storage::{CalendarFederation, Storage};
use std::sync::Arc;

use crate::fed_apply::{self, SyncPage};
use crate::fed_sig::FederationConfig;
use crate::federation;

/// Coordinates pulling of federated calendars.
#[derive(Debug)]
pub struct CalendarSyncCoordinator {
    storage: Arc<Storage>,
    public_url: String,
    config: FederationConfig,
}

impl CalendarSyncCoordinator {
    pub fn new(storage: Arc<Storage>, public_url: String, config: FederationConfig) -> Self {
        Self {
            storage,
            public_url,
            config,
        }
    }

    /// Pull and apply all pending changes for one inbound federation.
    pub async fn sync_federation(
        &self,
        federation: &CalendarFederation,
    ) -> Result<SyncStats, SyncError> {
        let capability = federation
            .capability_secret
            .as_deref()
            .ok_or(SyncError::Misconfigured("no capability secret"))?;
        let peer_domain = federation
            .peer_domain
            .as_deref()
            .ok_or(SyncError::Misconfigured("no peer domain"))?;

        let client = federation::build_client(&self.storage, &self.public_url, &self.config)
            .await
            .map_err(|e| SyncError::Crypto(e.to_string()))?;
        let server_secret =
            owney_pgp::server_cert(&self.storage, &crate::fed_sig::host_of(&self.public_url))
                .await
                .map_err(|e| SyncError::Crypto(e.to_string()))?;

        // Resume from the stored keyset cursor "since|after".
        let (mut since, mut after) = parse_cursor(federation.sync_token.as_deref());
        let mut stats = SyncStats::default();

        loop {
            let url = format!(
                "{}/.well-known/owney/calendar/sync/{}?since={}&after={}",
                federation.target_server_url,
                federation.id,
                since,
                urlencoding::encode(&after),
            );
            let resp = client
                .get_capable(&url, peer_domain, capability)
                .await
                .map_err(|e| SyncError::Network(e.to_string()))?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(SyncError::FederationNotFound);
            }
            if !resp.status().is_success() {
                return Err(SyncError::Remote(resp.status().to_string()));
            }
            let page: SyncPage = resp
                .json()
                .await
                .map_err(|e| SyncError::Network(e.to_string()))?;

            let applied = fed_apply::apply_page(&self.storage, &server_secret, federation, &page)
                .await
                .map_err(|e| SyncError::Apply(e.to_string()))?;
            stats.applied += applied;

            since = page.next_since;
            after = page.next_after.clone();
            if !page.has_more {
                break;
            }
        }

        // Persist the cursor for the next incremental pull.
        self.storage
            .update_federation_sync_token(&federation.id, Some(format!("{since}|{after}")))
            .await
            .map_err(|e| SyncError::Storage(e.to_string()))?;

        Ok(stats)
    }

    /// Pull all accepted inbound federations (reconciliation pass).
    pub async fn sync_all(&self) -> Result<SyncRunStats, SyncError> {
        let federations = self
            .storage
            .list_active_federations()
            .await
            .map_err(|e| SyncError::Storage(e.to_string()))?;

        let mut run = SyncRunStats::default();
        tracing::info!(
            "starting federation sync run for {} calendars",
            federations.len()
        );

        for federation in federations {
            run.total += 1;
            match self.sync_federation(&federation).await {
                Ok(stats) => {
                    tracing::info!(
                        federation_id = %federation.id,
                        applied = stats.applied,
                        "federation sync completed"
                    );
                    run.succeeded += 1;
                    run.applied += stats.applied;
                }
                Err(e) => {
                    tracing::warn!(
                        federation_id = %federation.id,
                        error = %e,
                        "federation sync failed"
                    );
                    run.failed += 1;
                    if let Err(err) = self.storage.mark_federation_error(&federation.id).await {
                        tracing::error!("failed to mark federation error: {err}");
                    }
                }
            }
        }

        tracing::info!(
            succeeded = run.succeeded,
            failed = run.failed,
            applied = run.applied,
            "federation sync run completed"
        );
        Ok(run)
    }

    /// Pull a single federation by id (used by the realtime push trigger).
    pub async fn sync_one(&self, federation_id: &str) -> Result<SyncStats, SyncError> {
        let federation = self
            .storage
            .get_federation(federation_id)
            .await
            .map_err(|e| SyncError::Storage(e.to_string()))?
            .ok_or(SyncError::FederationNotFound)?;
        if federation.direction.as_deref() != Some("inbound")
            || !matches!(federation.status.as_str(), "accepted" | "syncing")
        {
            return Err(SyncError::Misconfigured("not an active inbound federation"));
        }
        self.sync_federation(&federation).await
    }
}

/// Parse the stored "since|after" keyset cursor.
fn parse_cursor(token: Option<&str>) -> (i64, String) {
    match token.and_then(|t| t.split_once('|')) {
        Some((since, after)) => (since.parse().unwrap_or(0), after.to_string()),
        None => (0, String::new()),
    }
}

#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    pub applied: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SyncRunStats {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub applied: usize,
}

#[derive(Debug)]
pub enum SyncError {
    Network(String),
    Remote(String),
    Storage(String),
    Crypto(String),
    Apply(String),
    Misconfigured(&'static str),
    FederationNotFound,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Network(m) => write!(f, "network error: {m}"),
            SyncError::Remote(m) => write!(f, "remote error: {m}"),
            SyncError::Storage(m) => write!(f, "storage error: {m}"),
            SyncError::Crypto(m) => write!(f, "crypto error: {m}"),
            SyncError::Apply(m) => write!(f, "apply error: {m}"),
            SyncError::Misconfigured(m) => write!(f, "misconfigured: {m}"),
            SyncError::FederationNotFound => write!(f, "federation not found on remote"),
        }
    }
}

impl std::error::Error for SyncError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        assert_eq!(parse_cursor(None), (0, String::new()));
        assert_eq!(parse_cursor(Some("42|abc")), (42, "abc".to_string()));
        assert_eq!(parse_cursor(Some("garbage")), (0, String::new()));
    }

    #[test]
    fn sync_error_display() {
        assert_eq!(
            SyncError::Network("boom".into()).to_string(),
            "network error: boom"
        );
    }
}
