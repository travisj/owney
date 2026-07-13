//! Background sync of federated calendars.
//!
//! Polls remote servers for calendar changes and syncs events locally.
//! Uses sync tokens for incremental updates (polling-based, can upgrade to webhooks).

use std::sync::Arc;
use owney_storage::Storage;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Sync job for a federated calendar
#[derive(Debug, Clone)]
pub struct FederationSyncJob {
    pub federation_id: String,
    pub target_server_url: String,
    pub sync_token: Option<String>,
}

/// Calendar event from remote server (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteCalendarEvent {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub start: i64,
    pub end: i64,
    pub rrule: Option<String>,
}

/// Sync response from remote server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarSyncResponse {
    /// New or updated events
    pub events: Vec<RemoteCalendarEvent>,
    /// Event IDs to delete
    pub removed_event_ids: Vec<String>,
    /// Token for next incremental sync
    pub sync_token: Option<String>,
}

/// Calendar sync coordinator
pub struct CalendarSyncCoordinator {
    storage: Arc<Storage>,
}

impl CalendarSyncCoordinator {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// Sync a single federated calendar with remote server
    pub async fn sync_federation(&self, job: FederationSyncJob) -> Result<(), SyncError> {
        // Query remote server for changes since last sync
        let sync_response = self.fetch_remote_changes(&job).await?;

        // TODO: Apply events to local calendar
        // - Upsert events from remote
        // - Delete removed events
        // - Update sync token

        Ok(())
    }

    /// Fetch calendar changes from remote server
    async fn fetch_remote_changes(&self, job: &FederationSyncJob) -> Result<CalendarSyncResponse, SyncError> {
        let url = format!(
            "{}/calendar-sync?token={}",
            job.target_server_url,
            job.sync_token.as_deref().unwrap_or("")
        );

        let resp = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncError::RemoteError(resp.status().to_string()));
        }

        resp.json::<CalendarSyncResponse>()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))
    }

    /// List all federation sync jobs that need attention
    pub async fn list_sync_jobs(&self) -> Result<Vec<FederationSyncJob>, SyncError> {
        // TODO: Query database for all active federation records
        // and return jobs for those due for sync

        Ok(Vec::new()) // Placeholder
    }

    /// Run sync for all federated calendars (background task)
    pub async fn sync_all(&self) -> Result<(), SyncError> {
        let jobs = self.list_sync_jobs().await?;

        for job in jobs {
            if let Err(e) = self.sync_federation(job).await {
                tracing::warn!("sync error: {e:?}");
                // Continue with other calendars, don't fail
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum SyncError {
    NetworkError(String),
    RemoteError(String),
    StorageError(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NetworkError(msg) => write!(f, "network error: {msg}"),
            SyncError::RemoteError(msg) => write!(f, "remote error: {msg}"),
            SyncError::StorageError(msg) => write!(f, "storage error: {msg}"),
        }
    }
}

impl std::error::Error for SyncError {}

/// Webhook endpoint for receiving push notifications from remote servers
/// POST /.well-known/owney/calendar/sync-webhook
pub async fn receive_sync_webhook(
    body: Value,
    storage: Arc<Storage>,
) -> Result<Value, String> {
    // Format: { "federationId": "...", "updatedAt": 12345 }
    // Remote server pushes when calendar changes

    let federation_id = body["federationId"]
        .as_str()
        .ok_or("missing federationId")?
        .to_string();

    // Queue immediate sync for this federation
    // For now, just log it
    tracing::info!("received sync notification for federation {federation_id}");

    Ok(json!({
        "status": "queued",
        "federationId": federation_id
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_error_display() {
        let err = SyncError::NetworkError("connection refused".to_string());
        assert_eq!(err.to_string(), "network error: connection refused");
    }
}
