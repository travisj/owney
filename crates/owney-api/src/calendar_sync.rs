//! Background sync of federated calendars.
//!
//! Polls remote servers for calendar changes and syncs events locally.
//! Uses sync tokens for incremental updates (polling-based, can upgrade to webhooks).

use owney_core::{CalendarId, EventId};
use owney_storage::Storage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Sync job for a federated calendar
#[derive(Debug, Clone)]
pub struct FederationSyncJob {
    pub federation_id: String,
    pub calendar_id: CalendarId,
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
    #[serde(default)]
    pub removed: bool,
}

/// Sync response from remote server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarSyncResponse {
    /// New or updated events
    pub events: Vec<RemoteCalendarEvent>,
    /// Event IDs to delete
    #[serde(default)]
    pub removed_event_ids: Vec<String>,
    /// Token for next incremental sync
    pub sync_token: Option<String>,
    /// Whether there are more changes to fetch
    #[serde(default)]
    pub has_more_changes: bool,
}

/// Calendar sync coordinator - manages background polling of federated calendars
#[derive(Debug)]
pub struct CalendarSyncCoordinator {
    storage: Arc<Storage>,
}

impl CalendarSyncCoordinator {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// Sync a single federated calendar with remote server
    pub async fn sync_federation(&self, job: FederationSyncJob) -> Result<SyncStats, SyncError> {
        // Query remote server for changes since last sync
        let sync_response = self.fetch_remote_changes(&job).await?;

        let mut stats = SyncStats::default();

        // Upsert events from remote
        for event in sync_response.events {
            if event.removed {
                // Delete event if marked removed
                let event_id = event
                    .id
                    .parse::<EventId>()
                    .map_err(|_| SyncError::StorageError("invalid event id".into()))?;
                self.storage
                    .delete_calendar_event(event_id)
                    .await
                    .map_err(|e| SyncError::StorageError(e.to_string()))?;
                stats.deleted += 1;
            } else {
                // Upsert event
                self.upsert_remote_event(&job.calendar_id, event).await?;
                stats.upserted += 1;
            }
        }

        // Delete removed events (by ID list)
        for event_id_str in sync_response.removed_event_ids {
            let event_id = event_id_str
                .parse::<EventId>()
                .map_err(|_| SyncError::StorageError("invalid event id".into()))?;
            self.storage
                .delete_calendar_event(event_id)
                .await
                .map_err(|e| SyncError::StorageError(e.to_string()))?;
            stats.deleted += 1;
        }

        // Update sync token and timestamp
        self.storage
            .update_federation_sync_token(&job.federation_id, sync_response.sync_token)
            .await
            .map_err(|e| SyncError::StorageError(e.to_string()))?;

        Ok(stats)
    }

    /// Upsert a remote event into local calendar
    async fn upsert_remote_event(
        &self,
        calendar_id: &CalendarId,
        event: RemoteCalendarEvent,
    ) -> Result<(), SyncError> {
        // Check if event exists
        let event_id = event
            .id
            .parse::<EventId>()
            .map_err(|_| SyncError::StorageError("invalid event id".into()))?;

        match self.storage.get_calendar_event(event_id).await {
            Ok(Some(_existing)) => {
                // Update existing event
                self.storage
                    .update_calendar_event(
                        event_id,
                        Some(event.title),
                        event.description,
                        Some(event.start),
                        Some(event.end),
                        event.rrule,
                    )
                    .await
                    .map_err(|e| SyncError::StorageError(e.to_string()))?;
            }
            Ok(None) => {
                // Create new event
                self.storage
                    .create_calendar_event(
                        *calendar_id,
                        event.title,
                        event.description,
                        event.start,
                        event.end,
                        event.rrule,
                    )
                    .await
                    .map_err(|e| SyncError::StorageError(e.to_string()))?;
            }
            Err(e) => return Err(SyncError::StorageError(e.to_string())),
        }

        Ok(())
    }

    /// Fetch calendar changes from remote server
    async fn fetch_remote_changes(
        &self,
        job: &FederationSyncJob,
    ) -> Result<CalendarSyncResponse, SyncError> {
        let mut url = format!(
            "{0}/.well-known/owney/calendar/sync/{1}",
            job.target_server_url, job.federation_id
        );

        if let Some(token) = &job.sync_token {
            url.push('?');
            url.push_str(&format!("token={}", urlencoding::encode(token)));
        }

        tracing::debug!("fetching remote changes from: {}", url);

        let resp = reqwest::Client::new()
            .get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(SyncError::FederationNotFound);
            }
            return Err(SyncError::RemoteError(resp.status().to_string()));
        }

        resp.json::<CalendarSyncResponse>()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))
    }

    /// List all federation sync jobs that need attention
    pub async fn list_sync_jobs(&self) -> Result<Vec<FederationSyncJob>, SyncError> {
        let federations = self
            .storage
            .list_active_federations()
            .await
            .map_err(|e| SyncError::StorageError(e.to_string()))?;

        let jobs = federations
            .into_iter()
            .map(|f| FederationSyncJob {
                federation_id: f.id,
                calendar_id: f.calendar_id,
                target_server_url: f.target_server_url,
                sync_token: f.sync_token,
            })
            .collect();

        Ok(jobs)
    }

    /// Run sync for all federated calendars (background task)
    pub async fn sync_all(&self) -> Result<SyncRunStats, SyncError> {
        let jobs = self.list_sync_jobs().await?;
        let mut run_stats = SyncRunStats::default();

        tracing::info!("starting federation sync run for {} calendars", jobs.len());

        for job in jobs {
            run_stats.total_federations += 1;

            match self.sync_federation(job.clone()).await {
                Ok(stats) => {
                    tracing::info!(
                        federation_id = %job.federation_id,
                        upserted = stats.upserted,
                        deleted = stats.deleted,
                        "federation sync completed"
                    );
                    run_stats.successful_syncs += 1;
                    run_stats.total_upserted += stats.upserted;
                    run_stats.total_deleted += stats.deleted;
                }
                Err(e) => {
                    tracing::warn!(
                        federation_id = %job.federation_id,
                        error = %e,
                        "federation sync failed"
                    );
                    run_stats.failed_syncs += 1;

                    // Mark federation as error
                    if let Err(err) = self.storage.mark_federation_error(&job.federation_id).await {
                        tracing::error!("failed to mark federation error: {}", err);
                    }
                }
            }
        }

        tracing::info!(
            successful = run_stats.successful_syncs,
            failed = run_stats.failed_syncs,
            upserted = run_stats.total_upserted,
            deleted = run_stats.total_deleted,
            "federation sync run completed"
        );

        Ok(run_stats)
    }
}

/// Statistics from a single federation sync
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    pub upserted: usize,
    pub deleted: usize,
}

/// Statistics from a full sync run
#[derive(Debug, Clone, Default)]
pub struct SyncRunStats {
    pub total_federations: usize,
    pub successful_syncs: usize,
    pub failed_syncs: usize,
    pub total_upserted: usize,
    pub total_deleted: usize,
}

#[derive(Debug)]
pub enum SyncError {
    NetworkError(String),
    RemoteError(String),
    StorageError(String),
    FederationNotFound,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NetworkError(msg) => write!(f, "network error: {msg}"),
            SyncError::RemoteError(msg) => write!(f, "remote error: {msg}"),
            SyncError::StorageError(msg) => write!(f, "storage error: {msg}"),
            SyncError::FederationNotFound => write!(f, "federation not found on remote"),
        }
    }
}

impl std::error::Error for SyncError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_error_display() {
        let err = SyncError::NetworkError("connection refused".to_string());
        assert_eq!(err.to_string(), "network error: connection refused");
    }

    #[test]
    fn sync_stats_default() {
        let stats = SyncStats::default();
        assert_eq!(stats.upserted, 0);
        assert_eq!(stats.deleted, 0);
    }
}
