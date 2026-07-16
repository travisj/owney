//! Background worker for federated calendar synchronization.
//!
//! Runs periodically to poll remote servers and sync calendar changes.

use crate::calendar_sync::CalendarSyncCoordinator;
use crate::fed_sig::FederationConfig;
use owney_storage::Storage;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for background sync worker
#[derive(Debug, Clone)]
pub struct SyncWorkerConfig {
    /// Interval between sync runs (seconds)
    pub interval_secs: u64,
    /// Maximum backoff for failed federations (seconds)
    pub max_backoff_secs: u64,
}

impl Default for SyncWorkerConfig {
    fn default() -> Self {
        Self {
            interval_secs: 300,     // 5 minutes
            max_backoff_secs: 3600, // 1 hour
        }
    }
}

/// Background sync worker
#[derive(Debug)]
pub struct SyncWorker {
    storage: Arc<Storage>,
    public_url: String,
    federation: FederationConfig,
    config: SyncWorkerConfig,
}

impl SyncWorker {
    pub fn new(
        storage: Arc<Storage>,
        public_url: String,
        federation: FederationConfig,
        config: SyncWorkerConfig,
    ) -> Self {
        Self {
            storage,
            public_url,
            federation,
            config,
        }
    }

    /// Start the background sync worker
    /// Runs indefinitely, syncing all federations at configured interval
    pub async fn run(self) -> ! {
        let coordinator = CalendarSyncCoordinator::new(
            self.storage.clone(),
            self.public_url.clone(),
            self.federation.clone(),
        );
        let interval = Duration::from_secs(self.config.interval_secs);

        tracing::info!(
            interval_secs = self.config.interval_secs,
            "starting calendar federation sync worker"
        );

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

            match coordinator.sync_all().await {
                Ok(stats) => {
                    tracing::debug!(
                        total = stats.total,
                        succeeded = stats.succeeded,
                        failed = stats.failed,
                        applied = stats.applied,
                        "sync run completed"
                    );
                }
                Err(e) => {
                    tracing::error!("sync run failed: {}", e);
                }
            }
        }
    }

    /// Run sync once (for testing or manual triggers)
    pub async fn sync_once(&self) -> Result<(), String> {
        let coordinator = CalendarSyncCoordinator::new(
            self.storage.clone(),
            self.public_url.clone(),
            self.federation.clone(),
        );
        coordinator.sync_all().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default() {
        let config = SyncWorkerConfig::default();
        assert_eq!(config.interval_secs, 300);
        assert_eq!(config.max_backoff_secs, 3600);
    }

    #[test]
    fn config_custom() {
        let config = SyncWorkerConfig {
            interval_secs: 60,
            max_backoff_secs: 1800,
        };
        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.max_backoff_secs, 1800);
    }
}
