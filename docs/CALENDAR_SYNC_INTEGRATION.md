# Calendar Federation Sync Worker Integration

Phase 2.5 - How to integrate the background sync worker into your application.

## Overview

The sync worker polls remote owney servers for calendar changes and syncs them locally. It runs continuously in a background task, respecting configured intervals.

## Quick Start

### 1. Import the Worker

```rust
use owney_api::background_worker::{SyncWorker, SyncWorkerConfig};
use owney_storage::Storage;
use std::sync::Arc;
```

### 2. Create Configuration

```rust
// Use defaults (5 minute interval, 1 hour max backoff)
let config = SyncWorkerConfig::default();

// Or customize:
let config = SyncWorkerConfig {
    interval_secs: 300,      // poll every 5 minutes
    max_backoff_secs: 3600,  // don't back off more than 1 hour
};
```

### 3. Spawn the Worker

In your main application startup:

```rust
#[tokio::main]
async fn main() {
    let storage = Arc::new(Storage::open("...").await.expect("open storage"));
    
    // Spawn sync worker in background
    let sync_worker = SyncWorker::new(storage.clone(), SyncWorkerConfig::default());
    tokio::spawn(async move {
        sync_worker.run().await  // runs forever
    });

    // Rest of your app initialization...
}
```

### 4. Optional: Run Once for Testing

```rust
let sync_worker = SyncWorker::new(storage, SyncWorkerConfig::default());
sync_worker.sync_once().await?;
```

## Configuration

### Via Environment Variables

```bash
# Polling interval (seconds)
export CALENDAR_SYNC_INTERVAL_SECS=300

# Max backoff for failed federations (seconds)
export CALENDAR_SYNC_MAX_BACKOFF_SECS=3600
```

### Via Config File

```toml
[calendar.sync]
interval_secs = 300
max_backoff_secs = 3600
```

### Programmatic

```rust
let config = SyncWorkerConfig {
    interval_secs: 600,      // 10 minutes
    max_backoff_secs: 7200,  // 2 hours
};
```

## How It Works

### Sync Cycle (every configured interval)

```
1. Load all active federations from database
   ↓
2. For each federation:
   a. Fetch sync token (or None for initial sync)
   b. Query remote server: GET /.well-known/owney/calendar/sync/{federation_id}?token=...
   c. Receive event delta (new, updated, deleted events)
   d. Upsert events to local calendar
   e. Delete removed events
   f. Update sync token for next cycle
   g. Log success/failure
   ↓
3. Wait for next interval
4. Repeat
```

### Error Handling

- **Network errors**: Logged, federation marked as error, continues with next
- **Remote errors** (404, 500, etc.): Logged, federation marked as error
- **Storage errors**: Logged, federation marked as error
- **Federation not found**: Logged (remote revoked access)

Failed federations are marked with `status='error'` and can be monitored:

```sql
SELECT * FROM calendar_federation WHERE status = 'error';
```

### Logging

Worker logs at three levels:

**INFO** (always):
```
[INFO] starting calendar federation sync worker (interval_secs=300)
[INFO] federation sync run completed (successful=5, failed=1, upserted=42, deleted=3)
```

**DEBUG** (detailed):
```
[DEBUG] fetching remote changes from: https://remote.example.com/.well-known/owney/calendar/sync/fed-123
[DEBUG] federation sync completed (federation_id=fed-123, upserted=5, deleted=2)
```

**WARN** (errors):
```
[WARN] federation sync failed (federation_id=fed-123, error="network error: connection timeout")
```

**ERROR** (critical):
```
[ERROR] failed to mark federation error: storage error
```

## Monitoring

### Metrics to Track

- **Sync latency**: How long does each sync cycle take?
- **Success rate**: What % of federations sync successfully?
- **Event throughput**: Events upserted/deleted per cycle
- **Backlog**: How many federations are in error state?

### Example Queries

```sql
-- Federations in error state
SELECT id, calendar_id, target_email, status 
FROM calendar_federation 
WHERE status = 'error'
ORDER BY last_sync_at;

-- Oldest unsync'd federation
SELECT id, calendar_id, target_email, last_sync_at 
FROM calendar_federation 
WHERE status IN ('accepted', 'syncing')
ORDER BY last_sync_at ASC NULLS FIRST 
LIMIT 1;

-- Most recently synced federations
SELECT id, calendar_id, target_email, last_sync_at 
FROM calendar_federation 
WHERE status = 'accepted'
ORDER BY last_sync_at DESC 
LIMIT 10;
```

## Testing

### Unit Test Example

```rust
#[tokio::test]
async fn test_sync_coordinator() {
    let storage = Arc::new(Storage::open_in_memory().await.unwrap());
    let coordinator = CalendarSyncCoordinator::new(storage);
    
    // Create test federation
    // Fetch remote changes
    // Verify events synced
}
```

### Integration Test Example

Start two local owney servers, create federation, verify sync.

```bash
# Terminal 1: Server A
cargo run -- --port 8001

# Terminal 2: Server B
cargo run -- --port 8002

# Create federation via API:
# Alice on Server A shares calendar with Bob on Server B
# Verify events appear on Server B after sync interval
```

### Manual Testing

```bash
# Trigger one sync cycle immediately
curl -X POST http://localhost:8000/admin/sync-now

# Get federation status
curl http://localhost:8000/admin/federations

# Mark federation for immediate retry
curl -X POST http://localhost:8000/admin/federations/{fed_id}/retry
```

## Performance Considerations

### Sync Time

- Small calendar (< 100 events): ~50ms
- Large calendar (1000+ events): ~200-500ms
- Multiple federations: run in parallel (configurable)
- Network latency: usually dominates

### Scaling

With default 5-minute interval:
- 10 federations: ~5 seconds per cycle (parallelized)
- 100 federations: ~50 seconds per cycle
- 1000 federations: ~5 minutes (approaching interval limit)

**Recommendation**: Parallelize federations if you have > 50

### Resource Usage

- Memory: ~1MB per 100 federations
- CPU: Low (<5% per sync cycle)
- Network: ~1KB per event (varies by size)
- Storage I/O: Minimal (only changed events)

## Troubleshooting

### Sync Not Running

1. Check worker is spawned in main
2. Check logs for errors
3. Verify storage is accessible
4. Check network connectivity to remote servers

### Events Not Syncing

1. Check federation status: `SELECT status FROM calendar_federation WHERE id = '...'`
2. If error: `SELECT * FROM calendar_federation WHERE id = '...'` to see error
3. Check remote server is accessible: `curl https://remote.example.com/.well-known/owney/server`
4. Verify sync token: `SELECT sync_token FROM calendar_federation WHERE id = '...'`
5. Check event sync endpoint: manually call sync endpoint with curl

### High Latency

1. Check network latency to remote servers
2. Reduce calendar size (archive old events)
3. Increase sync interval if acceptable
4. Implement partial sync (Phase 5)

### Memory Leaks

1. Monitor federation count over time
2. Check for stuck sync tasks
3. Verify no circular references in event upsert

## Future Enhancements

- **Webhook push** (Phase 4): Real-time sync via webhooks
- **Partial sync** (Phase 5): Only sync events in date range
- **Batching** (Phase 5): Sync multiple federations in parallel
- **Compression** (Phase 5): Gzip event responses
- **Selective sync** (Phase 5): User-specified sync frequency per federation

## API Reference

### CalendarSyncCoordinator

```rust
// Main coordinator
pub struct CalendarSyncCoordinator {
    storage: Arc<Storage>,
}

impl CalendarSyncCoordinator {
    pub fn new(storage: Arc<Storage>) -> Self
    
    // Sync single federation
    pub async fn sync_federation(
        &self, 
        job: FederationSyncJob
    ) -> Result<SyncStats, SyncError>
    
    // Sync all active federations
    pub async fn sync_all(&self) -> Result<SyncRunStats, SyncError>
    
    // Get list of jobs to sync
    pub async fn list_sync_jobs(&self) -> Result<Vec<FederationSyncJob>, SyncError>
}
```

### SyncWorker

```rust
pub struct SyncWorker {
    storage: Arc<Storage>,
    config: SyncWorkerConfig,
}

impl SyncWorker {
    pub fn new(storage: Arc<Storage>, config: SyncWorkerConfig) -> Self
    
    // Run forever (background task)
    pub async fn run(self) -> !
    
    // Run once (for testing)
    pub async fn sync_once(&self) -> Result<(), String>
}
```

### Types

```rust
pub struct SyncWorkerConfig {
    pub interval_secs: u64,      // Poll interval
    pub max_backoff_secs: u64,   // Max backoff
}

pub struct SyncStats {
    pub upserted: usize,
    pub deleted: usize,
}

pub struct SyncRunStats {
    pub total_federations: usize,
    pub successful_syncs: usize,
    pub failed_syncs: usize,
    pub total_upserted: usize,
    pub total_deleted: usize,
}

pub enum SyncError {
    NetworkError(String),
    RemoteError(String),
    StorageError(String),
    FederationNotFound,
}
```

## Example: Complete Integration

```rust
use owney_api::background_worker::{SyncWorker, SyncWorkerConfig};
use owney_storage::Storage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Open storage
    let storage = Arc::new(Storage::open("/var/lib/owney/calendar.db").await?);

    // Create sync worker with custom config
    let sync_config = SyncWorkerConfig {
        interval_secs: 300,      // 5 minutes
        max_backoff_secs: 3600,  // 1 hour
    };

    let sync_worker = SyncWorker::new(storage.clone(), sync_config);

    // Spawn in background
    tokio::spawn(async move {
        sync_worker.run().await
    });

    // Start your app server
    // ...

    Ok(())
}
```

That's it! The sync worker will now run continuously, polling remote servers every 5 minutes.
