# Claude.md - Mailserver Project Guide

**Project**: Owney Mailserver - Full-featured email & collaboration platform  
**Status**: Active Development (M11: Calendar Federation)  
**Last Updated**: 2026-07-13

## Quick Start

### For Existing Context
- Read this file top to bottom
- Check `docs/PLAN.md` for overall roadmap
- Check `docs/CALENDAR_FEDERATION.md` for calendar federation architecture
- All major features documented in `docs/` directory

### For New Context
1. **Start here**: This file (CLAUDE.md)
2. **Then**: `docs/PLAN.md` - overall project roadmap
3. **Then**: Specific feature docs as needed (see Feature Docs section)
4. **Finally**: Code in `crates/` - organized by feature

### Quick Commands

```bash
# Build
cargo build --release

# Run tests
cargo test --lib

# Format code
cargo fmt

# Lint
cargo clippy --all --all-targets

# Check everything
cargo check && cargo test && cargo clippy && cargo fmt --check

# Local two-instance testing lab (no DNS/TLS needed) — docs/LOCAL_TESTING.md
scripts/lab.sh up
```

---

## Project Overview

### Mission
Build a modern, open-source email and collaboration server that respects user privacy while providing rich features (email, calendars, contacts, chat, AI assistance).

### Core Principles
- **User Privacy First**: Encrypted storage, no tracking, user controls
- **Standards-Based**: JMAP (RFC 8621), IMAP, SMTP, CalDAV (planned)
- **Extensible**: Modular crate architecture, clear APIs
- **Production-Ready**: Comprehensive error handling, monitoring, testing
- **Federation**: Connect across server instances seamlessly

### Current Phase (M11)
Calendar Federation - Multi-user sharing with cross-server support

### Key Stats
- **Crates**: 20+ modular Rust crates
- **LOC**: ~20,000+ (core)
- **Storage**: SQLite + blob store
- **API**: JMAP (primarily) + REST endpoints
- **Auth**: Bearer tokens + per-app tokens

---

## Architecture Overview

### High-Level Structure

```
┌─────────────────────────────────────────────────────────────┐
│                     HTTP Layer (axum)                        │
│  JMAP (/jmap/api) │ Push (/jmap/eventsource, /jmap/ws)      │
│  WKD (/well-known/openpgpkey) │ Federation (/well-known/*)   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   JMAP Dispatcher Core                       │
│  jmap-core: Method registration, dispatcher, auth           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              Data Method Handlers (Feature Crates)          │
│  owney-jmap-mail: Email/Mailbox/Thread/Chat                 │
│  owney-jmap-calendar: Calendar/CalendarEvent/Invitations    │
│  (Future: owney-jmap-contacts, owney-jmap-tasks, etc.)      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   Storage Layer (SQLite)                     │
│  Unified schema: accounts, emails, mailboxes, calendars      │
│  Encryption: PGP keys, passwords, sensitive data            │
│  Blob store: Email bodies, attachments, files               │
└─────────────────────────────────────────────────────────────┘
```

### Modular Crates

**Core Infrastructure**:
- `jmap-core` - JMAP protocol implementation
- `owney-core` - Type definitions (AccountId, EmailId, etc.)
- `owney-storage` - SQLite + blob store (persistence)
- `owney-events` - In-process event bus
- `owney-api` - HTTP transport layer

**Features**:
- `owney-jmap-mail` - Email, mailboxes, threads, chat
- `owney-jmap-calendar` - Calendars, events, sharing, federation
- `owney-pgp` - PGP key management, encryption
- `owney-spam` - Spam detection & filtering
- `owney-ai` - AI-powered features (summarization, search, etc.)

**Operations**:
- `owney-authn` - Authentication & authorization
- `owney-delivery` - Outbound email submission
- `owney-smtp-in` - Inbound SMTP server
- `owney-imap` - IMAP server (optional)
- `owney-backup` - Full backups to S3
- `owney-doctor` - Health checks & diagnostics

**Utilities**:
- `owney-mcp` - MCP (Model Context Protocol) - AI integration
- `owney-update` - Auto-update mechanism
- `owney-setup` - Deployment configuration

---

## Feature Documentation

### Email (M0-M3) ✅
- RFC 8621 Email, Mailbox, Thread methods
- Keywords, mailbox moves, message state
- Full-text search with SQLite FTS5
- Spam filtering integration
- PGP encryption support

**Files**: `crates/owney-jmap-mail/src/lib.rs`  
**Docs**: `docs/PLAN.md` (M0-M3 sections)

### Backup & Recovery (M4-M5) ✅
- S3 backup of full logical snapshots
- SQL dump + encrypted blob tarball
- Point-in-time recovery
- Automated backup scheduling

**Files**: `crates/owney-backup/src/lib.rs`  
**Docs**: `docs/PLAN.md` (M4-M5 sections)

### WebSocket Events (M10) ✅
- Real-time event broadcasting
- Per-account isolation
- StateChange, Delivery, AI, Security, DoctorCheck events
- Fire-and-forget, lossy by design

**Files**: `crates/owney-events/src/ws_events.rs`  
**Docs**: None yet (add if expanding)

### Calendar Federation (M11) 🚀 **CURRENT**
- Multi-calendar support per user
- Same-server sharing (read-only + delegation)
- Cross-server federation with email discovery
- Polling-based sync with incremental tokens
- Granular permission model

**Files**:
- `crates/owney-storage/src/calendar_sharing.rs` - Sharing model & ops
- `crates/owney-api/src/federation.rs` - Server discovery
- `crates/owney-api/src/calendar_sync.rs` - Sync coordinator
- `crates/owney-api/src/background_worker.rs` - Polling worker
- `crates/owney-api/src/wellknown.rs` - Well-known endpoints
- `crates/owney-jmap-mail/src/calendar_methods.rs` - JMAP methods

**Docs**:
- `docs/CALENDAR_FEDERATION.md` - Architecture & design
- `docs/CALENDAR_SYNC_PROTOCOL.md` - Polling protocol spec
- `docs/CALENDAR_FEDERATION_ROADMAP.md` - Phases 1-5 planning
- `docs/CALENDAR_IMPLEMENTATION_SUMMARY.md` - What's implemented
- `docs/CALENDAR_SYNC_INTEGRATION.md` - How to integrate the worker
- `docs/CALENDAR_PHASE_2_5_SUMMARY.md` - Background worker details

### Server-Added Email Attributes ✅
- Flexible per-email structured data attached by server-side detectors
- One attribute per (email, kind), upsert; client dismissal via JMAP
- Kinds: `unsubscribe`, `calendarInvite`, `summary` (`needsAttention` reserved)
- Writes bump the Email modseq + publish StateChange (visible to /changes + push)
- Read via `Email/get` `serverAttributes`; dismiss via `EmailAttribute/dismiss`
  under `urn:owney:params:jmap:attributes`

**Files**:
- `crates/owney-storage/src/attributes.rs` - Storage (set/list/dismiss)
- `crates/owney-jmap-mail/src/attribute_methods.rs` - JMAP dismiss method
- `crates/owney-ai/src/ics.rs` - Minimal RFC 5545 VEVENT extraction
- `crates/owney-ai/src/skills.rs` - Detectors (unsubscribe, calendar invite, summary)

**Docs**: `docs/SERVER_ATTRIBUTES.md`

### Scheduling Pages (Calendly-style booking) ✅
- Public `GET /schedule/{slug}` booking page, no auth; slots + book JSON APIs
- Availability: versioned JSON (weekly windows, date overrides, buffers,
  notice, day quota) in the page's IANA timezone; DST handled via chrono-tz
- Atomic `book_slot` (busy check across all owner calendars + quota + insert
  in one writer-thread transaction) → concurrent double-book gets 409
- Confirmations: visitor via outbound queue, owner via direct ingest; both
  carry a generated `text/calendar` METHOD:REQUEST invite
- Owner surfaces: `SchedulingPage/get|set`, `SchedulingBooking/get` under
  `urn:owney:params:jmap:scheduling`; `admin create-scheduling-page`

**Files**:
- `crates/owney-storage/src/scheduling.rs` - Model, validation, book_slot
- `crates/owney-api/src/schedule/` - Routes, slots, ICS, MIME, rate limit
- `crates/owney-jmap-mail/src/scheduling_methods.rs` - JMAP methods

**Docs**: `docs/SCHEDULING.md`

### OIDC Identity Provider ("Sign in with Owney") ✅
- Default **off** (`[oidc] enabled = false`); no routes mounted until on
- Authorization-code + PKCE (S256) flow; login is a **passkey assertion**
  (webauthn-rs), consent is remembered per (account, client)
- RS256 ID tokens signed by a key auto-generated under `<data_dir>/oidc/`;
  published via `/oidc/jwks.json` + `/.well-known/openid-configuration`
- Opaque scoped access tokens reuse the `app_passwords` table (scoped+expiring);
  `authenticate_scoped` gates JMAP/push on `owney:mail` and `/mcp` on `owney:mcp`.
  IMAP's `account_by_token` rejects scoped tokens, so they can't be IMAP passwords
- Rotating refresh tokens with **family reuse-detection**; RFC 7009 revocation
- Open-redirect guard: bad client/redirect_uri → error page, never a redirect
- Clients + grants are admin-managed; codes/ceremony state are in-memory (TTL'd)

**Files**:
- `crates/owney-storage/src/oauth.rs` - Clients, grants, refresh tokens (rotation)
- `crates/owney-storage/src/tokens.rs` - `TokenAccess`, scoped-token minting/lookup
- `crates/owney-api/src/oidc/` - keys, discovery, enroll, authorize, consent, token
- `bin/owneyd/src/main.rs` - `admin create-oauth-client|oauth-clients|…|enroll-passkey`

**Docs**: `docs/OIDC.md` (lists the test that proves each capability)

### Future Features (M12+)
- Calendar UI integration
- Contact management
- Task/todo lists
- Chat improvements
- Webhook-based sync (Phase 4)
- Advanced calendar features (Phase 5)

---

## Development Workflow

### How To Approach Tasks

1. **Understand the Context**
   - Read this file
   - Check `docs/PLAN.md` for current phase
   - Read feature-specific docs
   - Review relevant code files

2. **Design Before Coding**
   - Understand the requirement fully
   - Check existing architecture patterns
   - Propose schema/API changes if needed
   - Get alignment on approach

3. **Implement Modularly**
   - Add storage layer first (database + queries)
   - Add business logic (Storage trait methods)
   - Add API/JMAP methods
   - Add tests throughout

4. **Test Thoroughly**
   - Unit tests in each module
   - Integration tests for workflows
   - Check error paths

5. **Document Everything**
   - Code comments for non-obvious "why"
   - Feature docs in `docs/`
   - API examples in docs or comments

6. **Commit Meaningfully**
   - Atomic commits (one feature per commit)
   - Clear commit messages
   - Reference relevant files/methods

### Definition of Done (READ THIS)

On 2026-07-13 three features were built, documented as "complete," compiled, and
passed 182 unit tests — yet a review found 52 issues including unauthenticated
endpoints, an auth API that was never mounted, and recovery codes that could
never verify. See `docs/POSTMORTEM_2026-07-13.md` for the full analysis. To not
repeat it, a feature is **not done** until ALL of these hold:

1. **Wired** — reachable in the real binary (route mounted, worker spawned), not
   just defined. Unmounted code is not a feature.
2. **Run** — executed end-to-end against a running server/db (use `/verify` or
   `/run`), not only unit-tested. State what you actually observed.
3. **Boundary-tested** — at least one negative test per auth/authorization
   boundary ("caller without rights is rejected"), and one test that drives the
   real public entry points in caller order.
4. **No silent stubs** — zero `"placeholder"` identities, zero commented-out
   persistence, zero `unwrap_or_else(|_| ...::new())` on untrusted input.
   Incomplete paths must fail loudly (`todo!()`/`Err`) or be flag-gated OFF,
   never return a fake `Ok`.
5. **Gates green for real** — run (don't assume) `cargo check && cargo test &&
   cargo clippy --all-targets && cargo fmt --check`.
6. **Honest docs** — a completion claim must name the test/command that proves
   it. Do not write "✓ complete" summary docs; they inflate confidence and hide
   gaps. Report "what works / what doesn't yet" instead.

Verify unfamiliar crate APIs against docs.rs/`cargo doc` before use — do not code
from memory. Security endpoints default OFF until authenticated and tested.

### Code Style

**Rust Standards**:
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Use `?` operator for error propagation
- No unwrap() except in tests (use `map_err` + `?` instead)

**Comments**:
- Only document non-obvious "why", not "what"
- Self-documenting code is preferred
- Doc comments for public API items

**Testing**:
- Unit tests in same file (`#[cfg(test)]` module)
- Integration tests in `tests/` directory
- Mock external services in tests

**Naming**:
- `create_*` for new resources
- `get_*` for single item retrieval
- `list_*` for multiple items
- `update_*` for modifications
- `delete_*` for removals

### Database Migrations

**How to add a migration**:

1. **Add to migrations.rs**:
```rust
// N -> N+1: Description of changes
r#"
CREATE TABLE new_table (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    ...
);
CREATE INDEX index_name ON new_table(account_id);
"#,
```

2. **Update MIGRATIONS array**: Add migration string to end of array

3. **Increment version check**: Update `assert_eq!(version as usize, MIGRATIONS.len())`

4. **Add Storage methods**: Implement create/get/list/update/delete in storage layer

5. **Test**: Run migration test to verify schema applies correctly

**Never**:
- Modify old migrations (create new ones instead)
- Delete rows/columns from migrations
- Use unsafe operations

---

## Key Files & Their Purposes

### Storage Schema
- `crates/owney-storage/src/migrations.rs` - All schema migrations (single source of truth)
- `crates/owney-storage/src/lib.rs` - Storage trait implementation

### Feature Modules
- `crates/owney-storage/src/calendar.rs` - Calendar & event storage
- `crates/owney-storage/src/calendar_sharing.rs` - Sharing & federation storage
- `crates/owney-storage/src/contacts.rs` - Contact management
- `crates/owney-jmap-mail/src/lib.rs` - Email/mailbox/thread JMAP methods
- `crates/owney-jmap-mail/src/calendar_methods.rs` - Calendar JMAP methods

### API Layer
- `crates/owney-api/src/lib.rs` - Main router & JMAP dispatcher
- `crates/owney-api/src/federation.rs` - Server discovery protocol
- `crates/owney-api/src/calendar_sync.rs` - Event sync coordinator
- `crates/owney-api/src/background_worker.rs` - Polling worker
- `crates/owney-api/src/wellknown.rs` - Well-known endpoints

### Tests
- `crates/owney-storage/src/*.rs` - Each module has `#[cfg(test)]` section
- Run with: `cargo test --lib`

---

## Common Development Tasks

### Task: Add a New JMAP Method

**Steps**:

1. **Add to storage layer** (`owney-storage/src/*/`):
   ```rust
   pub async fn get_thing(&self, id: ThingId) -> Result<Option<Thing>, StorageError> {
       self.db.call(move |conn| {
           conn.query_row("SELECT ... FROM things WHERE id = ?1", ...)
       }).await
   }
   ```

2. **Add to JMAP handlers** (`owney-jmap-mail/src/calendar_methods.rs`):
   ```rust
   pub async fn thing_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
       let args: GetArgs = serde_json::from_value(args)?;
       let account_id = check_account(&ctx, &args.account_id)?;
       
       let things = ctx.storage.list_things(account_id).await?;
       Ok(json!({"list": things}))
   }
   ```

3. **Register in dispatcher** (`owney-jmap-mail/src/lib.rs`):
   ```rust
   pub fn register(dispatcher: &mut Dispatcher<JmapCtx>) {
       dispatcher.register("Thing/get", CAPABILITY, thing_get);
   }
   ```

4. **Add tests** (in `calendar_methods.rs`):
   ```rust
   #[tokio::test]
   async fn test_thing_get() {
       // test implementation
   }
   ```

5. **Document** in feature docs

### Task: Add a Database Table

**Steps**:

1. **Add migration** to `migrations.rs`:
   ```rust
   // 17 -> 18: Add things table
   r#"
   CREATE TABLE things (id TEXT PRIMARY KEY, ...);
   CREATE INDEX things_by_account ON things(account_id);
   "#,
   ```

2. **Add model** in storage file:
   ```rust
   pub struct Thing {
       pub id: String,
       // fields
   }
   ```

3. **Add Storage methods**: create, get, list, update, delete

4. **Add tests**: Verify CRUD operations

5. **Update version**: Tests verify schema version increments

### Task: Fix a Bug

**Steps**:

1. **Write a test** that reproduces the bug
2. **Verify test fails** - confirms bug exists
3. **Fix the code** - minimal change
4. **Verify test passes** - confirms fix
5. **Check for regressions** - run full test suite
6. **Commit with explanation** - reference the test case

### Task: Optimize a Query

**Steps**:

1. **Identify slow query** - use database logs/metrics
2. **Check if indexes exist** - look at migrations.rs
3. **Add indexes if needed** - create new migration
4. **Benchmark before/after** - measure improvement
5. **Commit with metrics** - document performance gain

### Task: Add Configuration

**Steps**:

1. **Add to config struct** (or env var parsing)
2. **Document in CLAUDE.md** - add to Configuration section
3. **Use in code** - pass config to components
4. **Add defaults** - reasonable defaults in Config::default()
5. **Document in README** - how to configure

### Task: Integrate the Sync Worker

See `docs/CALENDAR_SYNC_INTEGRATION.md` for complete guide.

**Quick version**:
```rust
let worker = SyncWorker::new(storage, SyncWorkerConfig::default());
tokio::spawn(async move { worker.run().await });
```

---

## Testing Strategy

### Unit Tests
- Located in `#[cfg(test)]` modules at end of files
- Test individual functions in isolation
- Use test database (in-memory or temp file)
- Run with: `cargo test --lib`

### Integration Tests
- Located in `tests/` directory (future)
- Test workflows across multiple components
- Use real database (temporary)
- Run with: `cargo test --test '*'`

### Test Patterns

**Storage tests**:
```rust
#[tokio::test]
async fn test_create_and_fetch() {
    let (storage, _) = harness().await;
    
    let account = storage.create_account("test@example.com", None).await.unwrap();
    let fetched = storage.account(account.id).await.unwrap();
    
    assert_eq!(fetched.unwrap().email, "test@example.com");
}
```

**JMAP tests**:
```rust
#[tokio::test]
async fn test_thing_get() {
    let ctx = create_test_context().await;
    
    let result = thing_get(json!({"accountId": "...", ...}), Arc::new(ctx)).await;
    
    assert!(result.is_ok());
}
```

### Running Tests

```bash
# All tests
cargo test

# Specific crate
cargo test -p owney-storage

# Specific test
cargo test calendar_get

# With output
cargo test -- --nocapture

# Ignored tests
cargo test -- --ignored
```

---

## Configuration

### Environment Variables

Most configuration lives in the TOML config file (see `owneyd config example`
and `crates/owney-core/src/config.rs`), NOT env vars. The real env vars:

**Calendar Federation** (read by `FederationConfig::from_env` in
`crates/owney-api/src/fed_sig.rs`):
```bash
OWNEY_FEDERATION_ENABLED=1                    # mount federation endpoints + workers
OWNEY_FEDERATION_ALLOW_PRIVATE_IPS=1          # dev only: allow http + loopback peers
OWNEY_FEDERATION_URL_OVERRIDES=a.test=http://127.0.0.1:8381,b.test=http://127.0.0.1:8382
OWNEY_FEDERATION_ALLOWLIST=server1.com        # unset = allow all domains
OWNEY_FEDERATION_SYNC_INTERVAL_SECS=10        # reconciliation pull (default 300)
```

**Other**: `RUST_LOG` (overrides `[log] filter`), and the AI provider key env
named by `[ai] api_key_env` (default `ANTHROPIC_API_KEY`).

The server's own URL comes from `[api] public_url` in the config file (its
host is the federation identity), not from any env var.

### Config File (Future)

Once implemented, config will be in TOML:
```toml
[server]
listen_addr = "0.0.0.0:8008"
public_url = "https://owney.example.com"

[calendar.sync]
interval_secs = 300
max_backoff_secs = 3600

[storage]
path = "/var/lib/owney/storage.db"
```

---

## Monitoring & Observability

### Logging

Structured logging via `tracing` crate. Enable with:

```bash
RUST_LOG=owney=debug cargo run
```

**Log levels**:
- `ERROR` - Critical issues (database errors, panic on sync)
- `WARN` - Warnings (failed federation sync, auth failures)
- `INFO` - Important events (server start, sync runs completed)
- `DEBUG` - Detailed flow (sync request sent, event upserted)

### Metrics (Future)

Current implementation tracks:
- Federation sync statistics (upserted, deleted events)
- Sync run success/failure rates
- Storage query times (implicit via logs)

Future: Prometheus metrics endpoint

### Health Checks

`GET /healthz` - Returns 200 if server is healthy

Future: Per-component health status

---

## Architecture Decisions

### Why SQLite?
- Simple deployment (single file)
- Excellent for this scale (millions of emails)
- Built-in FTS5 for search
- Transactions + ACID guarantees
- Easy backups

### Why Modular Crates?
- Clear separation of concerns
- Easier to test in isolation
- Can be compiled separately
- Future: optional features

### Why JMAP over IMAP/CalDAV?
- Modern protocol (RFC 8621)
- Push notifications built-in
- Efficient (delta sync)
- JSON-based (easier integration)
- Web-friendly

### Why Bearer Tokens?
- Stateless (no session DB needed)
- Web standard
- Easy to revoke
- Can be scoped per app

### Why Polling for Federation Sync?
- Simple to implement
- No need for server whitelisting
- Works through firewalls/NAT
- Future: upgrade to webhooks for real-time

---

## Known Issues & Limitations

### Current (M11)
- **Calendar JMAP methods incomplete** - Only get/share/invitation methods
- **No access control on sync endpoint** - Will verify in Phase 4
- **No soft deletes** - Events physically removed (add in Phase 5)
- **No recurring event expansion** - Synced as-is (add in Phase 5)
- **No conflict resolution** - Last-write-wins (upgrade in Phase 5)
- **Calendar sync polling only** - Webhooks in Phase 4

### General
- **No mobile apps** - Web UI only currently
- **No chat persistence** - In-memory only (will add to DB)
- **Limited AI features** - Summarization only (more in future)
- **No E2E encryption** - PGP optional only
- **Admin UI missing** - CLI tools only currently

### Performance
- **Full FTS scan for complex queries** - Add sharding in future
- **No query result caching** - Add in Phase 5
- **Sync worker single-threaded** - Federations polled sequentially (can parallelize)

---

## How to Extend

### Add a New Feature

1. **Create feature crate** (if major feature):
   ```
   crates/owney-jmap-{feature}/
   ```

2. **Add storage layer**:
   - New migration in `owney-storage/migrations.rs`
   - New model struct
   - CRUD methods in Storage trait

3. **Add JMAP methods**:
   - New method functions in feature crate
   - Register in dispatcher
   - Add tests

4. **Add background worker** (if needed):
   - Implement periodic job
   - Integrate with main app

5. **Add documentation**:
   - Architecture doc
   - API examples
   - Integration guide

### Hook into Existing Features

**Email events**: Subscribe to StateChange event bus
```rust
let mut rx = event_bus.subscribe();
while let Ok(event) = rx.recv().await {
    // Process StateChange events
}
```

**JMAP methods**: Register new method in dispatcher
```rust
dispatcher.register("MyFeature/get", CAPABILITY, my_handler);
```

**Background tasks**: Spawn async task in main
```rust
tokio::spawn(async { my_worker.run().await });
```

---

## Deployment

### Prerequisites
- Rust 1.70+ (build)
- Tokio runtime (async)
- SQLite (storage)
- S3 bucket (backups, optional)

### Build
```bash
cargo build --release
```

### Configuration
Set environment variables (see Configuration section)

### Run
```bash
./target/release/owney-api  # Or your binary name
```

### Health Check
```bash
curl http://localhost:8008/healthz
```

### Monitoring
- Check logs: `journalctl -u owney -f`
- Query database: `sqlite3 /var/lib/owney/storage.db`
- Monitor sync: `SELECT * FROM calendar_federation WHERE status = 'error'`

---

## Project Roadmap (Full)

| Phase | Feature | Status | Effort | Timeline |
|-------|---------|--------|--------|----------|
| M0 | Email storage & JMAP | ✅ | 40h | ✓ |
| M1 | SMTP inbound | ✅ | 30h | ✓ |
| M2 | Mailbox management | ✅ | 20h | ✓ |
| M3 | Full-text search | ✅ | 25h | ✓ |
| M4-5 | Backup/recovery | ✅ | 35h | ✓ |
| M6 | PGP encryption | ✅ | 30h | ✓ |
| M7-8 | Chat & contacts | ✅ | 45h | ✓ |
| M9 | AI integration | ✅ | 50h | ✓ |
| M10 | WebSocket events | ✅ | 20h | ✓ |
| **M11** | **Calendar Federation** | **🚀** | **40h** | **Current** |
| M12 | Calendar UI | ⏳ | 30h | ~2 wks |
| M13 | Webhooks/real-time | ⏳ | 25h | ~2 wks |
| M14 | Advanced features | ⏳ | 50h | ~3 wks |
| M15 | Mobile apps | 📋 | 80h | ~6 wks |

---

## Communication & Questions

### When Stuck
1. Check relevant docs in `docs/`
2. Look at similar existing code
3. Review commit history for context
4. Ask clarifying questions about requirements

### Code Review Checklist
- [ ] Tests added/updated
- [ ] Docs updated
- [ ] Error handling comprehensive
- [ ] No unwrap() in production code
- [ ] Follows naming conventions
- [ ] Commit message is clear

### Adding Documentation
- Add architecture docs to `docs/` for major features
- Include examples for API methods
- Document configuration options
- Note any non-obvious design decisions

---

## Repository Structure

```
.
├── CLAUDE.md                          ← You are here
├── README.md                          ← User-facing overview
├── Cargo.toml                         ← Workspace manifest
├── Cargo.lock                         ← Dependency lock file
├── crates/                            ← All Rust crates
│   ├── jmap-core/                     ← JMAP protocol
│   ├── owney-core/                    ← Core types
│   ├── owney-storage/                 ← Database layer
│   ├── owney-events/                  ← Event bus
│   ├── owney-api/                     ← HTTP + endpoints
│   ├── owney-jmap-mail/               ← Email JMAP methods
│   ├── owney-authn/                   ← Authentication
│   ├── owney-delivery/                ← Outbound mail
│   ├── owney-smtp-in/                 ← Inbound SMTP
│   ├── owney-pgp/                     ← Encryption
│   ├── owney-spam/                    ← Spam filter
│   ├── owney-ai/                      ← AI features
│   ├── owney-backup/                  ← Backups
│   ├── owney-mcp/                     ← AI integration
│   └── ... (more)
├── docs/                              ← Documentation
│   ├── PLAN.md                        ← Overall roadmap
│   ├── CALENDAR_FEDERATION.md         ← Calendar architecture
│   ├── CALENDAR_SYNC_PROTOCOL.md      ← Sync spec
│   ├── CALENDAR_FEDERATION_ROADMAP.md ← Phases 1-5
│   ├── CALENDAR_SYNC_INTEGRATION.md   ← Integration guide
│   └── ...
└── tests/                             ← Integration tests (future)
```

---

## Final Notes

### For AI Assistants
- This project uses Rust with async/await throughout
- Storage is SQLite via rusqlite (synchronous API, used in async via db.call())
- JMAP dispatcher pattern: methods take (Value, Arc<JmapCtx>) → Result<Value, MethodError>
- Errors use `?` operator for propagation + map_err for conversions
- No unwrap() in production code
- Tests use harness() helper to create temp storage
- Naming conventions: create_*, get_*, list_*, update_*, delete_*

### For Humans
- Start with `docs/PLAN.md` for big picture
- Check feature-specific docs for details
- Read code in order: storage → logic → API
- Run `cargo test` to verify changes
- Ask questions in commit messages / comments

### Key Contacts & Resources
- **Git**: Commit messages are primary documentation
- **Errors**: Check migration in migrations.rs for schema
- **Tests**: Look in `#[cfg(test)]` modules for examples
- **APIs**: Check dispatcher registration in lib.rs files

---

**Last Updated**: 2026-07-13  
**Current Phase**: M11 - Calendar Federation (Phase 2.5 Complete)  
**Next Phase**: M12 - Calendar UI Integration

Good luck! 🚀
