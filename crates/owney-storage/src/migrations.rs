//! Embedded schema migrations, tracked via `PRAGMA user_version`.
//!
//! Rules: migrations are append-only, each runs in its own transaction, and a
//! released migration is never edited — schema changes are always a new entry.
//! The M6 backup drill (restore previous release's backup into the new
//! version) is what keeps us honest here.

use rusqlite::Connection;

use crate::error::StorageError;

/// `MIGRATIONS[n]` upgrades the schema from user_version n to n+1.
const MIGRATIONS: &[&str] = &[
    // 0 -> 1: initial JMAP-shaped core schema.
    r#"
    CREATE TABLE accounts (
        id            TEXT PRIMARY KEY,
        email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name  TEXT,
        created_at    INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE mailboxes (
        id             TEXT PRIMARY KEY,
        account_id     TEXT NOT NULL REFERENCES accounts(id),
        parent_id      TEXT REFERENCES mailboxes(id),
        name           TEXT NOT NULL,
        role           TEXT,
        sort_order     INTEGER NOT NULL DEFAULT 0,
        created_modseq INTEGER NOT NULL,
        updated_modseq INTEGER NOT NULL
    ) STRICT;
    CREATE UNIQUE INDEX mailboxes_by_name ON mailboxes (account_id, ifnull(parent_id, ''), name);
    CREATE UNIQUE INDEX mailboxes_by_role ON mailboxes (account_id, role) WHERE role IS NOT NULL;

    CREATE TABLE threads (
        id             TEXT PRIMARY KEY,
        account_id     TEXT NOT NULL REFERENCES accounts(id),
        created_modseq INTEGER NOT NULL,
        updated_modseq INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE emails (
        id             TEXT PRIMARY KEY,
        account_id     TEXT NOT NULL REFERENCES accounts(id),
        thread_id      TEXT NOT NULL REFERENCES threads(id),
        blob_id        TEXT NOT NULL,
        message_id     TEXT,
        subject        TEXT,
        from_addr      TEXT,
        received_at    INTEGER NOT NULL,
        size           INTEGER NOT NULL,
        created_modseq INTEGER NOT NULL,
        updated_modseq INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX emails_by_arrival ON emails (account_id, received_at DESC);
    CREATE INDEX emails_by_thread ON emails (thread_id);
    CREATE INDEX emails_by_message_id ON emails (account_id, message_id);

    CREATE TABLE email_mailbox (
        email_id   TEXT NOT NULL REFERENCES emails(id),
        mailbox_id TEXT NOT NULL REFERENCES mailboxes(id),
        PRIMARY KEY (email_id, mailbox_id)
    ) STRICT, WITHOUT ROWID;
    CREATE INDEX email_mailbox_by_mailbox ON email_mailbox (mailbox_id);

    CREATE TABLE email_keyword (
        email_id TEXT NOT NULL REFERENCES emails(id),
        keyword  TEXT NOT NULL,
        PRIMARY KEY (email_id, keyword)
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE blobs (
        id         TEXT PRIMARY KEY,
        size       INTEGER NOT NULL,
        refcount   INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE states (
        account_id TEXT NOT NULL REFERENCES accounts(id),
        data_type  TEXT NOT NULL,
        modseq     INTEGER NOT NULL,
        PRIMARY KEY (account_id, data_type)
    ) STRICT, WITHOUT ROWID;
    "#,
    // 1 -> 2: per-message authentication verdicts (ms-authn), JSON.
    "ALTER TABLE emails ADD COLUMN auth_results TEXT;",
    // 2 -> 3: durable outbound delivery queue, one row per recipient.
    r#"
    CREATE TABLE queue (
        id           TEXT PRIMARY KEY,
        account_id   TEXT NOT NULL REFERENCES accounts(id),
        blob_id      TEXT NOT NULL,
        mail_from    TEXT NOT NULL,
        recipient    TEXT NOT NULL,
        domain       TEXT NOT NULL,
        attempts     INTEGER NOT NULL DEFAULT 0,
        next_attempt INTEGER NOT NULL,
        status       TEXT NOT NULL DEFAULT 'queued',
        last_error   TEXT,
        created_at   INTEGER NOT NULL,
        updated_at   INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX queue_due ON queue (status, next_attempt);
    "#,
    // 3 -> 4: API bearer tokens (app passwords). Only the BLAKE3 hash of a
    // token is stored; the plaintext is shown once at creation.
    r#"
    CREATE TABLE app_passwords (
        token_hash   TEXT PRIMARY KEY,
        account_id   TEXT NOT NULL REFERENCES accounts(id),
        name         TEXT NOT NULL,
        created_at   INTEGER NOT NULL,
        last_used_at INTEGER
    ) STRICT;
    "#,
    // 4 -> 5: PGP. Own secret certs live in the (encrypted) blob store; this
    // table only points at them. Peer certs are public material.
    r#"
    CREATE TABLE pgp_own_keys (
        account_id  TEXT PRIMARY KEY REFERENCES accounts(id),
        fingerprint TEXT NOT NULL,
        blob_id     TEXT NOT NULL,
        created_at  INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE pgp_peers (
        account_id     TEXT NOT NULL REFERENCES accounts(id),
        address        TEXT NOT NULL,
        cert           BLOB NOT NULL,
        fingerprint    TEXT NOT NULL,
        prefer_encrypt TEXT,
        last_seen      INTEGER NOT NULL,
        PRIMARY KEY (account_id, address)
    ) STRICT, WITHOUT ROWID;

    ALTER TABLE emails ADD COLUMN pgp_status TEXT;
    "#,
    // 5 -> 6: the AI layer. Annotations are enrichment (summaries,
    // unsubscribe affordances); actions are the audit log with inverse
    // patches so everything the AI does can be undone; the cursor makes
    // enrichment resumable (at-least-once over the modseq stream).
    r#"
    CREATE TABLE ai_annotations (
        id         TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id),
        email_id   TEXT NOT NULL REFERENCES emails(id),
        kind       TEXT NOT NULL,
        content    TEXT NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX ai_annotations_by_email ON ai_annotations (email_id, kind);

    CREATE TABLE ai_actions (
        id            TEXT PRIMARY KEY,
        account_id    TEXT NOT NULL REFERENCES accounts(id),
        email_id      TEXT REFERENCES emails(id),
        skill         TEXT NOT NULL,
        description   TEXT NOT NULL,
        inverse_patch TEXT,
        undone        INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX ai_actions_by_account ON ai_actions (account_id, created_at DESC);

    CREATE TABLE ai_cursor (
        account_id  TEXT PRIMARY KEY REFERENCES accounts(id),
        last_modseq INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    "#,
    // 6 -> 7: DMARC reporting. Stores aggregate reports (RFC 7489)
    // for visibility into email deliverability and authentication.
    r#"
    CREATE TABLE dmarc_reports (
        id                TEXT PRIMARY KEY,
        account_id        TEXT NOT NULL REFERENCES accounts(id),
        received_at       INTEGER NOT NULL,
        reporter          TEXT NOT NULL,
        domain            TEXT NOT NULL,
        date_range_start  INTEGER NOT NULL,
        date_range_end    INTEGER NOT NULL,
        dmarc_pass_count  INTEGER NOT NULL DEFAULT 0,
        dmarc_fail_count  INTEGER NOT NULL DEFAULT 0,
        policy_sent       TEXT,
        policy_evaluated  TEXT,
        raw_json          TEXT,
        created_at        INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX dmarc_reports_by_domain ON dmarc_reports (account_id, domain, received_at DESC);
    "#,
    // 7 -> 8: Account lifecycle: soft-disable via disabled_at timestamp.
    // Disabled accounts cannot authenticate (JMAP/REST/MCP/IMAP) and reject
    // inbound mail at RCPT (550). NULL = active; set to block login.
    r#"
    ALTER TABLE accounts ADD COLUMN disabled_at INTEGER;
    "#,
    // 8 -> 9: Email aliases (permanent and temporary).
    // Maps alias_email (e.g., alice+shopping@example.com) to an owner account.
    // Supports expiration (user-set TTL or manual deactivation).
    // Mail to alias lands in owner's mailbox; Identity/get lists all active aliases as send-as identities.
    r#"
    CREATE TABLE aliases (
        id          TEXT PRIMARY KEY,
        account_id  TEXT NOT NULL REFERENCES accounts(id),
        alias_email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        label       TEXT,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER,          -- NULL = permanent; set to unix timestamp for expiration
        active      INTEGER NOT NULL DEFAULT 1
    ) STRICT;
    CREATE INDEX aliases_by_account ON aliases (account_id, active) WHERE active = 1;
    "#,
    // 9 -> 10: Spam filtering verdicts per message.
    // Stores the result of spam scanning (DNSBL hits, heuristic score, Bayes probability).
    // Same pattern as auth_results: JSON string for flexibility.
    r#"
    ALTER TABLE emails ADD COLUMN spam_results TEXT;
    CREATE TABLE spam_tokens (
        account_id  TEXT NOT NULL REFERENCES accounts(id),
        token       TEXT NOT NULL,
        spam_count  INTEGER NOT NULL DEFAULT 0,
        ham_count   INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (account_id, token)
    ) STRICT, WITHOUT ROWID;
    "#,
    // 10 -> 11: Chat mode for real-time email delivery.
    // emails.chat_mode: whether this email was submitted with chat intent (sender-initiated).
    // chat_preferences: per-recipient settings for how to handle chat from each contact.
    r#"
    ALTER TABLE emails ADD COLUMN chat_mode INTEGER DEFAULT 0;
    CREATE TABLE chat_preferences (
        account_id  TEXT NOT NULL REFERENCES accounts(id),
        contact_email TEXT NOT NULL COLLATE NOCASE,
        preference  TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        updated_at  INTEGER NOT NULL,
        PRIMARY KEY (account_id, contact_email)
    ) STRICT;
    CREATE INDEX chat_preferences_by_account ON chat_preferences (account_id);
    "#,
    // 11 -> 12: Queue priority for chat mode delivery.
    // queue.priority: 0=normal (1m/5m/30m/2h/4h backoff), 1=chat (30s/2m/10m/1h backoff)
    "ALTER TABLE queue ADD COLUMN priority INTEGER DEFAULT 0;",
    // 12 -> 13: Full-text search index tracking via tantivy.
    // emails.search_indexed: whether this email has been indexed into the tantivy FTS engine.
    "ALTER TABLE emails ADD COLUMN search_indexed INTEGER DEFAULT 0;",
    // 13 -> 14: Calendar support (M9W3).
    // calendars: user's calendar collections (Personal, Work, etc.)
    // calendar_events: events with optional recurrence rules (RFC 5545 subset)
    r#"
    CREATE TABLE calendars (
        id             TEXT PRIMARY KEY,
        account_id     TEXT NOT NULL REFERENCES accounts(id),
        name           TEXT NOT NULL,
        description    TEXT,
        created_at     INTEGER NOT NULL,
        updated_at     INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX calendars_by_account ON calendars (account_id);

    CREATE TABLE calendar_events (
        id             TEXT PRIMARY KEY,
        calendar_id    TEXT NOT NULL REFERENCES calendars(id),
        title          TEXT NOT NULL,
        description    TEXT,
        start          INTEGER NOT NULL,
        end            INTEGER NOT NULL,
        rrule          TEXT,
        created_at     INTEGER NOT NULL,
        updated_at     INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX calendar_events_by_calendar ON calendar_events (calendar_id);
    CREATE INDEX calendar_events_by_time ON calendar_events (start, end);
    "#,
    // 14 -> 15: Contacts with auto-linking from email senders (M9W3W2).
    r#"
    CREATE TABLE contacts (
        id             TEXT PRIMARY KEY,
        account_id     TEXT NOT NULL REFERENCES accounts(id),
        email          TEXT NOT NULL COLLATE NOCASE,
        name           TEXT,
        phone          TEXT,
        created_at     INTEGER NOT NULL,
        updated_at     INTEGER NOT NULL,
        UNIQUE (account_id, email)
    ) STRICT;
    CREATE INDEX contacts_by_account ON contacts (account_id);
    "#,
    // 15 -> 16: Calendar sharing for same-server sharing and delegation.
    r#"
    CREATE TABLE calendar_sharing (
        id                      TEXT PRIMARY KEY,
        calendar_id             TEXT NOT NULL REFERENCES calendars(id),
        shared_with_account_id  TEXT NOT NULL REFERENCES accounts(id),
        sharing_type            TEXT NOT NULL,  -- "sharing", "delegation"
        permissions             TEXT NOT NULL,  -- JSON: {view_calendar, view_events, edit_events, delete_events, change_sharing, admin}
        status                  TEXT NOT NULL,  -- "pending", "accepted", "rejected", "revoked"
        created_at              INTEGER NOT NULL,
        accepted_at             INTEGER,
        UNIQUE (calendar_id, shared_with_account_id)
    ) STRICT;
    CREATE INDEX calendar_sharing_by_account ON calendar_sharing (shared_with_account_id);
    CREATE INDEX calendar_sharing_by_calendar ON calendar_sharing (calendar_id);

    CREATE TABLE calendar_invitations (
        id                  TEXT PRIMARY KEY,
        calendar_id         TEXT NOT NULL REFERENCES calendars(id),
        inviter_account_id  TEXT NOT NULL REFERENCES accounts(id),
        invitee_email       TEXT NOT NULL,                    -- Can be federated: user@domain.com or local
        invitee_server_url  TEXT,                             -- Set if federated
        sharing_type        TEXT NOT NULL,                    -- "sharing", "delegation"
        status              TEXT NOT NULL,                    -- "pending", "accepted", "rejected"
        message             TEXT,
        created_at          INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX calendar_invitations_by_invitee ON calendar_invitations (invitee_email);
    CREATE INDEX calendar_invitations_by_calendar ON calendar_invitations (calendar_id);
    "#,
    // 16 -> 17: Cross-server calendar federation with sync support.
    r#"
    CREATE TABLE calendar_federation (
        id              TEXT PRIMARY KEY,
        calendar_id     TEXT NOT NULL REFERENCES calendars(id),
        target_email    TEXT NOT NULL,                        -- user@domain.com
        target_server_url TEXT NOT NULL,                      -- https://owney.domain.com
        sharing_type    TEXT NOT NULL,                        -- "sharing", "delegation"
        permissions     TEXT NOT NULL,                        -- JSON permissions
        status          TEXT NOT NULL,                        -- "pending", "accepted", "syncing", "error"
        sync_token      TEXT,                                 -- Opaque token for incremental sync
        last_sync_at    INTEGER,
        created_at      INTEGER NOT NULL,
        UNIQUE (calendar_id, target_email)
    ) STRICT;
    CREATE INDEX calendar_federation_by_calendar ON calendar_federation (calendar_id);
    CREATE INDEX calendar_federation_by_status ON calendar_federation (status);
    "#,
    // 17 -> 18: Passwordless authentication (M12).
    // Passkeys (WebAuthn/FIDO2), recovery codes, device pairings, and approval requests.
    r#"
    CREATE TABLE passkey_credentials (
        id            BLOB PRIMARY KEY,
        account_id    TEXT NOT NULL REFERENCES accounts(id),
        device_name   TEXT NOT NULL,
        public_key    BLOB NOT NULL,
        counter       INTEGER NOT NULL DEFAULT 0,
        backup_eligible INTEGER DEFAULT 0,
        backup_state  INTEGER DEFAULT 0,
        aaguid        BLOB,
        created_at    INTEGER NOT NULL,
        last_used_at  INTEGER,
        disabled      INTEGER DEFAULT 0
    ) STRICT;
    CREATE INDEX passkey_by_account ON passkey_credentials (account_id);
    CREATE INDEX passkey_by_disabled ON passkey_credentials (disabled);

    CREATE TABLE recovery_codes (
        id            TEXT PRIMARY KEY,
        account_id    TEXT NOT NULL REFERENCES accounts(id),
        code_hash     TEXT NOT NULL,
        display_code  TEXT NOT NULL,
        used          INTEGER DEFAULT 0,
        used_at       INTEGER,
        created_at    INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX recovery_by_account ON recovery_codes (account_id);
    CREATE INDEX recovery_by_used ON recovery_codes (used);

    CREATE TABLE device_pairings (
        id            TEXT PRIMARY KEY,
        account_id    TEXT NOT NULL REFERENCES accounts(id),
        device_name   TEXT NOT NULL,
        device_type   TEXT NOT NULL,
        public_key    BLOB NOT NULL,
        can_approve   INTEGER DEFAULT 1,
        push_token    TEXT,
        paired_at     INTEGER NOT NULL,
        last_used_at  INTEGER,
        disabled      INTEGER DEFAULT 0
    ) STRICT;
    CREATE INDEX pairing_by_account ON device_pairings (account_id);

    CREATE TABLE approval_requests (
        id                    TEXT PRIMARY KEY,
        account_id            TEXT NOT NULL REFERENCES accounts(id),
        source_device         TEXT NOT NULL,
        request_type          TEXT NOT NULL,
        challenge             TEXT NOT NULL,
        created_at            INTEGER NOT NULL,
        expires_at            INTEGER NOT NULL,
        status                TEXT NOT NULL,
        approved_by_device    TEXT REFERENCES device_pairings(id),
        approved_at           INTEGER
    ) STRICT;
    CREATE INDEX approval_by_account ON approval_requests (account_id);
    CREATE INDEX approval_by_expires ON approval_requests (expires_at);
    CREATE INDEX approval_by_status ON approval_requests (status);
    "#,
    // 18 -> 19: Secure calendar federation (M11).
    // Server identity keypair, pinned peer server certs, replay-nonce cache,
    // per-federation capability + direction, remote-event id mapping (closes the
    // cross-tenant overwrite bug), and the federation delivery outbox.
    r#"
    -- Singleton PGP identity for this server (secret TSK in the encrypted blob
    -- store; only the fingerprint + blob pointer live here).
    CREATE TABLE server_identity (
        id           INTEGER PRIMARY KEY CHECK (id = 1),
        fingerprint  TEXT NOT NULL,
        blob_id      TEXT NOT NULL,
        created_at   INTEGER NOT NULL
    ) STRICT;

    -- Public server certs pinned per peer domain (trust-on-first-use over TLS).
    CREATE TABLE federation_peers (
        domain       TEXT PRIMARY KEY,
        server_url   TEXT NOT NULL,
        cert         BLOB NOT NULL,
        fingerprint  TEXT NOT NULL,
        pinned_at    INTEGER NOT NULL,
        last_seen    INTEGER
    ) STRICT;

    -- Seen request nonces, for replay rejection within the timestamp window.
    CREATE TABLE federation_replay_nonce (
        sender_fp   TEXT NOT NULL,
        nonce       TEXT NOT NULL,
        expires_at  INTEGER NOT NULL,
        PRIMARY KEY (sender_fp, nonce)
    ) STRICT, WITHOUT ROWID;
    CREATE INDEX federation_nonce_gc ON federation_replay_nonce (expires_at);

    -- Authenticated-federation columns on the existing federation table.
    ALTER TABLE calendar_federation ADD COLUMN peer_domain TEXT;
    ALTER TABLE calendar_federation ADD COLUMN peer_fingerprint TEXT;
    ALTER TABLE calendar_federation ADD COLUMN capability_secret TEXT;
    ALTER TABLE calendar_federation ADD COLUMN direction TEXT;

    -- Maps a peer's opaque event uid to a LOCAL server-minted event id, scoped
    -- to the federation. Remote ids are never used as local primary keys.
    CREATE TABLE federation_event_map (
        federation_id  TEXT NOT NULL REFERENCES calendar_federation(id),
        remote_uid     TEXT NOT NULL,
        local_event_id TEXT NOT NULL REFERENCES calendar_events(id),
        author_email   TEXT NOT NULL,
        updated_at     INTEGER NOT NULL,
        PRIMARY KEY (federation_id, remote_uid)
    ) STRICT;
    CREATE INDEX federation_event_map_by_local ON federation_event_map (local_event_id);

    -- Provenance markers on events so synced-in events don't echo back out.
    ALTER TABLE calendar_events ADD COLUMN origin TEXT;
    ALTER TABLE calendar_events ADD COLUMN origin_federation TEXT;

    -- Durable outbox of signed webhook deliveries (mirrors the mail queue).
    CREATE TABLE federation_outbox (
        id            TEXT PRIMARY KEY,
        federation_id TEXT NOT NULL REFERENCES calendar_federation(id),
        peer_domain   TEXT NOT NULL,
        payload       BLOB NOT NULL,
        attempts      INTEGER NOT NULL DEFAULT 0,
        next_attempt  INTEGER NOT NULL,
        status        TEXT NOT NULL DEFAULT 'queued',
        last_error    TEXT,
        created_at    INTEGER NOT NULL,
        updated_at    INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX federation_outbox_due ON federation_outbox (status, next_attempt);
    "#,
    // 19 -> 20: Server-added email attributes (supersedes ai_annotations).
    // One attribute per (email, kind), upserted by server-side detectors;
    // clients may dismiss. Writes must bump the Email modseq so /changes and
    // push observe them. ai_annotations stays dormant (never edit or drop a
    // shipped migration's objects); a future migration removes it.
    r#"
    CREATE TABLE email_attributes (
        id           TEXT PRIMARY KEY,
        account_id   TEXT NOT NULL REFERENCES accounts(id),
        email_id     TEXT NOT NULL REFERENCES emails(id),
        kind         TEXT NOT NULL,
        content      TEXT NOT NULL,
        dismissed_at INTEGER,
        created_at   INTEGER NOT NULL,
        updated_at   INTEGER NOT NULL,
        UNIQUE (email_id, kind)
    ) STRICT;
    CREATE INDEX email_attributes_by_email ON email_attributes (email_id);
    CREATE INDEX email_attributes_by_account ON email_attributes (account_id, kind);

    -- Copy existing annotations; the old table allowed duplicates per
    -- (email_id, kind), so keep only the newest (ids are UUIDv7, so id DESC
    -- is a time-ordered tiebreak within equal created_at).
    INSERT INTO email_attributes
        (id, account_id, email_id, kind, content, dismissed_at, created_at, updated_at)
    SELECT a.id, a.account_id, a.email_id, a.kind, a.content, NULL, a.created_at, a.created_at
    FROM ai_annotations a
    WHERE a.id = (SELECT b.id FROM ai_annotations b
                  WHERE b.email_id = a.email_id AND b.kind = a.kind
                  ORDER BY b.created_at DESC, b.id DESC LIMIT 1);
    "#,
    // 20 -> 21: Public scheduling pages ("book a meeting with me") + bookings.
    // availability is a versioned JSON document (owney-storage/src/scheduling.rs).
    // bookings.status is 'confirmed'|'cancelled' today; 'pending' is reserved
    // for a future approval flow, cancel_token for future cancellation links.
    r#"
    CREATE TABLE scheduling_pages (
        id                 TEXT PRIMARY KEY,
        account_id         TEXT NOT NULL REFERENCES accounts(id),
        slug               TEXT NOT NULL,
        title              TEXT NOT NULL,
        description        TEXT,
        calendar_id        TEXT NOT NULL REFERENCES calendars(id),
        timezone           TEXT NOT NULL,
        availability       TEXT NOT NULL,
        durations_mins     TEXT NOT NULL,
        buffer_before_mins INTEGER NOT NULL DEFAULT 0,
        buffer_after_mins  INTEGER NOT NULL DEFAULT 0,
        min_notice_mins    INTEGER NOT NULL DEFAULT 0,
        max_per_day        INTEGER,
        valid_from         TEXT,
        valid_until        TEXT,
        status             TEXT NOT NULL DEFAULT 'active',
        created_at         INTEGER NOT NULL,
        updated_at         INTEGER NOT NULL
    ) STRICT;
    CREATE UNIQUE INDEX scheduling_pages_by_slug ON scheduling_pages (slug);
    CREATE INDEX scheduling_pages_by_account ON scheduling_pages (account_id);

    CREATE TABLE bookings (
        id            TEXT PRIMARY KEY,
        page_id       TEXT NOT NULL REFERENCES scheduling_pages(id),
        account_id    TEXT NOT NULL REFERENCES accounts(id),
        event_id      TEXT NOT NULL REFERENCES calendar_events(id),
        visitor_name  TEXT NOT NULL,
        visitor_email TEXT NOT NULL,
        note          TEXT,
        start         INTEGER NOT NULL,
        end           INTEGER NOT NULL,
        status        TEXT NOT NULL DEFAULT 'confirmed',
        cancel_token  TEXT NOT NULL,
        created_at    INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX bookings_by_page ON bookings (page_id, start);
    CREATE INDEX bookings_by_account_time ON bookings (account_id, start, end);
    "#,
];

pub fn apply(conn: &mut Connection) -> Result<(), StorageError> {
    let current: usize =
        conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))? as usize;

    if current > MIGRATIONS.len() {
        return Err(StorageError::Corrupt(format!(
            "database schema version {current} is newer than this binary understands \
             ({}); refusing to open",
            MIGRATIONS.len()
        )));
    }

    for (n, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (n + 1) as i64)?;
        tx.commit()?;
        tracing::info!(version = n + 1, "applied schema migration");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_is_idempotent() {
        let mut conn = Connection::open_in_memory().expect("open");
        apply(&mut conn).expect("first");
        apply(&mut conn).expect("second");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version as usize, MIGRATIONS.len());
    }

    #[test]
    fn migration_20_dedups_ai_annotations() {
        let mut conn = Connection::open_in_memory().expect("open");
        // Apply everything up to (not including) the email_attributes migration.
        for (n, sql) in MIGRATIONS.iter().enumerate().take(19) {
            let tx = conn.transaction().expect("tx");
            tx.execute_batch(sql).expect("migration");
            tx.pragma_update(None, "user_version", (n + 1) as i64)
                .expect("version");
            tx.commit().expect("commit");
        }
        // Disable FKs so no fixture accounts/emails are needed. Two rows for
        // the same (email_id, kind): newest must win.
        conn.pragma_update(None, "foreign_keys", "OFF").expect("fk");
        conn.execute_batch(
            "INSERT INTO ai_annotations (id, account_id, email_id, kind, content, created_at)
             VALUES ('0198a000-0000-7000-8000-000000000001', 'acct', 'em1', 'summary', 'old', 100),
                    ('0198a000-0000-7000-8000-000000000002', 'acct', 'em1', 'summary', 'new', 200),
                    ('0198a000-0000-7000-8000-000000000003', 'acct', 'em1', 'unsubscribe', '{}', 150);",
        )
        .expect("seed");

        apply(&mut conn).expect("finish migrations");

        let rows: Vec<(String, String)> = conn
            .prepare(
                "SELECT kind, content FROM email_attributes WHERE email_id = 'em1' ORDER BY kind",
            )
            .expect("prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![
                ("summary".to_string(), "new".to_string()),
                ("unsubscribe".to_string(), "{}".to_string()),
            ]
        );
        let dismissed: i64 = conn
            .query_row(
                "SELECT count(*) FROM email_attributes WHERE dismissed_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(dismissed, 0);
    }

    #[test]
    fn newer_schema_is_refused() {
        let mut conn = Connection::open_in_memory().expect("open");
        conn.pragma_update(None, "user_version", 999).expect("set");
        assert!(matches!(apply(&mut conn), Err(StorageError::Corrupt(_))));
    }
}
