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
    fn newer_schema_is_refused() {
        let mut conn = Connection::open_in_memory().expect("open");
        conn.pragma_update(None, "user_version", 999).expect("set");
        assert!(matches!(apply(&mut conn), Err(StorageError::Corrupt(_))));
    }
}
