//! Persistence for the whole server: SQLite (JMAP-shaped schema) plus the
//! encrypted blob store, unified behind `Storage`.
//!
//! The one rule everything else relies on: **all mutations go through this
//! crate, and every mutation bumps the per-account modseq for the data types
//! it touched and publishes a `StateChange` event after commit.** JMAP
//! `/changes`, push, and client realtime sync are all derived from that.
//!
//! ## Backend portability — explicitly *not* abstracted today
//!
//! `Storage` is a concrete struct, not a trait. Swapping the SQLite backend
//! for PostgreSQL or an in-memory test double would touch every call site.
//! This is a deliberate trade-off: the storage crate is the only place
//! touching `rusqlite` directly, so the blast radius of a future trait
//! refactor is bounded to this one crate. Until there is a second backend
//! worth supporting, the untyped concrete API stays.

mod ai_store;
mod aliases;
mod blob;
mod chat_preferences;
mod db;
mod error;
mod ingest;
mod keys;
mod mail_queries;
mod migrations;
mod pgp_store;
mod queue;
mod spam_store;
mod tokens;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use owney_core::{AccountId, BlobId, DataType, MailboxId, ModSeq};
use owney_events::{Event, EventBus};
use rusqlite::{Connection, OptionalExtension, params};

pub use ai_store::AiAction;
pub use aliases::Alias;
pub use blob::BlobStore;
pub use chat_preferences::{ChatMode, ChatPreference};
pub use db::Db;
pub use error::StorageError;
pub use ingest::{EmailSummary, IngestedEmail, MailboxTarget};
pub use keys::{MASTER_KEY_FILE, MasterKey};
pub use mail_queries::{ChangesResult, EmailRow, MailboxRow};
pub use pgp_store::PgpPeer;
pub use queue::{AttemptOutcome, QueueItem};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub email: String,
    pub display_name: Option<String>,
    pub created_at: i64,
}

#[derive(Debug)]
pub struct Storage {
    pub(crate) db: Db,
    blobs: BlobStore,
    pub(crate) events: EventBus,
    data_dir: PathBuf,
}

impl Storage {
    /// Open (creating on first run) the data directory: master key, database,
    /// and blob store.
    pub fn open(data_dir: &Path, events: EventBus) -> Result<Self, StorageError> {
        std::fs::create_dir_all(data_dir).map_err(|source| StorageError::io(data_dir, source))?;
        let master = MasterKey::load_or_create(&data_dir.join(MASTER_KEY_FILE))?;
        let blobs = BlobStore::open(data_dir.join("blobs"), master)?;
        let db = Db::open(&data_dir.join("mail.db"))?;
        Ok(Self {
            db,
            blobs,
            events,
            data_dir: data_dir.to_owned(),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Create an account with its default mailbox set.
    pub async fn create_account(
        &self,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<Account, StorageError> {
        let email = email.trim().to_lowercase();
        let display_name = display_name.map(str::to_owned);
        let account_id = AccountId::new();

        let changed = self
            .db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let created_at = unix_now();
                tx.execute(
                    "INSERT INTO accounts (id, email, display_name, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![account_id.to_string(), email, display_name, created_at],
                )?;

                let modseq = bump(&tx, account_id, DataType::Mailbox)?;
                for (name, role, sort_order) in DEFAULT_MAILBOXES {
                    tx.execute(
                        "INSERT INTO mailboxes
                           (id, account_id, name, role, sort_order,
                            created_modseq, updated_modseq)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                        params![
                            MailboxId::new().to_string(),
                            account_id.to_string(),
                            name,
                            role,
                            sort_order,
                            modseq.0 as i64,
                        ],
                    )?;
                }
                tx.commit()?;
                Ok(vec![(DataType::Mailbox, modseq)])
            })
            .await?;

        self.events.publish(Event::StateChange {
            account_id,
            changed,
        });
        self.account(account_id)
            .await?
            .ok_or(StorageError::AccountNotFound)
    }

    pub async fn account(&self, id: AccountId) -> Result<Option<Account>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, email, display_name, created_at
                         FROM accounts WHERE id = ?1",
                        [id.to_string()],
                        row_to_account,
                    )
                    .optional()?)
            })
            .await
    }

    pub async fn account_by_email(&self, email: &str) -> Result<Option<Account>, StorageError> {
        let email = email.trim().to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, email, display_name, created_at
                         FROM accounts WHERE email = ?1 AND disabled_at IS NULL",
                        [email],
                        row_to_account,
                    )
                    .optional()?)
            })
            .await
    }

    /// Look up an account by email including disabled ones (for admin enable/disable operations).
    pub async fn account_by_email_any_state(&self, email: &str) -> Result<Option<Account>, StorageError> {
        let email = email.trim().to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, email, display_name, created_at
                         FROM accounts WHERE email = ?1",
                        [email],
                        row_to_account,
                    )
                    .optional()?)
            })
            .await
    }

    pub async fn accounts(&self) -> Result<Vec<Account>, StorageError> {
        self.db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, email, display_name, created_at
                     FROM accounts ORDER BY created_at",
                )?;
                let accounts = stmt
                    .query_map([], row_to_account)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(accounts)
            })
            .await
    }

    /// Disable an account: blocks login and inbound mail rejection (550).
    pub async fn disable_account(&self, id: AccountId) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE accounts SET disabled_at = ?1 WHERE id = ?2",
                    params![unix_now(), id.to_string()],
                )?;
                Ok(())
            })
            .await
    }

    /// Re-enable a disabled account.
    pub async fn enable_account(&self, id: AccountId) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE accounts SET disabled_at = NULL WHERE id = ?2",
                    params![id.to_string()],
                )?;
                Ok(())
            })
            .await
    }

    /// Hard-delete an account and all associated data (cascades to emails, blobs, tokens, aliases).
    /// This is permanent and intentionally explicit to avoid accidents.
    pub async fn delete_account(&self, id: AccountId) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;

                // Collect blob IDs to delete from storage
                let mut stmt = tx.prepare(
                    "SELECT DISTINCT b.id FROM blobs b
                     INNER JOIN emails e ON e.blob_id = b.id
                     WHERE e.account_id = ?1",
                )?;
                let blob_ids: Vec<String> = stmt
                    .query_map([id.to_string()], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                drop(stmt);

                // Delete cascade: aliases, submissions, tokens, pgp_peers, pgp_own_keys, ai_actions, ai_annotations, email_keywords, email_mailbox, emails, threads, mailboxes, states, accounts
                for table in &[
                    "aliases",
                    "submissions",
                    "queue",
                    "app_passwords",
                    "pgp_peers",
                    "pgp_own_keys",
                    "ai_actions",
                    "ai_annotations",
                    "email_keyword",
                    "email_mailbox",
                    "emails",
                    "threads",
                    "mailboxes",
                    "states",
                ] {
                    tx.execute(
                        &format!("DELETE FROM {} WHERE account_id = ?1", table),
                        [id.to_string()],
                    )?;
                }
                tx.execute(
                    "DELETE FROM accounts WHERE id = ?1",
                    [id.to_string()],
                )?;
                tx.commit()?;

                // Delete blobs from filesystem
                for blob_id in blob_ids {
                    let _ = std::fs::remove_file(std::path::Path::new("blobs").join(&blob_id));
                }
                Ok(())
            })
            .await
    }

    /// Current modseq for one data type of an account (zero if never bumped).
    pub async fn state(
        &self,
        account_id: AccountId,
        data_type: DataType,
    ) -> Result<ModSeq, StorageError> {
        self.db
            .call(move |conn| {
                let modseq: Option<i64> = conn
                    .query_row(
                        "SELECT modseq FROM states WHERE account_id = ?1 AND data_type = ?2",
                        params![account_id.to_string(), data_type.as_str()],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(ModSeq(modseq.unwrap_or(0) as u64))
            })
            .await
    }

    /// Store a blob (encrypted, content-addressed) and record it in the
    /// database. Refcounts are managed by the rows that link to it.
    pub async fn put_blob(&self, plaintext: Vec<u8>) -> Result<BlobId, StorageError> {
        let blobs = self.blobs.clone();
        let size = plaintext.len() as i64;
        let id = tokio::task::spawn_blocking(move || blobs.put(&plaintext))
            .await
            .map_err(|_| StorageError::Closed)??;

        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO blobs (id, size, created_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT (id) DO NOTHING",
                    params![id.to_hex(), size, unix_now()],
                )?;
                Ok(())
            })
            .await?;
        Ok(id)
    }

    pub async fn get_blob(&self, id: BlobId) -> Result<Vec<u8>, StorageError> {
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || blobs.get(&id))
            .await
            .map_err(|_| StorageError::Closed)?
    }

    /// Clean shutdown: drains pending writes and checkpoints the WAL.
    pub fn close(self) {
        self.db.close();
    }

    /// Get queue statistics: (total pending, failed).
    pub async fn queue_stats(&self) -> Result<(u32, u32), StorageError> {
        self.db.call(|conn| {
            let total: u32 = conn.query_row(
                "SELECT COUNT(*) FROM queue WHERE status IN ('queued', 'failed')",
                [],
                |row| row.get(0),
            )?;
            let failed: u32 = conn.query_row(
                "SELECT COUNT(*) FROM queue WHERE status = 'failed'",
                [],
                |row| row.get(0),
            )?;
            Ok((total, failed))
        }).await
    }

    /// Check database integrity using PRAGMA integrity_check.
    pub async fn check_integrity(&self) -> Result<bool, StorageError> {
        self.db.call(|conn| {
            let mut stmt = conn.prepare("PRAGMA integrity_check")?;
            let rows = stmt.query_map([], |row| {
                row.get::<_, String>(0)
            })?;

            for row_result in rows {
                let message = row_result?;
                if message != "ok" {
                    tracing::warn!("database integrity issue: {}", message);
                    return Ok(false);
                }
            }
            Ok(true)
        }).await
    }
}

const DEFAULT_MAILBOXES: [(&str, &str, i64); 7] = [
    ("Inbox", "inbox", 0),
    ("Screener", "screener", 1),
    ("Drafts", "drafts", 2),
    ("Sent", "sent", 3),
    ("Archive", "archive", 4),
    ("Junk", "junk", 5),
    ("Trash", "trash", 6),
];

/// Bump and return the modseq for one data type, inside the caller's
/// transaction. Every mutation in this crate goes through here.
pub(crate) fn bump(
    conn: &Connection,
    account_id: AccountId,
    data_type: DataType,
) -> Result<ModSeq, StorageError> {
    let modseq: i64 = conn.query_row(
        "INSERT INTO states (account_id, data_type, modseq) VALUES (?1, ?2, 1)
         ON CONFLICT (account_id, data_type) DO UPDATE SET modseq = modseq + 1
         RETURNING modseq",
        params![account_id.to_string(), data_type.as_str()],
        |row| row.get(0),
    )?;
    Ok(ModSeq(modseq as u64))
}

pub(crate) fn row_to_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<Account> {
    let id: String = row.get(0)?;
    Ok(Account {
        id: id.parse().map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
        })?,
        email: row.get(1)?,
        display_name: row.get(2)?,
        created_at: row.get(3)?,
    })
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) async fn open(dir: &Path) -> (Storage, EventBus) {
        let events = EventBus::new(64);
        let storage = Storage::open(dir, events.clone()).expect("open");
        (storage, events)
    }

    #[tokio::test]
    async fn create_account_bumps_modseq_and_publishes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, events) = open(dir.path()).await;
        let mut rx = events.subscribe();

        let account = storage
            .create_account("Alice@Example.com", Some("Alice"))
            .await
            .expect("create");
        assert_eq!(
            account.email, "alice@example.com",
            "addresses normalize to lowercase"
        );

        let state = storage
            .state(account.id, DataType::Mailbox)
            .await
            .expect("state");
        assert_eq!(state, ModSeq(1));
        assert_eq!(
            storage
                .state(account.id, DataType::Email)
                .await
                .expect("state"),
            ModSeq(0)
        );

        let event = rx.recv().await.expect("event");
        match &*event {
            Event::StateChange {
                account_id,
                changed,
            } => {
                assert_eq!(*account_id, account.id);
                assert_eq!(changed, &[(DataType::Mailbox, ModSeq(1))]);
            }
            other => panic!("unexpected event {other:?}"),
        }

        let found = storage
            .account_by_email("alice@example.com")
            .await
            .expect("lookup");
        assert_eq!(found.as_ref(), Some(&account));

        storage.close();
    }

    #[tokio::test]
    async fn duplicate_account_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = open(dir.path()).await;

        storage
            .create_account("a@example.com", None)
            .await
            .expect("first");
        assert!(storage.create_account("A@example.com", None).await.is_err());
        storage.close();
    }

    #[tokio::test]
    async fn blob_round_trip_through_storage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = open(dir.path()).await;

        let body = b"Subject: hi\r\n\r\nbody".to_vec();
        let id = storage.put_blob(body.clone()).await.expect("put");
        assert_eq!(storage.get_blob(id).await.expect("get"), body);
        storage.close();
    }

    #[tokio::test]
    async fn reopen_preserves_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let account = {
            let (storage, _events) = open(dir.path()).await;
            let account = storage
                .create_account("keep@example.com", None)
                .await
                .expect("create");
            storage.close();
            account
        };

        let (storage, _events) = open(dir.path()).await;
        let found = storage.account(account.id).await.expect("lookup");
        assert_eq!(found, Some(account));
        storage.close();
    }

    #[tokio::test]
    async fn failed_ingest_does_not_advance_email_modseq() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = open(dir.path()).await;
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("create");

        let before = storage.state(account.id, DataType::Email).await.expect("state");
        assert_eq!(before, ModSeq(0), "starts at 0");

        // Ingest targeting a mailbox role that doesn't exist on this account.
        // The storage layer rejects with `Corrupt`, and any modseq bump inside
        // the same transaction must roll back (SQLite's atomic guarantee).
        let result = storage
            .ingest_email(account.id, b"From: a@x\r\n\r\nhello\r\n".to_vec(), "nonexistent_role", None)
            .await;
        assert!(result.is_err(), "ingest to missing role must fail");

        let after = storage.state(account.id, DataType::Email).await.expect("state");
        assert_eq!(
            after, before,
            "rolled-back ingest must leave modseq untouched (got {before:?} → {after:?})"
        );
        storage.close();
    }
}
