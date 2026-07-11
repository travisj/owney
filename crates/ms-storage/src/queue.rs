//! The durable outbound queue. One row per (message, recipient) so each
//! recipient retries independently. `ms-delivery` drives this; all SQL stays
//! here so the storage crate remains the single mutation path.

use ms_core::{AccountId, BlobId};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::error::StorageError;
use crate::{Storage, unix_now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueItem {
    pub id: Uuid,
    pub account_id: AccountId,
    pub blob_id: BlobId,
    pub mail_from: String,
    pub recipient: String,
    pub domain: String,
    pub attempts: u32,
    pub next_attempt: i64,
}

/// Outcome of one delivery attempt, decided by ms-delivery.
#[derive(Debug, Clone)]
pub enum AttemptOutcome {
    Delivered,
    /// Try again at `next_attempt` (unix seconds).
    Retry {
        error: String,
        next_attempt: i64,
    },
    /// Give up; a DSN is the caller's responsibility.
    Failed {
        error: String,
    },
}

impl Storage {
    /// Add one recipient of an outbound message to the queue.
    pub async fn enqueue(
        &self,
        account_id: AccountId,
        blob_id: BlobId,
        mail_from: &str,
        recipient: &str,
    ) -> Result<QueueItem, StorageError> {
        let domain = recipient
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_lowercase())
            .ok_or_else(|| StorageError::BadInput(format!("recipient {recipient} has no domain")))?;
        let item = QueueItem {
            id: Uuid::now_v7(),
            account_id,
            blob_id,
            mail_from: mail_from.to_owned(),
            recipient: recipient.to_owned(),
            domain,
            attempts: 0,
            next_attempt: unix_now(),
        };
        let insert = item.clone();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO queue
                       (id, account_id, blob_id, mail_from, recipient, domain,
                        attempts, next_attempt, status, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, 'queued', ?8, ?8)",
                    params![
                        insert.id.to_string(),
                        insert.account_id.to_string(),
                        insert.blob_id.to_hex(),
                        insert.mail_from,
                        insert.recipient,
                        insert.domain,
                        insert.next_attempt,
                        unix_now(),
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(item)
    }

    /// Atomically claim due items (status 'queued' → 'sending'), oldest
    /// first. The claim is what makes concurrent workers — including a CLI
    /// process next to the server — safe from double delivery.
    pub async fn due_queue_items(&self, limit: usize) -> Result<Vec<QueueItem>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "UPDATE queue SET status = 'sending', updated_at = ?1
                     WHERE id IN (
                        SELECT id FROM queue
                        WHERE status = 'queued' AND next_attempt <= ?1
                        ORDER BY next_attempt
                        LIMIT ?2
                     )
                     RETURNING id, account_id, blob_id, mail_from, recipient, domain,
                               attempts, next_attempt",
                )?;
                let rows = stmt
                    .query_map(params![unix_now(), limit as i64], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows.into_iter()
                    .map(
                        |(id, account, blob, mail_from, recipient, domain, attempts, next)| {
                            Ok(QueueItem {
                                id: id.parse().map_err(|_| {
                                    StorageError::Corrupt(format!("bad queue id {id}"))
                                })?,
                                account_id: account.parse().map_err(|_| {
                                    StorageError::Corrupt(format!("bad account id {account}"))
                                })?,
                                blob_id: blob.parse().map_err(|_| {
                                    StorageError::Corrupt(format!("bad blob id {blob}"))
                                })?,
                                mail_from,
                                recipient,
                                domain,
                                attempts: attempts as u32,
                                next_attempt: next,
                            })
                        },
                    )
                    .collect()
            })
            .await
    }

    /// Record the outcome of a delivery attempt.
    pub async fn record_attempt(
        &self,
        id: Uuid,
        outcome: &AttemptOutcome,
    ) -> Result<(), StorageError> {
        let (status, error, next_attempt) = match outcome {
            AttemptOutcome::Delivered => ("delivered", None, None),
            AttemptOutcome::Retry {
                error,
                next_attempt,
            } => ("queued", Some(error.clone()), Some(*next_attempt)),
            AttemptOutcome::Failed { error } => ("failed", Some(error.clone()), None),
        };
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE queue SET
                       status = ?2,
                       attempts = attempts + 1,
                       last_error = coalesce(?3, last_error),
                       next_attempt = coalesce(?4, next_attempt),
                       updated_at = ?5
                     WHERE id = ?1",
                    params![id.to_string(), status, error, next_attempt, unix_now()],
                )?;
                Ok(())
            })
            .await
    }

    /// Recover claims abandoned by a crashed or restarted worker.
    pub async fn reset_stale_claims(&self) -> Result<usize, StorageError> {
        self.db
            .call(move |conn| {
                let reset = conn.execute(
                    "UPDATE queue SET status = 'queued', updated_at = ?1
                     WHERE status = 'sending'",
                    [unix_now()],
                )?;
                Ok(reset)
            })
            .await
    }

    /// All non-terminal queue rows, for the admin queue view.
    pub async fn queue_overview(
        &self,
    ) -> Result<Vec<(String, String, String, u32, i64, Option<String>)>, StorageError> {
        self.db
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, recipient, status, attempts, next_attempt, last_error
                     FROM queue
                     WHERE status IN ('queued', 'sending')
                     ORDER BY next_attempt",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)? as u32,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    /// One queue row, for tests and the future admin queue view.
    pub async fn queue_status(
        &self,
        id: Uuid,
    ) -> Result<Option<(String, u32, Option<String>)>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT status, attempts, last_error FROM queue WHERE id = ?1",
                        [id.to_string()],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)? as u32,
                                row.get::<_, Option<String>>(2)?,
                            ))
                        },
                    )
                    .optional()?)
            })
            .await
    }
}
