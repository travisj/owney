//! Server-added email attributes: structured data detectors attach to a
//! message after ingest (unsubscribe info, calendar invites, summaries, …).
//!
//! At most one attribute per (email, kind); re-detection upserts the content
//! but never clears a client's dismissal. Every write bumps the Email modseq
//! and publishes `StateChange`, so attributes surface through the ordinary
//! `Email/get` + `Email/changes` + push cycle.

use owney_core::{AccountId, DataType, EmailId};
use rusqlite::params;
use uuid::Uuid;

use crate::error::StorageError;
use crate::{Storage, bump, unix_now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAttribute {
    pub kind: String,
    /// JSON payload; shape is per-kind.
    pub content: String,
    pub dismissed_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Storage {
    /// Upsert one attribute on an email the account owns. Dismissal is
    /// sticky: re-detection updates `content` but leaves `dismissed_at`.
    pub async fn set_email_attribute(
        &self,
        account_id: AccountId,
        email_id: EmailId,
        kind: &str,
        content: &str,
    ) -> Result<(), StorageError> {
        let (kind, content) = (kind.to_owned(), content.to_owned());
        let changed = self
            .db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let id = email_id.to_string();
                owned_email_check(&tx, account_id, &id)?;

                let now = unix_now();
                tx.execute(
                    "INSERT INTO email_attributes
                       (id, account_id, email_id, kind, content, dismissed_at, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?6)
                     ON CONFLICT (email_id, kind) DO UPDATE SET
                       content = excluded.content,
                       updated_at = excluded.updated_at",
                    params![
                        Uuid::now_v7().to_string(),
                        account_id.to_string(),
                        id,
                        kind,
                        content,
                        now,
                    ],
                )?;

                let seq = bump(&tx, account_id, DataType::Email)?;
                tx.execute(
                    "UPDATE emails SET updated_modseq = ?2 WHERE id = ?1",
                    params![email_id.to_string(), seq.0 as i64],
                )?;
                tx.commit()?;
                Ok(vec![(DataType::Email, seq)])
            })
            .await?;

        self.events.publish(owney_events::Event::StateChange {
            account_id,
            changed,
        });
        Ok(())
    }

    /// All attributes on one email, dismissed included (clients decide how
    /// to render dismissed ones).
    pub async fn list_email_attributes(
        &self,
        account_id: AccountId,
        email_id: EmailId,
    ) -> Result<Vec<EmailAttribute>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT kind, content, dismissed_at, created_at, updated_at
                     FROM email_attributes
                     WHERE account_id = ?1 AND email_id = ?2
                     ORDER BY kind",
                )?;
                let rows = stmt
                    .query_map(
                        params![account_id.to_string(), email_id.to_string()],
                        |row| {
                            Ok(EmailAttribute {
                                kind: row.get(0)?,
                                content: row.get(1)?,
                                dismissed_at: row.get(2)?,
                                created_at: row.get(3)?,
                                updated_at: row.get(4)?,
                            })
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    /// Owner-only: mark an attribute dismissed (idempotent on an already
    /// dismissed one is an error so clients notice stale state).
    pub async fn dismiss_email_attribute(
        &self,
        account_id: AccountId,
        email_id: EmailId,
        kind: &str,
    ) -> Result<(), StorageError> {
        let kind = kind.to_owned();
        let changed = self
            .db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let id = email_id.to_string();
                owned_email_check(&tx, account_id, &id)?;

                let now = unix_now();
                let updated = tx.execute(
                    "UPDATE email_attributes
                     SET dismissed_at = ?4, updated_at = ?4
                     WHERE account_id = ?1 AND email_id = ?2 AND kind = ?3
                       AND dismissed_at IS NULL",
                    params![account_id.to_string(), id, kind, now],
                )?;
                if updated == 0 {
                    return Err(StorageError::BadInput(format!(
                        "no active attribute {kind} on email {id}"
                    )));
                }

                let seq = bump(&tx, account_id, DataType::Email)?;
                tx.execute(
                    "UPDATE emails SET updated_modseq = ?2 WHERE id = ?1",
                    params![email_id.to_string(), seq.0 as i64],
                )?;
                tx.commit()?;
                Ok(vec![(DataType::Email, seq)])
            })
            .await?;

        self.events.publish(owney_events::Event::StateChange {
            account_id,
            changed,
        });
        Ok(())
    }
}

/// Reject writes against emails the account does not own; the authz boundary
/// for every attribute mutation.
fn owned_email_check(
    tx: &rusqlite::Transaction<'_>,
    account_id: AccountId,
    email_id: &str,
) -> Result<(), StorageError> {
    let owned: bool = tx
        .query_row(
            "SELECT 1 FROM emails WHERE account_id = ?1 AND id = ?2",
            params![account_id.to_string(), email_id],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if owned {
        Ok(())
    } else {
        Err(StorageError::NotAuthorized)
    }
}

#[cfg(test)]
mod tests {
    use owney_core::{DataType, ModSeq};
    use owney_events::Event;

    use super::*;
    use crate::tests::open;

    async fn harness() -> (
        tempfile::TempDir,
        Storage,
        owney_events::EventBus,
        AccountId,
        EmailId,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, events) = open(dir.path()).await;
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");
        let ingested = storage
            .ingest_email(
                account.id,
                b"Subject: hi\r\nMessage-ID: <a@x>\r\n\r\nbody".to_vec(),
                "inbox",
                None,
            )
            .await
            .expect("ingest");
        (dir, storage, events, account.id, ingested.id)
    }

    #[tokio::test]
    async fn upsert_replaces_content_and_keeps_one_row() {
        let (_dir, storage, _events, account, email) = harness().await;

        storage
            .set_email_attribute(account, email, "summary", "\"first\"")
            .await
            .expect("set");
        storage
            .set_email_attribute(account, email, "summary", "\"second\"")
            .await
            .expect("set again");

        let attrs = storage
            .list_email_attributes(account, email)
            .await
            .expect("list");
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].kind, "summary");
        assert_eq!(attrs[0].content, "\"second\"");
        assert_eq!(attrs[0].dismissed_at, None);
        storage.close();
    }

    #[tokio::test]
    async fn write_bumps_email_modseq_and_publishes() {
        let (_dir, storage, events, account, email) = harness().await;
        let before = storage
            .state(account, DataType::Email)
            .await
            .expect("state");
        let mut rx = events.subscribe();

        storage
            .set_email_attribute(account, email, "unsubscribe", "{}")
            .await
            .expect("set");

        let after = storage
            .state(account, DataType::Email)
            .await
            .expect("state");
        assert_eq!(after, ModSeq(before.0 + 1));

        let changes = storage
            .changes_since(account, DataType::Email, before.0, 64)
            .await
            .expect("changes");
        assert_eq!(changes.updated, vec![email.to_string()]);

        let event = rx.recv().await.expect("event");
        match &*event {
            Event::StateChange {
                account_id,
                changed,
            } => {
                assert_eq!(*account_id, account);
                assert_eq!(changed, &[(DataType::Email, after)]);
            }
            other => panic!("unexpected event {other:?}"),
        }
        storage.close();
    }

    #[tokio::test]
    async fn dismiss_sets_flag_and_survives_redetection() {
        let (_dir, storage, _events, account, email) = harness().await;

        storage
            .set_email_attribute(account, email, "calendarInvite", "{\"uid\":\"1\"}")
            .await
            .expect("set");
        storage
            .dismiss_email_attribute(account, email, "calendarInvite")
            .await
            .expect("dismiss");

        // Re-detection updates content but must not clear the dismissal.
        storage
            .set_email_attribute(account, email, "calendarInvite", "{\"uid\":\"2\"}")
            .await
            .expect("redetect");

        let attrs = storage
            .list_email_attributes(account, email)
            .await
            .expect("list");
        assert_eq!(attrs[0].content, "{\"uid\":\"2\"}");
        assert!(attrs[0].dismissed_at.is_some());

        // Dismissing again (already dismissed) or a missing kind errors.
        assert!(matches!(
            storage
                .dismiss_email_attribute(account, email, "calendarInvite")
                .await,
            Err(StorageError::BadInput(_))
        ));
        assert!(matches!(
            storage
                .dismiss_email_attribute(account, email, "nope")
                .await,
            Err(StorageError::BadInput(_))
        ));
        storage.close();
    }

    #[tokio::test]
    async fn cross_account_access_is_rejected() {
        let (_dir, storage, _events, alice, email) = harness().await;
        let mallory = storage
            .create_account("mallory@example.com", None)
            .await
            .expect("account")
            .id;

        storage
            .set_email_attribute(alice, email, "summary", "\"secret\"")
            .await
            .expect("set");

        assert!(matches!(
            storage
                .set_email_attribute(mallory, email, "summary", "\"evil\"")
                .await,
            Err(StorageError::NotAuthorized)
        ));
        assert!(matches!(
            storage
                .dismiss_email_attribute(mallory, email, "summary")
                .await,
            Err(StorageError::NotAuthorized)
        ));
        assert!(
            storage
                .list_email_attributes(mallory, email)
                .await
                .expect("list")
                .is_empty()
        );

        // Alice's attribute is untouched and still active.
        let attrs = storage
            .list_email_attributes(alice, email)
            .await
            .expect("list");
        assert_eq!(attrs[0].content, "\"secret\"");
        assert_eq!(attrs[0].dismissed_at, None);
        storage.close();
    }
}
