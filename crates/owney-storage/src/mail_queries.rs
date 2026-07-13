//! Read/update queries backing the JMAP mail data types. All the SQL for
//! Mailbox/Email/Thread get/query/changes lives here; ms-jmap-mail turns the
//! rows into RFC 8621 JSON.

use owney_core::{AccountId, DataType, EmailId, MailboxId, ModSeq, ThreadId};
use owney_events::Event;
use rusqlite::params;

use crate::error::StorageError;
use crate::{Storage, bump};

#[derive(Debug, Clone)]
pub struct MailboxRow {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub role: Option<String>,
    pub sort_order: i64,
    pub total_emails: u64,
    pub unread_emails: u64,
    pub updated_modseq: u64,
}

#[derive(Debug, Clone)]
pub struct EmailRow {
    pub id: String,
    pub thread_id: String,
    pub blob_id: String,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub from_addr: Option<String>,
    pub received_at: i64,
    pub size: u64,
    pub mailbox_ids: Vec<String>,
    pub keywords: Vec<String>,
    /// PGP disposition JSON (`emails.pgp_status`), when the message was
    /// encrypted or signed.
    pub pgp_status: Option<String>,
    /// Chat mode flag: true if email was submitted with chat intent.
    pub chat_mode: bool,
}

/// Result of a `/changes` computation for one data type.
#[derive(Debug, Clone)]
pub struct ChangesResult {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub new_state: ModSeq,
    pub has_more: bool,
}

impl Storage {
    pub async fn mailboxes(&self, account_id: AccountId) -> Result<Vec<MailboxRow>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT m.id, m.parent_id, m.name, m.role, m.sort_order, m.updated_modseq,
                       (SELECT count(*) FROM email_mailbox em WHERE em.mailbox_id = m.id),
                       (SELECT count(*) FROM email_mailbox em
                        WHERE em.mailbox_id = m.id
                          AND NOT EXISTS (SELECT 1 FROM email_keyword k
                                          WHERE k.email_id = em.email_id AND k.keyword = '$seen'))
                     FROM mailboxes m WHERE m.account_id = ?1
                     ORDER BY m.sort_order, m.name",
                )?;
                let rows = stmt
                    .query_map([account_id.to_string()], |row| {
                        Ok(MailboxRow {
                            id: row.get(0)?,
                            parent_id: row.get(1)?,
                            name: row.get(2)?,
                            role: row.get(3)?,
                            sort_order: row.get(4)?,
                            updated_modseq: row.get::<_, i64>(5)? as u64,
                            total_emails: row.get::<_, i64>(6)? as u64,
                            unread_emails: row.get::<_, i64>(7)? as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    pub async fn emails_by_ids(
        &self,
        account_id: AccountId,
        ids: Vec<EmailId>,
    ) -> Result<Vec<EmailRow>, StorageError> {
        self.db
            .call(move |conn| {
                let mut out = Vec::with_capacity(ids.len());
                let mut email_stmt = conn.prepare(
                    "SELECT id, thread_id, blob_id, message_id, subject, from_addr,
                            received_at, size, pgp_status, chat_mode
                     FROM emails WHERE account_id = ?1 AND id = ?2",
                )?;
                let mut mailbox_stmt =
                    conn.prepare("SELECT mailbox_id FROM email_mailbox WHERE email_id = ?1")?;
                let mut keyword_stmt =
                    conn.prepare("SELECT keyword FROM email_keyword WHERE email_id = ?1")?;

                for id in ids {
                    let id_string = id.to_string();
                    let row =
                        email_stmt.query_row(params![account_id.to_string(), id_string], |row| {
                            Ok(EmailRow {
                                id: row.get(0)?,
                                thread_id: row.get(1)?,
                                blob_id: row.get(2)?,
                                message_id: row.get(3)?,
                                subject: row.get(4)?,
                                from_addr: row.get(5)?,
                                received_at: row.get(6)?,
                                size: row.get::<_, i64>(7)? as u64,
                                mailbox_ids: Vec::new(),
                                keywords: Vec::new(),
                                pgp_status: row.get(8)?,
                                chat_mode: row.get::<_, i64>(9)? != 0,
                            })
                        });
                    let mut row = match row {
                        Ok(row) => row,
                        Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                        Err(err) => return Err(err.into()),
                    };
                    row.mailbox_ids = mailbox_stmt
                        .query_map([&id_string], |r| r.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    row.keywords = keyword_stmt
                        .query_map([&id_string], |r| r.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    out.push(row);
                }
                Ok(out)
            })
            .await
    }

    /// Email ids newest-first, optionally restricted to one mailbox.
    /// Returns (ids, total matching, current Email state).
    pub async fn query_emails(
        &self,
        account_id: AccountId,
        in_mailbox: Option<String>,
        position: usize,
        limit: usize,
    ) -> Result<(Vec<String>, u64, ModSeq), StorageError> {
        self.db
            .call(move |conn| {
                let account = account_id.to_string();
                let (ids, total): (Vec<String>, i64) = match &in_mailbox {
                    Some(mailbox_id) => {
                        let mut stmt = conn.prepare(
                            "SELECT e.id FROM emails e
                             JOIN email_mailbox em ON em.email_id = e.id
                             WHERE e.account_id = ?1 AND em.mailbox_id = ?2
                             ORDER BY e.received_at DESC, e.id DESC
                             LIMIT ?3 OFFSET ?4",
                        )?;
                        let ids = stmt
                            .query_map(
                                params![account, mailbox_id, limit as i64, position as i64],
                                |r| r.get(0),
                            )?
                            .collect::<Result<Vec<_>, _>>()?;
                        let total = conn.query_row(
                            "SELECT count(*) FROM emails e
                             JOIN email_mailbox em ON em.email_id = e.id
                             WHERE e.account_id = ?1 AND em.mailbox_id = ?2",
                            params![account, mailbox_id],
                            |r| r.get(0),
                        )?;
                        (ids, total)
                    }
                    None => {
                        let mut stmt = conn.prepare(
                            "SELECT id FROM emails WHERE account_id = ?1
                             ORDER BY received_at DESC, id DESC
                             LIMIT ?2 OFFSET ?3",
                        )?;
                        let ids = stmt
                            .query_map(params![account, limit as i64, position as i64], |r| {
                                r.get(0)
                            })?
                            .collect::<Result<Vec<_>, _>>()?;
                        let total = conn.query_row(
                            "SELECT count(*) FROM emails WHERE account_id = ?1",
                            [&account],
                            |r| r.get(0),
                        )?;
                        (ids, total)
                    }
                };
                let state: Option<i64> = conn
                    .query_row(
                        "SELECT modseq FROM states WHERE account_id = ?1 AND data_type = 'Email'",
                        [&account],
                        |r| r.get(0),
                    )
                    .ok();
                Ok((ids, total as u64, ModSeq(state.unwrap_or(0) as u64)))
            })
            .await
    }


    /// Ids created/updated since a state token, for `Foo/changes`.
    pub async fn changes_since(
        &self,
        account_id: AccountId,
        data_type: DataType,
        since: u64,
        max: usize,
    ) -> Result<ChangesResult, StorageError> {
        let table = match data_type {
            DataType::Email => "emails",
            DataType::Mailbox => "mailboxes",
            DataType::Thread => "threads",
            DataType::EmailSubmission => {
                return Err(StorageError::Corrupt(
                    "submission changes not tracked yet".into(),
                ));
            }
            // `DataType` is `#[non_exhaustive]`, so new variants added by
            // future protocol work (e.g. per-identity `Identity`) fall here
            // and produce a clear error at the storage layer rather than
            // panicking on a missing arm.
            _ => {
                return Err(StorageError::Corrupt(format!(
                    "changes_since not implemented for {data_type}"
                )));
            }
        };
        self.db
            .call(move |conn| {
                let account = account_id.to_string();
                // `table` is derived from the `DataType` match above, so its
                // value is bounded to one of three `&'static str` constants.
                // The `debug_assert!` below is a defense-in-depth check — if
                // someone adds a new arm to the `match` without updating this
                // assertion, CI will fail before the SQL is interpolated.
                debug_assert!(
                    matches!(table, "emails" | "mailboxes" | "threads"),
                    "changes_since table {table:?} is not in the allow-list"
                );
                let mut stmt = conn.prepare(&format!(
                    "SELECT id, created_modseq FROM {table}
                     WHERE account_id = ?1 AND updated_modseq > ?2
                     ORDER BY updated_modseq
                     LIMIT ?3"
                ))?;
                let rows: Vec<(String, i64)> = stmt
                    .query_map(params![account, since as i64, (max + 1) as i64], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                let has_more = rows.len() > max;
                let mut created = Vec::new();
                let mut updated = Vec::new();
                for (id, created_modseq) in rows.into_iter().take(max) {
                    if created_modseq as u64 > since {
                        created.push(id);
                    } else {
                        updated.push(id);
                    }
                }

                let state: Option<i64> = conn
                    .query_row(
                        "SELECT modseq FROM states WHERE account_id = ?1 AND data_type = ?2",
                        params![account, data_type.as_str()],
                        |r| r.get(0),
                    )
                    .ok();
                Ok(ChangesResult {
                    created,
                    updated,
                    new_state: ModSeq(state.unwrap_or(0) as u64),
                    has_more,
                })
            })
            .await
    }

    /// Email ids per thread, arrival order.
    pub async fn thread_emails(
        &self,
        account_id: AccountId,
        thread_ids: Vec<ThreadId>,
    ) -> Result<Vec<(String, Vec<String>)>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id FROM emails
                     WHERE account_id = ?1 AND thread_id = ?2
                     ORDER BY received_at, id",
                )?;
                let mut out = Vec::with_capacity(thread_ids.len());
                for thread_id in thread_ids {
                    let ids = stmt
                        .query_map(
                            params![account_id.to_string(), thread_id.to_string()],
                            |r| r.get::<_, String>(0),
                        )?
                        .collect::<Result<Vec<_>, _>>()?;
                    if !ids.is_empty() {
                        out.push((thread_id.to_string(), ids));
                    }
                }
                Ok(out)
            })
            .await
    }

    /// Apply a JMAP `Email/set` update: replace keywords and/or mailbox
    /// placement. Bumps Email + Mailbox modseqs, publishes the change.
    pub async fn update_email(
        &self,
        account_id: AccountId,
        email_id: EmailId,
        keywords: Option<Vec<String>>,
        mailbox_ids: Option<Vec<MailboxId>>,
    ) -> Result<(), StorageError> {
        let changed = self
            .db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let account = account_id.to_string();
                let id = email_id.to_string();

                let exists: bool = tx
                    .query_row(
                        "SELECT 1 FROM emails WHERE account_id = ?1 AND id = ?2",
                        params![account, id],
                        |_| Ok(true),
                    )
                    .unwrap_or(false);
                if !exists {
                    return Err(StorageError::Corrupt(format!("no email {id}")));
                }

                if let Some(keywords) = &keywords {
                    tx.execute("DELETE FROM email_keyword WHERE email_id = ?1", [&id])?;
                    for keyword in keywords {
                        tx.execute(
                            "INSERT OR IGNORE INTO email_keyword (email_id, keyword)
                             VALUES (?1, ?2)",
                            params![id, keyword.to_lowercase()],
                        )?;
                    }
                }
                if let Some(mailbox_ids) = &mailbox_ids {
                    if mailbox_ids.is_empty() {
                        return Err(StorageError::Corrupt(
                            "an email must belong to at least one mailbox".into(),
                        ));
                    }
                    // Every target mailbox must exist and belong to the account.
                    for mailbox_id in mailbox_ids {
                        let ok: bool = tx
                            .query_row(
                                "SELECT 1 FROM mailboxes WHERE account_id = ?1 AND id = ?2",
                                params![account, mailbox_id.to_string()],
                                |_| Ok(true),
                            )
                            .unwrap_or(false);
                        if !ok {
                            return Err(StorageError::Corrupt(format!("no mailbox {mailbox_id}")));
                        }
                    }
                    tx.execute("DELETE FROM email_mailbox WHERE email_id = ?1", [&id])?;
                    for mailbox_id in mailbox_ids {
                        tx.execute(
                            "INSERT INTO email_mailbox (email_id, mailbox_id) VALUES (?1, ?2)",
                            params![id, mailbox_id.to_string()],
                        )?;
                    }
                }

                let email_seq = bump(&tx, account_id, DataType::Email)?;
                let mailbox_seq = bump(&tx, account_id, DataType::Mailbox)?;
                tx.execute(
                    "UPDATE emails SET updated_modseq = ?2 WHERE id = ?1",
                    params![id, email_seq.0 as i64],
                )?;
                tx.commit()?;
                Ok(vec![
                    (DataType::Email, email_seq),
                    (DataType::Mailbox, mailbox_seq),
                ])
            })
            .await?;

        self.events.publish(Event::StateChange {
            account_id,
            changed,
        });
        Ok(())
    }

    /// Filter a list of email IDs by mailbox and keywords.
    /// Used by Email/query when text search results need further filtering.
    pub async fn filter_emails(
        &self,
        account_id: AccountId,
        email_ids: Vec<EmailId>,
        in_mailbox: Option<&str>,
        has_keyword: Option<&str>,
        not_keyword: Option<&str>,
    ) -> Result<Vec<EmailId>, StorageError> {
        if email_ids.is_empty() {
            return Ok(Vec::new());
        }

        let in_mailbox = in_mailbox.map(str::to_string);
        let has_keyword = has_keyword.map(str::to_string);
        let not_keyword = not_keyword.map(str::to_string);

        self.db
            .call(move |conn| {
                let account = account_id.to_string();

                // Build the WHERE clause based on filters
                let mut where_parts = vec!["e.account_id = ?1".to_string()];
                let email_id_strings: Vec<String> =
                    email_ids.iter().map(|id| format!("'{}'", id)).collect();
                where_parts.push(format!("e.id IN ({})", email_id_strings.join(",")));

                if let Some(ref mailbox_id) = in_mailbox {
                    where_parts.push(format!(
                        "EXISTS (SELECT 1 FROM email_mailbox em WHERE em.email_id = e.id AND em.mailbox_id = '{}')",
                        mailbox_id
                    ));
                }

                if let Some(ref keyword) = has_keyword {
                    where_parts.push(format!(
                        "EXISTS (SELECT 1 FROM email_keyword ek WHERE ek.email_id = e.id AND ek.keyword = '{}')",
                        keyword
                    ));
                }

                if let Some(ref keyword) = not_keyword {
                    where_parts.push(format!(
                        "NOT EXISTS (SELECT 1 FROM email_keyword ek WHERE ek.email_id = e.id AND ek.keyword = '{}')",
                        keyword
                    ));
                }

                let where_clause = where_parts.join(" AND ");
                let sql = format!(
                    "SELECT e.id FROM emails e WHERE {} ORDER BY e.received_at DESC, e.id DESC",
                    where_clause
                );

                let mut stmt = conn.prepare(&sql)?;
                let ids: Vec<EmailId> = stmt
                    .query_map([&account], |r| {
                        let id_str: String = r.get(0)?;
                        Ok(id_str.parse().unwrap_or_else(|_| EmailId::new()))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(ids)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn harness(tmp: &tempfile::TempDir) -> (crate::Storage, owney_events::EventBus) {
        crate::tests::open(tmp.path()).await
    }

    #[tokio::test]
    async fn changes_since_buckets_created_vs_updated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create");

        let initial = storage
            .changes_since(acct.id, DataType::Email, 0, 256)
            .await
            .expect("changes");
        assert_eq!(initial.created.len(), 0);
        assert_eq!(initial.updated.len(), 0);
        assert!(!initial.has_more);

        let raw1 = b"From: a@x\r\nMessage-ID: <m1@x>\r\nSubject: one\r\n\r\none\r\n".to_vec();
        let raw2 = b"From: b@x\r\nMessage-ID: <m2@x>\r\nSubject: two\r\n\r\ntwo\r\n".to_vec();
        let id1 = storage.ingest_email(acct.id, raw1, "inbox", None).await.expect("ingest1").id;
        let id2 = storage.ingest_email(acct.id, raw2, "inbox", None).await.expect("ingest2").id;

        let state_after_ingest = storage.state(acct.id, DataType::Email).await.expect("state");
        let changes = storage
            .changes_since(acct.id, DataType::Email, 0, 256)
            .await
            .expect("changes");
        assert_eq!(changes.created.len(), 2, "two new emails = created");
        assert_eq!(changes.updated.len(), 0);
        assert!(changes.created.contains(&id1.to_string()));
        assert!(changes.created.contains(&id2.to_string()));
        assert_eq!(changes.new_state, state_after_ingest);

        let post_create_state = state_after_ingest;
        storage
            .update_email(acct.id, id1, Some(vec!["$seen".to_owned()]), None)
            .await
            .expect("update");

        // From the *initial* state (since=0), id1 was created in the window
        // so it lives in `created`. RFC 8620: rows created and then updated
        // in the same window are still `created` (created_modseq ≤ since is
        // the bucket discriminator, and created_modseq < updated_modseq for
        // any newly-created row).
        let all_changes = storage
            .changes_since(acct.id, DataType::Email, 0, 256)
            .await
            .expect("changes");
        assert_eq!(all_changes.created.len(), 2, "both emails were created in the window");
        assert!(all_changes.created.contains(&id1.to_string()));
        assert_eq!(
            all_changes.updated.len(),
            0,
            "re-checking from since=0: no row was created strictly before the window"
        );

        // From `post_create_state` (modseq value captured after the two ingests
        // but before the update), id1 is now an update.
        let tail = storage
            .changes_since(acct.id, DataType::Email, post_create_state.0, 256)
            .await
            .expect("tail");
        assert_eq!(tail.created.len(), 0, "no new creates since post-create");
        assert_eq!(tail.updated.len(), 1);
        assert_eq!(tail.updated[0], id1.to_string());

        storage.close();
    }

    #[tokio::test]
    async fn changes_since_has_more_pages_correctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create");

        for i in 0..5 {
            let raw = format!(
                "From: a@x\r\nMessage-ID: <m{i}@x>\r\nSubject: {i}\r\n\r\nbody {i}\r\n"
            ).into_bytes();
            storage
                .ingest_email(acct.id, raw, "inbox", None)
                .await
                .expect("ingest");
        }

        let page1 = storage
            .changes_since(acct.id, DataType::Email, 0, 2)
            .await
            .expect("page1");
        assert_eq!(page1.created.len(), 2);
        assert!(page1.has_more, "5 items with max=2 → has_more");
        assert!(page1.new_state.0 > 0);

        let full = storage
            .changes_since(acct.id, DataType::Email, 0, 256)
            .await
            .expect("full");
        assert_eq!(full.created.len(), 5);
        assert!(!full.has_more);

        storage.close();
    }
}
