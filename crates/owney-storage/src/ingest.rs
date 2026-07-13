//! Message ingestion: raw RFC 5322 bytes → encrypted blob + Email row +
//! thread linkage + mailbox placement, in one transaction, with the modseq
//! bumps and `StateChange` event every mutation owes the rest of the system.
//!
//! Used by inbound SMTP (into Inbox/Screener) and, later, by outbound
//! submission (into Sent) so sent mail is searchable and AI-visible through
//! the exact same path.

use owney_core::{AccountId, BlobId, DataType, EmailId, ThreadId};
use owney_events::Event;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StorageError;
use crate::{Storage, unix_now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedEmail {
    pub id: EmailId,
    pub thread_id: ThreadId,
    pub blob_id: BlobId,
}

/// Summary row for listings (CLI now, JMAP `Email/query` later).
#[derive(Debug, Clone)]
pub struct EmailSummary {
    pub id: EmailId,
    pub thread_id: ThreadId,
    pub from_addr: Option<String>,
    pub subject: Option<String>,
    pub received_at: i64,
    pub size: u64,
    /// Serialized `AuthVerdict` JSON (inbound mail only).
    pub auth_results: Option<String>,
}

/// Metadata pulled out of the raw message before storage. Parsing is
/// best-effort: a message that defeats the parser is still stored raw.
#[derive(Debug, Default)]
struct ParsedMeta {
    message_id: Option<String>,
    subject: Option<String>,
    from_addr: Option<String>,
    /// Message-IDs from References + In-Reply-To, used for threading.
    references: Vec<String>,
}

fn parse_meta(raw: &[u8]) -> ParsedMeta {
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else {
        return ParsedMeta::default();
    };
    let mut references: Vec<String> = message
        .references()
        .as_text_list()
        .map(|refs| refs.iter().map(|r| r.to_string()).collect())
        .unwrap_or_default();
    if let Some(irt) = message.in_reply_to().as_text() {
        references.push(irt.to_string());
    }
    ParsedMeta {
        message_id: message.message_id().map(str::to_owned),
        subject: message.subject().map(str::to_owned),
        from_addr: message
            .from()
            .and_then(|from| from.first())
            .and_then(|addr| addr.address())
            .map(str::to_owned),
        references,
    }
}

/// Where an ingested message lands.
#[derive(Debug, Clone)]
pub enum MailboxTarget {
    /// A role mailbox (`"inbox"`, `"sent"`, `"drafts"`, ...).
    Role(&'static str),
    /// A specific mailbox by id (JMAP `Email/set` create).
    Id(owney_core::MailboxId),
}

impl Storage {
    /// Ingest a raw message into a role mailbox. `auth_results` is the
    /// serialized `AuthVerdict` for inbound mail (None for local messages).
    pub async fn ingest_email(
        &self,
        account_id: AccountId,
        raw: Vec<u8>,
        mailbox_role: &'static str,
        auth_results: Option<String>,
    ) -> Result<IngestedEmail, StorageError> {
        self.ingest_email_into(
            account_id,
            raw,
            MailboxTarget::Role(mailbox_role),
            auth_results,
            false,
        )
        .await
    }

    /// Ingest a raw message with explicit chat_mode flag.
    pub async fn ingest_email_with_chat(
        &self,
        account_id: AccountId,
        raw: Vec<u8>,
        mailbox_role: &'static str,
        auth_results: Option<String>,
        chat_mode: bool,
    ) -> Result<IngestedEmail, StorageError> {
        self.ingest_email_into(
            account_id,
            raw,
            MailboxTarget::Role(mailbox_role),
            auth_results,
            chat_mode,
        )
        .await
    }

    /// Ingest a raw message into an arbitrary mailbox.
    pub async fn ingest_email_into(
        &self,
        account_id: AccountId,
        raw: Vec<u8>,
        target: MailboxTarget,
        auth_results: Option<String>,
        chat_mode: bool,
    ) -> Result<IngestedEmail, StorageError> {
        let meta = parse_meta(&raw);
        let size = raw.len() as u64;
        let blob_id = self.put_blob(raw).await?;
        let email_id = EmailId::new();

        let (ingested, changed) = self
            .db
            .call(move |conn| {
                let tx = conn.transaction()?;

                let mailbox_id: String = match &target {
                    MailboxTarget::Role(role) => tx
                        .query_row(
                            "SELECT id FROM mailboxes WHERE account_id = ?1 AND role = ?2",
                            params![account_id.to_string(), role],
                            |row| row.get(0),
                        )
                        .optional()?
                        .ok_or_else(|| {
                            StorageError::Corrupt(format!(
                                "account {account_id} has no {role} mailbox"
                            ))
                        })?,
                    MailboxTarget::Id(id) => tx
                        .query_row(
                            "SELECT id FROM mailboxes WHERE account_id = ?1 AND id = ?2",
                            params![account_id.to_string(), id.to_string()],
                            |row| row.get(0),
                        )
                        .optional()?
                        .ok_or_else(|| StorageError::Corrupt(format!("no mailbox {id}")))?,
                };

                let thread_id = resolve_thread(&tx, account_id, &meta)?;

                let email_seq = crate::bump(&tx, account_id, DataType::Email)?;
                let thread_seq = crate::bump(&tx, account_id, DataType::Thread)?;
                let mailbox_seq = crate::bump(&tx, account_id, DataType::Mailbox)?;

                let (thread_id, is_new_thread) = match thread_id {
                    Some(existing) => (existing, false),
                    None => (ThreadId::new(), true),
                };
                if is_new_thread {
                    tx.execute(
                        "INSERT INTO threads (id, account_id, created_modseq, updated_modseq)
                         VALUES (?1, ?2, ?3, ?3)",
                        params![
                            thread_id.to_string(),
                            account_id.to_string(),
                            thread_seq.0 as i64
                        ],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE threads SET updated_modseq = ?2 WHERE id = ?1",
                        params![thread_id.to_string(), thread_seq.0 as i64],
                    )?;
                }

                tx.execute(
                    "INSERT INTO emails
                       (id, account_id, thread_id, blob_id, message_id, subject,
                        from_addr, received_at, size, created_modseq, updated_modseq,
                        auth_results, chat_mode)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?12)",
                    params![
                        email_id.to_string(),
                        account_id.to_string(),
                        thread_id.to_string(),
                        blob_id.to_hex(),
                        meta.message_id,
                        meta.subject,
                        meta.from_addr,
                        unix_now(),
                        size as i64,
                        email_seq.0 as i64,
                        auth_results,
                        if chat_mode { 1 } else { 0 },
                    ],
                )?;
                tx.execute(
                    "INSERT INTO email_mailbox (email_id, mailbox_id) VALUES (?1, ?2)",
                    params![email_id.to_string(), mailbox_id],
                )?;
                tx.execute(
                    "UPDATE blobs SET refcount = refcount + 1 WHERE id = ?1",
                    [blob_id.to_hex()],
                )?;

                tx.commit()?;

                let changed = vec![
                    (DataType::Email, email_seq),
                    (DataType::Thread, thread_seq),
                    (DataType::Mailbox, mailbox_seq),
                ];
                Ok((
                    IngestedEmail {
                        id: email_id,
                        thread_id,
                        blob_id,
                    },
                    changed,
                ))
            })
            .await?;

        self.events.publish(Event::StateChange {
            account_id,
            changed,
        });
        Ok(ingested)
    }

    /// Recent messages in a role mailbox, newest first.
    pub async fn list_mailbox(
        &self,
        account_id: AccountId,
        mailbox_role: &str,
        limit: usize,
    ) -> Result<Vec<EmailSummary>, StorageError> {
        let mailbox_role = mailbox_role.to_owned();
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT e.id, e.thread_id, e.from_addr, e.subject, e.received_at, e.size,
                            e.auth_results
                     FROM emails e
                     JOIN email_mailbox em ON em.email_id = e.id
                     JOIN mailboxes m ON m.id = em.mailbox_id
                     WHERE e.account_id = ?1 AND m.role = ?2
                     ORDER BY e.received_at DESC
                     LIMIT ?3",
                )?;
                let rows = stmt
                    .query_map(
                        params![account_id.to_string(), mailbox_role, limit as i64],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                                row.get::<_, i64>(4)?,
                                row.get::<_, i64>(5)?,
                                row.get::<_, Option<String>>(6)?,
                            ))
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;

                rows.into_iter()
                    .map(
                        |(id, thread_id, from_addr, subject, received_at, size, auth_results)| {
                            Ok(EmailSummary {
                                id: parse_id(&id)?,
                                thread_id: parse_id(&thread_id)?,
                                from_addr,
                                subject,
                                received_at,
                                size: size as u64,
                                auth_results,
                            })
                        },
                    )
                    .collect()
            })
            .await
    }

    /// The raw RFC 5322 bytes of a stored message.
    pub async fn email_raw(&self, email_id: EmailId) -> Result<Option<Vec<u8>>, StorageError> {
        let blob_id: Option<String> = self
            .db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT blob_id FROM emails WHERE id = ?1",
                        [email_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?)
            })
            .await?;
        match blob_id {
            Some(hex) => {
                let blob_id: BlobId = hex
                    .parse()
                    .map_err(|_| StorageError::Corrupt(format!("bad blob id {hex}")))?;
                Ok(Some(self.get_blob(blob_id).await?))
            }
            None => Ok(None),
        }
    }
}

/// Find the thread this message belongs to: any existing message in the
/// same account whose Message-ID appears in this message's
/// `References`/`In-Reply-To` headers.
///
/// **Forward linking is not yet implemented.** When an older message in a
/// thread is sent before us, its `References` would mention a Message-ID
/// we now own. The full RFC 5536 / JMAP threading spec supports this via a
/// `References` LIKE match; doing so requires storing parsed references on
/// `emails`, which is a Phase-N+1 schema change tracked in `docs/PLAN.md`.
fn resolve_thread(
    conn: &Connection,
    account_id: AccountId,
    meta: &ParsedMeta,
) -> Result<Option<ThreadId>, StorageError> {
    for reference in &meta.references {
        let found: Option<String> = conn
            .query_row(
                "SELECT thread_id FROM emails
                 WHERE account_id = ?1 AND message_id = ?2
                 ORDER BY received_at DESC LIMIT 1",
                params![account_id.to_string(), reference],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(thread_id) = found {
            return Ok(Some(parse_id(&thread_id)?));
        }
    }
    Ok(None)
}

fn parse_id<T: std::str::FromStr>(s: &str) -> Result<T, StorageError> {
    s.parse()
        .map_err(|_| StorageError::Corrupt(format!("bad id in database: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use owney_core::ModSeq;
    use owney_events::EventBus;

    async fn open() -> (Storage, tempfile::TempDir, AccountId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path(), EventBus::new(64)).expect("open");
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");
        (storage, dir, account.id)
    }

    fn message(message_id: &str, subject: &str, references: &str) -> Vec<u8> {
        let refs = if references.is_empty() {
            String::new()
        } else {
            format!("References: {references}\r\n")
        };
        format!(
            "From: Bob <bob@remote.test>\r\nTo: alice@example.com\r\n\
             Message-ID: <{message_id}>\r\nSubject: {subject}\r\n{refs}\r\n\
             body of {message_id}\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn ingest_stores_and_lists() {
        let (storage, _dir, account_id) = open().await;

        let ingested = storage
            .ingest_email(
                account_id,
                message("m1@remote.test", "Hello", ""),
                "inbox",
                None,
            )
            .await
            .expect("ingest");

        let inbox = storage
            .list_mailbox(account_id, "inbox", 10)
            .await
            .expect("list");
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].id, ingested.id);
        assert_eq!(inbox[0].subject.as_deref(), Some("Hello"));
        assert_eq!(inbox[0].from_addr.as_deref(), Some("bob@remote.test"));

        let raw = storage
            .email_raw(ingested.id)
            .await
            .expect("raw")
            .expect("present");
        assert!(raw.windows(5).any(|w| w == b"Hello"));
        storage.close();
    }

    #[tokio::test]
    async fn replies_join_the_thread() {
        let (storage, _dir, account_id) = open().await;

        let first = storage
            .ingest_email(
                account_id,
                message("m1@remote.test", "Hi", ""),
                "inbox",
                None,
            )
            .await
            .expect("first");
        let reply = storage
            .ingest_email(
                account_id,
                message("m2@remote.test", "Re: Hi", "<m1@remote.test>"),
                "inbox",
                None,
            )
            .await
            .expect("reply");
        let unrelated = storage
            .ingest_email(
                account_id,
                message("m3@remote.test", "Other", ""),
                "inbox",
                None,
            )
            .await
            .expect("unrelated");

        assert_eq!(first.thread_id, reply.thread_id, "reply joins the thread");
        assert_ne!(
            first.thread_id, unrelated.thread_id,
            "unrelated starts a new one"
        );
        storage.close();
    }

    #[tokio::test]
    async fn unparseable_message_is_still_stored() {
        let (storage, _dir, account_id) = open().await;

        let ingested = storage
            .ingest_email(account_id, vec![0xff, 0xfe, 0x00, 0x01], "inbox", None)
            .await
            .expect("ingest garbage");
        let raw = storage
            .email_raw(ingested.id)
            .await
            .expect("raw")
            .expect("present");
        assert_eq!(raw, vec![0xff, 0xfe, 0x00, 0x01]);
        storage.close();
    }

    #[tokio::test]
    async fn modseqs_advance_per_ingest() {
        let (storage, _dir, account_id) = open().await;

        let before = storage
            .state(account_id, DataType::Email)
            .await
            .expect("state");
        storage
            .ingest_email(
                account_id,
                message("m1@remote.test", "One", ""),
                "inbox",
                None,
            )
            .await
            .expect("ingest");
        let after = storage
            .state(account_id, DataType::Email)
            .await
            .expect("state");
        assert_eq!(after, ModSeq(before.0 + 1));
        storage.close();
    }
}
