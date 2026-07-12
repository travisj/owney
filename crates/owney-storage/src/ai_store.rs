//! Persistence for the AI layer: annotations, the auditable action log with
//! inverse patches, and the enrichment cursor.

use owney_core::{AccountId, EmailId};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::error::StorageError;
use crate::{Storage, unix_now};

#[derive(Debug, Clone)]
pub struct AiAction {
    pub id: Uuid,
    pub email_id: Option<String>,
    pub skill: String,
    pub description: String,
    pub inverse_patch: Option<String>,
    pub undone: bool,
    pub created_at: i64,
}

impl Storage {
    pub async fn insert_annotation(
        &self,
        account_id: AccountId,
        email_id: EmailId,
        kind: &str,
        content: &str,
    ) -> Result<(), StorageError> {
        let (kind, content) = (kind.to_owned(), content.to_owned());
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO ai_annotations (id, account_id, email_id, kind, content, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        Uuid::now_v7().to_string(),
                        account_id.to_string(),
                        email_id.to_string(),
                        kind,
                        content,
                        unix_now(),
                    ],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn annotations(
        &self,
        email_id: EmailId,
    ) -> Result<Vec<(String, String)>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT kind, content FROM ai_annotations WHERE email_id = ?1
                     ORDER BY created_at",
                )?;
                let rows = stmt
                    .query_map([email_id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    /// Record an AI action; returns its id for the activity feed.
    pub async fn record_ai_action(
        &self,
        account_id: AccountId,
        email_id: Option<EmailId>,
        skill: &str,
        description: &str,
        inverse_patch: Option<String>,
    ) -> Result<Uuid, StorageError> {
        let id = Uuid::now_v7();
        let (skill, description) = (skill.to_owned(), description.to_owned());
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO ai_actions
                       (id, account_id, email_id, skill, description, inverse_patch, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        id.to_string(),
                        account_id.to_string(),
                        email_id.map(|e| e.to_string()),
                        skill,
                        description,
                        inverse_patch,
                        unix_now(),
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(id)
    }

    pub async fn ai_actions(
        &self,
        account_id: AccountId,
        limit: usize,
    ) -> Result<Vec<AiAction>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, email_id, skill, description, inverse_patch, undone, created_at
                     FROM ai_actions WHERE account_id = ?1
                     ORDER BY created_at DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![account_id.to_string(), limit as i64], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows.into_iter()
                    .map(
                        |(id, email_id, skill, description, inverse, undone, created_at)| {
                            Ok(AiAction {
                                id: id.parse().map_err(|_| {
                                    StorageError::Corrupt(format!("bad action id {id}"))
                                })?,
                                email_id,
                                skill,
                                description,
                                inverse_patch: inverse,
                                undone: undone != 0,
                                created_at,
                            })
                        },
                    )
                    .collect()
            })
            .await
    }

    pub async fn ai_action(
        &self,
        account_id: AccountId,
        action_id: Uuid,
    ) -> Result<Option<AiAction>, StorageError> {
        let actions = self.ai_actions(account_id, 10_000).await?;
        Ok(actions.into_iter().find(|a| a.id == action_id))
    }

    pub async fn mark_action_undone(&self, action_id: Uuid) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE ai_actions SET undone = 1 WHERE id = ?1",
                    [action_id.to_string()],
                )?;
                Ok(())
            })
            .await
    }

    /// Enrichment cursor: the Email modseq up to which AI has processed.
    pub async fn ai_cursor(&self, account_id: AccountId) -> Result<u64, StorageError> {
        self.db
            .call(move |conn| {
                let modseq: Option<i64> = conn
                    .query_row(
                        "SELECT last_modseq FROM ai_cursor WHERE account_id = ?1",
                        [account_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(modseq.unwrap_or(0) as u64)
            })
            .await
    }

    pub async fn set_ai_cursor(
        &self,
        account_id: AccountId,
        modseq: u64,
    ) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO ai_cursor (account_id, last_modseq) VALUES (?1, ?2)
                     ON CONFLICT (account_id) DO UPDATE SET last_modseq = excluded.last_modseq",
                    params![account_id.to_string(), modseq as i64],
                )?;
                Ok(())
            })
            .await
    }

    /// How many messages this account has from a sender (screener heuristic:
    /// 1 means the one just stored is first contact).
    pub async fn sender_message_count(
        &self,
        account_id: AccountId,
        from_addr: &str,
    ) -> Result<u64, StorageError> {
        let from_addr = from_addr.to_owned();
        self.db
            .call(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM emails
                     WHERE account_id = ?1 AND from_addr = ?2",
                    params![account_id.to_string(), from_addr],
                    |row| row.get(0),
                )?;
                Ok(count as u64)
            })
            .await
    }

    /// The mailbox id for a role (worker helpers).
    pub async fn mailbox_id_by_role(
        &self,
        account_id: AccountId,
        role: &str,
    ) -> Result<Option<String>, StorageError> {
        let role = role.to_owned();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id FROM mailboxes WHERE account_id = ?1 AND role = ?2",
                        params![account_id.to_string(), role],
                        |row| row.get(0),
                    )
                    .optional()?)
            })
            .await
    }
}
