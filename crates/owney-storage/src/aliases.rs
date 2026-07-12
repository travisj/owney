//! Email aliases (permanent and temporary).

use owney_core::AccountId;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::error::StorageError;
use crate::{Account, Storage, row_to_account, unix_now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub id: String,
    pub account_id: AccountId,
    pub alias_email: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub active: bool,
}

impl Storage {
    /// Create an alias for an account.
    /// expires_at: Unix timestamp when this alias expires (None = permanent).
    pub async fn create_alias(
        &self,
        account_id: AccountId,
        alias_email: &str,
        label: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<Alias, StorageError> {
        let id = Uuid::now_v7().to_string();
        let alias_email_lower = alias_email.trim().to_lowercase();
        let label_owned = label.map(str::to_owned);
        let created_at = unix_now();
        let account_id_str = account_id.to_string();

        let id_clone = id.clone();
        let alias_email_clone = alias_email_lower.clone();
        let label_clone = label_owned.clone();

        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO aliases (id, account_id, alias_email, label, created_at, expires_at, active)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
                    params![&id_clone, &account_id_str, &alias_email_clone, &label_clone, created_at, expires_at],
                )?;
                Ok(())
            })
            .await?;

        Ok(Alias {
            id,
            account_id,
            alias_email: alias_email_lower,
            label: label_owned,
            created_at,
            expires_at,
            active: true,
        })
    }

    /// List all active, non-expired aliases for an account.
    pub async fn list_aliases_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<Alias>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, account_id, alias_email, label, created_at, expires_at, active
                     FROM aliases
                     WHERE account_id = ?1 AND active = 1
                       AND (expires_at IS NULL OR expires_at > ?2)
                     ORDER BY created_at DESC",
                )?;
                let aliases = stmt
                    .query_map(params![account_id.to_string(), unix_now()], row_to_alias)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(aliases)
            })
            .await
    }

    /// Resolve an alias email to its owner account (if active and not expired).
    pub async fn alias_target_account(&self, alias_email: &str) -> Result<Option<Account>, StorageError> {
        let alias_email = alias_email.trim().to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT a.id, a.email, a.display_name, a.created_at
                         FROM aliases al
                         INNER JOIN accounts a ON a.id = al.account_id
                         WHERE al.alias_email = ?1
                           AND al.active = 1
                           AND (al.expires_at IS NULL OR al.expires_at > ?2)
                           AND a.disabled_at IS NULL",
                        params![alias_email, unix_now()],
                        row_to_account,
                    )
                    .optional()?)
            })
            .await
    }

    /// Deactivate an alias (marks as inactive but keeps the record for history).
    pub async fn deactivate_alias(&self, id: &str) -> Result<(), StorageError> {
        let id = id.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE aliases SET active = 0 WHERE id = ?1",
                    [id],
                )?;
                Ok(())
            })
            .await
    }

    /// Resolve a recipient email to its target account (direct account or alias).
    /// Returns the owner's Account if found, None if unknown user (expired/inactive alias or account).
    pub async fn resolve_recipient(&self, email: &str) -> Result<Option<Account>, StorageError> {
        // Try direct account first
        if let Ok(Some(account)) = self.account_by_email(email).await {
            return Ok(Some(account));
        }
        // Fall back to alias
        self.alias_target_account(email).await
    }

    /// Find an alias by email address (including expired/inactive aliases).
    /// Returns the alias ID if found.
    pub async fn find_alias_id(&self, email: &str) -> Result<Option<String>, StorageError> {
        let email = email.trim().to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id FROM aliases WHERE alias_email = ?1",
                        [email],
                        |row| row.get(0),
                    )
                    .optional()?)
            })
            .await
    }
}

fn row_to_alias(row: &rusqlite::Row) -> rusqlite::Result<Alias> {
    let id: String = row.get(0)?;
    let account_id: String = row.get(1)?;
    let alias_email: String = row.get(2)?;
    let label: Option<String> = row.get(3)?;
    let created_at: i64 = row.get(4)?;
    let expires_at: Option<i64> = row.get(5)?;
    let active: i64 = row.get(6)?;

    Ok(Alias {
        id,
        account_id: account_id.parse().unwrap_or_else(|_| AccountId::new()),
        alias_email,
        label,
        created_at,
        expires_at,
        active: active != 0,
    })
}
