//! API bearer tokens ("app passwords"). Only a BLAKE3 hash is stored;
//! lookup is by hash, so the table never contains usable secrets.
//!
//! Two kinds of token share the table: legacy full-access tokens (NULL
//! scopes/expiry, minted by `admin token`) and OIDC-minted scoped tokens
//! (scopes + expiry + client link). `account_by_token` only accepts the
//! former, so callers that predate scoping (IMAP LOGIN) never honor an
//! OIDC token; scope-aware HTTP callers use `account_and_access_by_token`.

use owney_core::{AccountId, OAuthClientId};
use rusqlite::{OptionalExtension, params};

use crate::error::StorageError;
use crate::{Account, Storage, row_to_account, unix_now};

const TOKEN_PREFIX: &str = "msk_";

/// What a bearer token is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenAccess {
    /// Legacy admin-minted token: everything.
    Full,
    /// OIDC-minted token: the granted scope set.
    Scoped(Vec<String>),
}

impl TokenAccess {
    pub fn allows(&self, scope: &str) -> bool {
        match self {
            TokenAccess::Full => true,
            TokenAccess::Scoped(scopes) => scopes.iter().any(|s| s == scope),
        }
    }
}

impl Storage {
    /// Create a token for an account; returns the plaintext exactly once.
    pub async fn create_token(
        &self,
        account_id: AccountId,
        name: &str,
    ) -> Result<String, StorageError> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| StorageError::Crypto("os rng"))?;
        let token = format!("{TOKEN_PREFIX}{}", hex(&secret));
        let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();

        let name = name.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO app_passwords (token_hash, account_id, name, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![token_hash, account_id.to_string(), name, unix_now()],
                )?;
                Ok(())
            })
            .await?;
        Ok(token)
    }

    /// OIDC-minted variant: scoped, expiring, linked to the issuing client.
    /// Returns (plaintext, token_hash) — the hash links refresh tokens.
    pub async fn create_scoped_token(
        &self,
        account_id: AccountId,
        name: &str,
        scopes: &[String],
        expires_at: i64,
        client_id: OAuthClientId,
    ) -> Result<(String, String), StorageError> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| StorageError::Crypto("os rng"))?;
        let token = format!("{TOKEN_PREFIX}{}", hex(&secret));
        let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();

        let name = name.to_owned();
        let scopes = scopes.join(" ");
        let stored_hash = token_hash.clone();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO app_passwords
                       (token_hash, account_id, name, created_at, expires_at, scopes,
                        oauth_client_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        stored_hash,
                        account_id.to_string(),
                        name,
                        unix_now(),
                        expires_at,
                        scopes,
                        client_id.to_string(),
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok((token, token_hash))
    }

    /// Resolve a bearer token to its account, updating last-used.
    /// Returns None if the token is invalid, expired, scoped (OIDC-minted),
    /// or the account is disabled. Pre-scoping callers (IMAP) stay safe.
    pub async fn account_by_token(&self, token: &str) -> Result<Option<Account>, StorageError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Ok(None);
        }
        let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();
        self.db
            .call(move |conn| {
                let account = conn
                    .query_row(
                        "SELECT a.id, a.email, a.display_name, a.created_at
                         FROM app_passwords p JOIN accounts a ON a.id = p.account_id
                         WHERE p.token_hash = ?1 AND a.disabled_at IS NULL
                           AND p.scopes IS NULL
                           AND (p.expires_at IS NULL OR p.expires_at > ?2)",
                        params![token_hash, unix_now()],
                        row_to_account,
                    )
                    .optional()?;
                if account.is_some() {
                    conn.execute(
                        "UPDATE app_passwords SET last_used_at = ?2 WHERE token_hash = ?1",
                        params![token_hash, unix_now()],
                    )?;
                }
                Ok(account)
            })
            .await
    }

    /// Scope-aware lookup for HTTP callers: accepts both legacy full-access
    /// tokens (NULL scopes) and live OIDC-minted scoped tokens.
    pub async fn account_and_access_by_token(
        &self,
        token: &str,
    ) -> Result<Option<(Account, TokenAccess)>, StorageError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Ok(None);
        }
        let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();
        self.db
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT a.id, a.email, a.display_name, a.created_at, p.scopes
                         FROM app_passwords p JOIN accounts a ON a.id = p.account_id
                         WHERE p.token_hash = ?1 AND a.disabled_at IS NULL
                           AND (p.expires_at IS NULL OR p.expires_at > ?2)",
                        params![token_hash, unix_now()],
                        |row| {
                            let account = row_to_account(row)?;
                            let scopes: Option<String> = row.get(4)?;
                            Ok((account, scopes))
                        },
                    )
                    .optional()?;
                let result = row.map(|(account, scopes)| {
                    let access = match scopes {
                        None => TokenAccess::Full,
                        Some(scopes) => TokenAccess::Scoped(
                            scopes.split_whitespace().map(str::to_owned).collect(),
                        ),
                    };
                    (account, access)
                });
                if result.is_some() {
                    conn.execute(
                        "UPDATE app_passwords SET last_used_at = ?2 WHERE token_hash = ?1",
                        params![token_hash, unix_now()],
                    )?;
                }
                Ok(result)
            })
            .await
    }

    /// Revoke one token by its stored hash (OAuth revocation / family sweep).
    pub async fn revoke_token_by_hash(&self, token_hash: &str) -> Result<(), StorageError> {
        let token_hash = token_hash.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM app_passwords WHERE token_hash = ?1",
                    [token_hash],
                )?;
                Ok(())
            })
            .await
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use owney_events::EventBus;

    #[tokio::test]
    async fn token_round_trip_and_rejection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path(), EventBus::new(8)).expect("open");
        let account = storage
            .create_account("a@example.com", None)
            .await
            .expect("account");

        let token = storage
            .create_token(account.id, "test")
            .await
            .expect("create");
        assert!(token.starts_with("msk_"));

        let found = storage.account_by_token(&token).await.expect("lookup");
        assert_eq!(found.map(|a| a.id), Some(account.id));

        assert!(
            storage
                .account_by_token("msk_wrong")
                .await
                .expect("lookup")
                .is_none()
        );
        assert!(
            storage
                .account_by_token("garbage")
                .await
                .expect("lookup")
                .is_none()
        );
        storage.close();
    }
}
