//! API bearer tokens ("app passwords"). Only a BLAKE3 hash is stored;
//! lookup is by hash, so the table never contains usable secrets.

use owney_core::AccountId;
use rusqlite::{OptionalExtension, params};

use crate::error::StorageError;
use crate::{Account, Storage, row_to_account, unix_now};

const TOKEN_PREFIX: &str = "msk_";

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

    /// Resolve a bearer token to its account, updating last-used.
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
                         WHERE p.token_hash = ?1",
                        [&token_hash],
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
}

fn hex(bytes: &[u8]) -> String {
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
