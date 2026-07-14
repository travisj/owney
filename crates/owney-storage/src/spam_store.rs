//! Spam filtering storage: token counts for Naive Bayes classifier training.

use owney_core::AccountId;
use rusqlite::params;
use std::collections::HashMap;

use crate::{Storage, StorageError};

impl Storage {
    /// Get token counts (spam_count, ham_count) for the given tokens for an account.
    pub async fn get_spam_token_counts(
        &self,
        account_id: AccountId,
        tokens: &[String],
    ) -> Result<HashMap<String, (u32, u32)>, StorageError> {
        if tokens.is_empty() {
            return Ok(HashMap::new());
        }

        let account_id_str = account_id.to_string();
        let tokens_owned = tokens.to_vec();

        self.db
            .call(move |conn| {
                let mut result = HashMap::new();
                for token in &tokens_owned {
                    let (spam, ham): (u32, u32) = conn
                        .query_row(
                            "SELECT spam_count, ham_count FROM spam_tokens
                             WHERE account_id = ?1 AND token = ?2",
                            params![&account_id_str, token],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .unwrap_or((0, 0));
                    result.insert(token.clone(), (spam, ham));
                }
                Ok(result)
            })
            .await
    }

    /// Train the Bayes classifier with new tokens (spam or ham).
    pub async fn train_spam_tokens(
        &self,
        account_id: AccountId,
        tokens: &[String],
        is_spam: bool,
    ) -> Result<(), StorageError> {
        if tokens.is_empty() {
            return Ok(());
        }

        let account_id_str = account_id.to_string();
        let tokens_owned = tokens.to_vec();

        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                for token in &tokens_owned {
                    // Upsert: increment spam_count or ham_count
                    if is_spam {
                        tx.execute(
                            "INSERT INTO spam_tokens (account_id, token, spam_count, ham_count)
                             VALUES (?1, ?2, 1, 0)
                             ON CONFLICT(account_id, token) DO UPDATE SET
                               spam_count = spam_count + 1",
                            params![&account_id_str, token],
                        )?;
                    } else {
                        tx.execute(
                            "INSERT INTO spam_tokens (account_id, token, spam_count, ham_count)
                             VALUES (?1, ?2, 0, 1)
                             ON CONFLICT(account_id, token) DO UPDATE SET
                               ham_count = ham_count + 1",
                            params![&account_id_str, token],
                        )?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Set the spam_results JSON for an email after scanning.
    pub async fn set_spam_verdict(
        &self,
        email_id: &str,
        verdict_json: &str,
    ) -> Result<(), StorageError> {
        let email_id = email_id.to_owned();
        let verdict_json = verdict_json.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE emails SET spam_results = ?1 WHERE id = ?2",
                    params![&verdict_json, &email_id],
                )?;
                Ok(())
            })
            .await
    }
}
