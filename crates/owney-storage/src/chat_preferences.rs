//! Chat mode preferences: per-contact settings for real-time email delivery.

use owney_core::AccountId;
use rusqlite::{OptionalExtension, params};

use crate::{Storage, StorageError, unix_now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatPreference {
    pub account_id: AccountId,
    pub contact_email: String,
    pub preference: ChatMode,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatMode {
    /// Always deliver from this contact as chat (real-time).
    AutoChat,
    /// Never deliver from this contact as chat (ignore sender's chat_mode flag).
    NeverChat,
    /// Respect sender's chat_mode flag.
    RespectSender,
}

impl ChatMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChatMode::AutoChat => "auto_chat",
            ChatMode::NeverChat => "never_chat",
            ChatMode::RespectSender => "respect_sender",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto_chat" => Some(ChatMode::AutoChat),
            "never_chat" => Some(ChatMode::NeverChat),
            "respect_sender" => Some(ChatMode::RespectSender),
            _ => None,
        }
    }
}

impl Storage {
    /// Get chat preference for a contact (defaults to RespectSender if not set).
    pub async fn get_chat_preference(
        &self,
        account_id: AccountId,
        contact_email: &str,
    ) -> Result<ChatMode, StorageError> {
        let contact_email = contact_email.trim().to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT preference FROM chat_preferences
                         WHERE account_id = ?1 AND contact_email = ?2",
                        params![account_id.to_string(), contact_email],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .and_then(|s| ChatMode::parse(&s))
                    .unwrap_or(ChatMode::RespectSender))
            })
            .await
    }

    /// Set chat preference for a contact.
    pub async fn set_chat_preference(
        &self,
        account_id: AccountId,
        contact_email: &str,
        preference: ChatMode,
    ) -> Result<(), StorageError> {
        let contact_email = contact_email.trim().to_lowercase();
        let preference_str = preference.as_str().to_owned();
        let now = unix_now();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO chat_preferences (account_id, contact_email, preference, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (account_id, contact_email) DO UPDATE SET
                       preference = excluded.preference,
                       updated_at = excluded.updated_at",
                    params![
                        account_id.to_string(),
                        contact_email,
                        preference_str,
                        now,
                        now
                    ],
                )?;
                Ok(())
            })
            .await
    }

    /// List all chat preferences for an account.
    pub async fn list_chat_preferences(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<ChatPreference>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT account_id, contact_email, preference, created_at, updated_at
                     FROM chat_preferences
                     WHERE account_id = ?1
                     ORDER BY updated_at DESC",
                )?;
                let prefs = stmt
                    .query_map(params![account_id.to_string()], |row| {
                        let account_id_str: String = row.get(0)?;
                        let contact_email: String = row.get(1)?;
                        let preference_str: String = row.get(2)?;
                        let created_at: i64 = row.get(3)?;
                        let updated_at: i64 = row.get(4)?;

                        Ok(ChatPreference {
                            account_id: account_id_str.parse().unwrap_or_else(|_| AccountId::new()),
                            contact_email,
                            preference: ChatMode::parse(&preference_str)
                                .unwrap_or(ChatMode::RespectSender),
                            created_at,
                            updated_at,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(prefs)
            })
            .await
    }

    /// Delete a chat preference.
    pub async fn delete_chat_preference(
        &self,
        account_id: AccountId,
        contact_email: &str,
    ) -> Result<(), StorageError> {
        let contact_email = contact_email.trim().to_lowercase();
        self.db
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM chat_preferences WHERE account_id = ?1 AND contact_email = ?2",
                    params![account_id.to_string(), contact_email],
                )?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owney_events::EventBus;

    #[tokio::test]
    async fn get_defaults_to_respect_sender() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path(), EventBus::new(8)).expect("open");
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");

        let pref = storage
            .get_chat_preference(account.id, "bob@example.com")
            .await
            .expect("pref");
        assert_eq!(pref, ChatMode::RespectSender);
        storage.close();
    }

    #[tokio::test]
    async fn set_and_get_auto_chat() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path(), EventBus::new(8)).expect("open");
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");

        storage
            .set_chat_preference(account.id, "bob@example.com", ChatMode::AutoChat)
            .await
            .expect("set");

        let pref = storage
            .get_chat_preference(account.id, "bob@example.com")
            .await
            .expect("pref");
        assert_eq!(pref, ChatMode::AutoChat);
        storage.close();
    }

    #[tokio::test]
    async fn list_preferences() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path(), EventBus::new(8)).expect("open");
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");

        storage
            .set_chat_preference(account.id, "bob@example.com", ChatMode::AutoChat)
            .await
            .expect("set");
        storage
            .set_chat_preference(account.id, "spam@bot.com", ChatMode::NeverChat)
            .await
            .expect("set");

        let prefs = storage
            .list_chat_preferences(account.id)
            .await
            .expect("list");
        assert_eq!(prefs.len(), 2);
        assert!(prefs.iter().any(|p| p.contact_email == "bob@example.com"));
        assert!(prefs.iter().any(|p| p.contact_email == "spam@bot.com"));
        storage.close();
    }

    #[tokio::test]
    async fn case_insensitive_email() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path(), EventBus::new(8)).expect("open");
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");

        storage
            .set_chat_preference(account.id, "Bob@Example.COM", ChatMode::AutoChat)
            .await
            .expect("set");

        let pref = storage
            .get_chat_preference(account.id, "bob@example.com")
            .await
            .expect("pref");
        assert_eq!(pref, ChatMode::AutoChat);
        storage.close();
    }
}
