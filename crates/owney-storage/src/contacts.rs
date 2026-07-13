//! Contact storage with auto-linking from email senders.
//!
//! Contacts are auto-created/updated when emails arrive from new senders.
//! Manual contact creation also supported for address book.

use owney_core::{AccountId, ContactId};
use rusqlite::{params, OptionalExtension};

use crate::error::StorageError;
use crate::Storage;

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: ContactId,
    pub account_id: AccountId,
    pub email: String,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Storage {
    /// Create or update a contact (used for auto-linking from email senders).
    pub async fn upsert_contact(
        &self,
        account_id: AccountId,
        email: String,
        name: Option<String>,
    ) -> Result<Contact, StorageError> {
        let email_lower = email.to_lowercase();
        let now = crate::unix_now();

        self.db
            .call(move |conn| {
                // Check if contact exists
                let existing: Option<String> = conn
                    .query_row(
                        "SELECT id FROM contacts WHERE account_id = ?1 AND email = ?2",
                        params![account_id.to_string(), email_lower],
                        |r| r.get(0),
                    )
                    .optional()?;

                if let Some(id_str) = existing {
                    // Update existing contact
                    if let Some(ref n) = name {
                        conn.execute(
                            "UPDATE contacts SET name = ?1, updated_at = ?2 WHERE id = ?3",
                            params![n, now, id_str],
                        )?;
                    }
                    Ok(Contact {
                        id: id_str.parse().unwrap_or_else(|_| ContactId::new()),
                        account_id,
                        email: email_lower,
                        name,
                        phone: None,
                        created_at: now,
                        updated_at: now,
                    })
                } else {
                    // Create new contact
                    let contact_id = ContactId::new();
                    conn.execute(
                        "INSERT INTO contacts (id, account_id, email, name, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                        params![
                            contact_id.to_string(),
                            account_id.to_string(),
                            email_lower,
                            name,
                            now
                        ],
                    )?;
                    Ok(Contact {
                        id: contact_id,
                        account_id,
                        email: email_lower,
                        name,
                        phone: None,
                        created_at: now,
                        updated_at: now,
                    })
                }
            })
            .await
    }

    /// Get a contact by ID.
    pub async fn get_contact(
        &self,
        account_id: AccountId,
        contact_id: ContactId,
    ) -> Result<Option<Contact>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, account_id, email, name, phone, created_at, updated_at
                         FROM contacts WHERE id = ?1 AND account_id = ?2",
                        params![contact_id.to_string(), account_id.to_string()],
                        |row| {
                            Ok(Contact {
                                id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| ContactId::new()),
                                account_id,
                                email: row.get(2)?,
                                name: row.get(3)?,
                                phone: row.get(4)?,
                                created_at: row.get(5)?,
                                updated_at: row.get(6)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    /// Find a contact by email address.
    pub async fn find_contact_by_email(
        &self,
        account_id: AccountId,
        email: &str,
    ) -> Result<Option<Contact>, StorageError> {
        let email = email.to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, account_id, email, name, phone, created_at, updated_at
                         FROM contacts WHERE account_id = ?1 AND email = ?2",
                        params![account_id.to_string(), email],
                        |row| {
                            Ok(Contact {
                                id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| ContactId::new()),
                                account_id,
                                email: row.get(2)?,
                                name: row.get(3)?,
                                phone: row.get(4)?,
                                created_at: row.get(5)?,
                                updated_at: row.get(6)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    /// List all contacts for an account.
    pub async fn list_contacts(&self, account_id: AccountId) -> Result<Vec<Contact>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, account_id, email, name, phone, created_at, updated_at
                     FROM contacts WHERE account_id = ?1 ORDER BY name, email",
                )?;
                let contacts = stmt
                    .query_map(params![account_id.to_string()], |row| {
                        Ok(Contact {
                            id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| ContactId::new()),
                            account_id,
                            email: row.get(2)?,
                            name: row.get(3)?,
                            phone: row.get(4)?,
                            created_at: row.get(5)?,
                            updated_at: row.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(contacts)
            })
            .await
    }

    /// Update a contact's information.
    pub async fn update_contact(
        &self,
        contact_id: ContactId,
        name: Option<String>,
        phone: Option<String>,
    ) -> Result<(), StorageError> {
        let now = crate::unix_now();

        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE contacts SET name = ?1, phone = ?2, updated_at = ?3 WHERE id = ?4",
                    params![name, phone, now, contact_id.to_string()],
                )?;
                Ok(())
            })
            .await
    }

    /// Delete a contact.
    pub async fn delete_contact(&self, contact_id: ContactId) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute("DELETE FROM contacts WHERE id = ?1", params![contact_id.to_string()])?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::Storage;

    #[allow(dead_code)]
    async fn harness(tmp: &tempfile::TempDir) -> (crate::Storage, owney_events::EventBus) {
        crate::tests::open(tmp.path()).await
    }

    #[tokio::test]
    async fn upsert_creates_new_contact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create account");

        let contact = storage
            .upsert_contact(acct.id, "bob@example.com".to_string(), Some("Bob Smith".to_string()))
            .await
            .expect("upsert");

        assert_eq!(contact.email, "bob@example.com");
        assert_eq!(contact.name, Some("Bob Smith".to_string()));

        storage.close();
    }

    #[tokio::test]
    async fn upsert_updates_existing_contact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create account");

        storage
            .upsert_contact(acct.id, "bob@example.com".to_string(), Some("Bob".to_string()))
            .await
            .expect("first upsert");

        let updated = storage
            .upsert_contact(acct.id, "bob@example.com".to_string(), Some("Bob Smith".to_string()))
            .await
            .expect("second upsert");

        assert_eq!(updated.name, Some("Bob Smith".to_string()));

        storage.close();
    }

    #[tokio::test]
    async fn find_contact_by_email() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create account");

        storage
            .upsert_contact(acct.id, "bob@example.com".to_string(), Some("Bob".to_string()))
            .await
            .expect("upsert");

        let found = storage
            .find_contact_by_email(acct.id, "BOB@EXAMPLE.COM")
            .await
            .expect("find")
            .expect("should exist");

        assert_eq!(found.email, "bob@example.com");

        storage.close();
    }

    #[tokio::test]
    async fn list_contacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create account");

        storage
            .upsert_contact(acct.id, "bob@example.com".to_string(), Some("Bob".to_string()))
            .await
            .expect("upsert 1");
        storage
            .upsert_contact(acct.id, "charlie@example.com".to_string(), Some("Charlie".to_string()))
            .await
            .expect("upsert 2");

        let contacts = storage.list_contacts(acct.id).await.expect("list");
        assert_eq!(contacts.len(), 2);

        storage.close();
    }
}
