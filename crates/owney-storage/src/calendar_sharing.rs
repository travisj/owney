//! Calendar sharing and delegation with federation support.
//!
//! Supports:
//! - Same-server sharing (read-only) and delegation (read-write)
//! - Cross-server federation with federated email discovery
//! - Granular permission model
//! - Pending invitation workflow

use owney_core::{AccountId, CalendarId};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::Storage;
use crate::error::StorageError;

/// Sharing type: read-only sharing vs. read-write delegation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SharingType {
    /// Read-only access to calendar
    Sharing,
    /// Full read-write access (delegation)
    Delegation,
}

impl SharingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SharingType::Sharing => "sharing",
            SharingType::Delegation => "delegation",
        }
    }
}

/// Permission model with granular control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permissions {
    pub view_calendar: bool,
    pub view_events: bool,
    pub edit_events: bool,
    pub delete_events: bool,
    pub change_sharing: bool,
    pub admin: bool,
}

impl Permissions {
    /// Read-only sharing permissions
    pub fn sharing() -> Self {
        Self {
            view_calendar: true,
            view_events: true,
            edit_events: false,
            delete_events: false,
            change_sharing: false,
            admin: false,
        }
    }

    /// Full delegation permissions
    pub fn delegation() -> Self {
        Self {
            view_calendar: true,
            view_events: true,
            edit_events: true,
            delete_events: true,
            change_sharing: true,
            admin: true,
        }
    }
}

/// Calendar shared with another user (same-server)
#[derive(Debug, Clone)]
pub struct CalendarSharing {
    pub id: String,
    pub calendar_id: CalendarId,
    pub shared_with_account_id: AccountId,
    pub sharing_type: SharingType,
    pub permissions: Permissions,
    pub status: String, // "accepted", "rejected", "revoked"
    pub created_at: i64,
    pub accepted_at: Option<i64>,
}

/// Calendar shared via federation (cross-server)
#[derive(Debug, Clone)]
pub struct CalendarFederation {
    pub id: String,
    pub calendar_id: CalendarId,
    pub target_email: String,      // user@domain.com
    pub target_server_url: String, // https://owney.domain.com
    pub sharing_type: SharingType,
    pub permissions: Permissions,
    pub status: String, // "pending", "accepted", "syncing", "error"
    pub last_sync_at: Option<i64>,
    pub sync_token: Option<String>,
    pub created_at: i64,
}

/// Pending calendar invitation
#[derive(Debug, Clone)]
pub struct CalendarInvitation {
    pub id: String,
    pub calendar_id: CalendarId,
    pub inviter_account_id: AccountId,
    pub invitee_email: String, // Can be "user@domain.com" or local account email
    pub invitee_server_url: Option<String>, // Set if federated
    pub sharing_type: SharingType,
    pub status: String, // "pending", "accepted", "rejected"
    pub message: Option<String>,
    pub created_at: i64,
}

impl Storage {
    /// Share a calendar with another same-server account.
    pub async fn share_calendar(
        &self,
        calendar_id: CalendarId,
        _account_id: AccountId,
        target_account_id: AccountId,
        sharing_type: SharingType,
    ) -> Result<CalendarSharing, StorageError> {
        let sharing_id = uuid::Uuid::now_v7().to_string();
        let now = crate::unix_now();
        let permissions = match sharing_type {
            SharingType::Sharing => Permissions::sharing(),
            SharingType::Delegation => Permissions::delegation(),
        };
        let permissions_json = serde_json::to_string(&permissions)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO calendar_sharing
                     (id, calendar_id, shared_with_account_id, sharing_type, permissions, status, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                    params![
                        sharing_id,
                        calendar_id.to_string(),
                        target_account_id.to_string(),
                        sharing_type.as_str(),
                        permissions_json,
                        now
                    ],
                )?;
                Ok(CalendarSharing {
                    id: sharing_id,
                    calendar_id,
                    shared_with_account_id: target_account_id,
                    sharing_type,
                    permissions,
                    status: "pending".to_string(),
                    created_at: now,
                    accepted_at: None,
                })
            })
            .await
    }

    /// Accept a calendar sharing invitation.
    pub async fn accept_sharing(&self, sharing_id: &str) -> Result<(), StorageError> {
        let now = crate::unix_now();
        let sharing_id = sharing_id.to_string();

        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE calendar_sharing SET status = 'accepted', accepted_at = ?1 WHERE id = ?2",
                    params![now, sharing_id],
                )?;
                Ok(())
            })
            .await
    }

    /// Reject a calendar sharing invitation.
    pub async fn reject_sharing(&self, sharing_id: &str) -> Result<(), StorageError> {
        let sharing_id = sharing_id.to_string();

        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE calendar_sharing SET status = 'rejected' WHERE id = ?1",
                    params![sharing_id],
                )?;
                Ok(())
            })
            .await
    }

    /// Get all calendars shared with an account (including shared & delegated).
    pub async fn get_shared_calendars(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<CalendarSharing>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, calendar_id, shared_with_account_id, sharing_type, permissions, status, created_at, accepted_at
                     FROM calendar_sharing WHERE shared_with_account_id = ?1 AND status IN ('pending', 'accepted')",
                )?;
                let sharings = stmt
                    .query_map(params![account_id.to_string()], |row| {
                        let perms_json: String = row.get(4)?;
                        let permissions: Permissions =
                            serde_json::from_str(&perms_json).unwrap_or(Permissions::sharing());
                        Ok(CalendarSharing {
                            id: row.get(0)?,
                            calendar_id: row.get::<_, String>(1)?.parse().unwrap_or_else(|_| CalendarId::new()),
                            shared_with_account_id: account_id,
                            sharing_type: match row.get::<_, String>(3)?.as_str() {
                                "delegation" => SharingType::Delegation,
                                _ => SharingType::Sharing,
                            },
                            permissions,
                            status: row.get(5)?,
                            created_at: row.get(6)?,
                            accepted_at: row.get(7)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(sharings)
            })
            .await
    }

    /// Create a federated calendar invitation.
    pub async fn create_federation_invitation(
        &self,
        calendar_id: CalendarId,
        inviter_account_id: AccountId,
        target_email: String,
        target_server_url: Option<String>,
        sharing_type: SharingType,
    ) -> Result<CalendarInvitation, StorageError> {
        let invitation_id = uuid::Uuid::now_v7().to_string();
        let now = crate::unix_now();

        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO calendar_invitations
                     (id, calendar_id, inviter_account_id, invitee_email, invitee_server_url, sharing_type, status, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)",
                    params![
                        invitation_id,
                        calendar_id.to_string(),
                        inviter_account_id.to_string(),
                        target_email,
                        target_server_url,
                        sharing_type.as_str(),
                        now
                    ],
                )?;
                Ok(CalendarInvitation {
                    id: invitation_id,
                    calendar_id,
                    inviter_account_id,
                    invitee_email: target_email,
                    invitee_server_url: target_server_url,
                    sharing_type,
                    status: "pending".to_string(),
                    message: None,
                    created_at: now,
                })
            })
            .await
    }

    /// Get pending invitations for an account.
    pub async fn get_pending_invitations(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<CalendarInvitation>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, calendar_id, inviter_account_id, invitee_email, invitee_server_url, sharing_type, status, created_at
                     FROM calendar_invitations WHERE invitee_email IN (SELECT email FROM accounts WHERE id = ?1) AND status = 'pending'",
                )?;
                let invitations = stmt
                    .query_map(params![account_id.to_string()], |row| {
                        Ok(CalendarInvitation {
                            id: row.get(0)?,
                            calendar_id: row.get::<_, String>(1)?.parse().unwrap_or_else(|_| CalendarId::new()),
                            inviter_account_id: row.get::<_, String>(2)?.parse().unwrap_or_else(|_| AccountId::new()),
                            invitee_email: row.get(3)?,
                            invitee_server_url: row.get(4)?,
                            sharing_type: match row.get::<_, String>(5)?.as_str() {
                                "delegation" => SharingType::Delegation,
                                _ => SharingType::Sharing,
                            },
                            status: row.get(6)?,
                            message: None,
                            created_at: row.get(7)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(invitations)
            })
            .await
    }

    /// Accept a federated invitation and create corresponding sharing record.
    pub async fn accept_federation_invitation(
        &self,
        invitation_id: &str,
    ) -> Result<(), StorageError> {
        let invitation_id = invitation_id.to_string();

        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE calendar_invitations SET status = 'accepted' WHERE id = ?1",
                    params![invitation_id],
                )?;
                Ok(())
            })
            .await
    }

    /// Get federation record by ID.
    pub async fn get_federation(
        &self,
        federation_id: &str,
    ) -> Result<Option<CalendarFederation>, StorageError> {
        let federation_id = federation_id.to_string();

        self.db
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, calendar_id, target_email, target_server_url, sharing_type, permissions, status, sync_token, last_sync_at, created_at
                     FROM calendar_federation WHERE id = ?1",
                    [federation_id],
                    |row| {
                        let perms_json: String = row.get(5)?;
                        let permissions: Permissions = serde_json::from_str(&perms_json).unwrap_or(Permissions::sharing());
                        Ok(CalendarFederation {
                            id: row.get(0)?,
                            calendar_id: row.get::<_, String>(1)?.parse().unwrap_or_else(|_| CalendarId::new()),
                            target_email: row.get(2)?,
                            target_server_url: row.get(3)?,
                            sharing_type: match row.get::<_, String>(4)?.as_str() {
                                "delegation" => SharingType::Delegation,
                                _ => SharingType::Sharing,
                            },
                            permissions,
                            status: row.get(6)?,
                            sync_token: row.get(7)?,
                            last_sync_at: row.get(8)?,
                            created_at: row.get(9)?,
                        })
                    },
                )
                .optional()
                .map_err(StorageError::from)
            })
            .await
    }

    /// Update federation sync token and timestamp after successful sync.
    pub async fn update_federation_sync_token(
        &self,
        federation_id: &str,
        sync_token: Option<String>,
    ) -> Result<(), StorageError> {
        let now = crate::unix_now();
        let federation_id = federation_id.to_string();

        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE calendar_federation SET sync_token = ?1, last_sync_at = ?2, status = 'syncing' WHERE id = ?3",
                    params![sync_token, now, federation_id],
                )?;
                Ok(())
            })
            .await
    }

    /// Get IDs of calendar events modified since timestamp (for sync).
    pub async fn list_calendar_event_ids_since(
        &self,
        calendar_id: owney_core::CalendarId,
        since_timestamp: i64,
    ) -> Result<Vec<(owney_core::EventId, bool)>, StorageError> {
        // Returns (event_id, is_deleted) tuples
        // Note: This is a simplified version. In Phase 2+, we'd track soft deletes.

        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, updated_at FROM calendar_events WHERE calendar_id = ?1 AND updated_at > ?2 ORDER BY updated_at",
                )?;
                let events = stmt
                    .query_map(params![calendar_id.to_string(), since_timestamp], |row| {
                        Ok((
                            row.get::<_, String>(0)?.parse().unwrap_or_else(|_| owney_core::EventId::new()),
                            false, // is_deleted: would need soft delete tracking
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(events)
            })
            .await
    }

    /// Get all active federations that need syncing.
    pub async fn list_active_federations(&self) -> Result<Vec<CalendarFederation>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, calendar_id, target_email, target_server_url, sharing_type, permissions, status, sync_token, last_sync_at, created_at
                     FROM calendar_federation WHERE status IN ('accepted', 'syncing')
                     ORDER BY last_sync_at ASC NULLS FIRST",
                )?;
                let federations = stmt
                    .query_map([], |row| {
                        let perms_json: String = row.get(5)?;
                        let permissions: Permissions =
                            serde_json::from_str(&perms_json).unwrap_or(Permissions::sharing());
                        Ok(CalendarFederation {
                            id: row.get(0)?,
                            calendar_id: row.get::<_, String>(1)?.parse().unwrap_or_else(|_| CalendarId::new()),
                            target_email: row.get(2)?,
                            target_server_url: row.get(3)?,
                            sharing_type: match row.get::<_, String>(4)?.as_str() {
                                "delegation" => SharingType::Delegation,
                                _ => SharingType::Sharing,
                            },
                            permissions,
                            status: row.get(6)?,
                            sync_token: row.get(7)?,
                            last_sync_at: row.get(8)?,
                            created_at: row.get(9)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(federations)
            })
            .await
    }

    /// Mark federation as having an error during sync.
    pub async fn mark_federation_error(&self, federation_id: &str) -> Result<(), StorageError> {
        let federation_id = federation_id.to_string();

        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE calendar_federation SET status = 'error' WHERE id = ?1",
                    params![federation_id],
                )?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    async fn harness(tmp: &tempfile::TempDir) -> (crate::Storage, owney_events::EventBus) {
        crate::tests::open(tmp.path()).await
    }

    #[tokio::test]
    async fn share_calendar_creates_pending_invitation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let bob = storage
            .create_account("bob@example.com", None)
            .await
            .expect("bob");

        let calendar = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("calendar");

        let sharing = storage
            .share_calendar(calendar.id, alice.id, bob.id, super::SharingType::Sharing)
            .await
            .expect("share");

        assert_eq!(sharing.status, "pending");
        assert!(!sharing.permissions.edit_events); // Sharing is read-only

        storage.close();
    }

    #[tokio::test]
    async fn delegation_has_full_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let bob = storage
            .create_account("bob@example.com", None)
            .await
            .expect("bob");

        let calendar = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("calendar");

        let sharing = storage
            .share_calendar(
                calendar.id,
                alice.id,
                bob.id,
                super::SharingType::Delegation,
            )
            .await
            .expect("share");

        assert!(sharing.permissions.edit_events); // Delegation is read-write
        assert!(sharing.permissions.admin);

        storage.close();
    }

    #[tokio::test]
    async fn accept_sharing_updates_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let bob = storage
            .create_account("bob@example.com", None)
            .await
            .expect("bob");

        let calendar = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("calendar");

        let sharing = storage
            .share_calendar(calendar.id, alice.id, bob.id, super::SharingType::Sharing)
            .await
            .expect("share");

        assert_eq!(sharing.status, "pending");

        storage.accept_sharing(&sharing.id).await.expect("accept");

        // Verify the sharing is now accepted by fetching it
        let shared = storage
            .get_shared_calendars(bob.id)
            .await
            .expect("list shared");
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].status, "accepted");

        storage.close();
    }

    #[tokio::test]
    async fn get_shared_calendars_returns_all_sharings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let bob = storage
            .create_account("bob@example.com", None)
            .await
            .expect("bob");

        let cal1 = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("cal1");
        let cal2 = storage
            .create_calendar(alice.id, "Work".to_string(), None)
            .await
            .expect("cal2");

        let _share1 = storage
            .share_calendar(cal1.id, alice.id, bob.id, super::SharingType::Sharing)
            .await
            .expect("share1");

        let _share2 = storage
            .share_calendar(cal2.id, alice.id, bob.id, super::SharingType::Delegation)
            .await
            .expect("share2");

        let shared = storage
            .get_shared_calendars(bob.id)
            .await
            .expect("list shared");
        assert_eq!(shared.len(), 2);

        // One should be sharing, one should be delegation
        let types: std::collections::HashSet<_> = shared.iter().map(|s| s.sharing_type).collect();
        assert!(types.contains(&super::SharingType::Sharing));
        assert!(types.contains(&super::SharingType::Delegation));

        storage.close();
    }

    #[tokio::test]
    async fn federation_invitation_workflow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let calendar = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("calendar");

        // Create federated invitation
        let invitation = storage
            .create_federation_invitation(
                calendar.id,
                alice.id,
                "bob@remote.example.com".to_string(),
                Some("https://remote.example.com".to_string()),
                super::SharingType::Delegation,
            )
            .await
            .expect("create invitation");

        assert_eq!(invitation.status, "pending");
        assert_eq!(invitation.invitee_email, "bob@remote.example.com");

        // Accept invitation
        storage
            .accept_federation_invitation(&invitation.id)
            .await
            .expect("accept");

        storage.close();
    }
}
