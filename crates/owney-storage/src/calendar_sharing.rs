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

    /// Permissions held by a calendar's owner (unconditional full access).
    pub fn owner() -> Self {
        Self::delegation()
    }
}

/// Parse a stored permissions JSON blob, surfacing corruption as a rusqlite
/// error rather than silently downgrading to read-only (which would hide the
/// corruption and could mask an over- or under-grant).
fn parse_permissions(col: usize, json: &str) -> rusqlite::Result<Permissions> {
    serde_json::from_str(json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Parse a stored id column, surfacing an unparseable id as an error instead of
/// substituting a fresh random id (which would silently rebind the row).
fn parse_id<T: std::str::FromStr>(col: usize, raw: &str) -> rusqlite::Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    raw.parse::<T>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
    })
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
    /// The verified counterpart server domain.
    pub peer_domain: Option<String>,
    /// The pinned fingerprint of the counterpart server's cert.
    pub peer_fingerprint: Option<String>,
    /// Shared secret gating the serve/notify path for this federation.
    pub capability_secret: Option<String>,
    /// "outbound" (we own & serve this calendar) or "inbound" (we subscribe).
    pub direction: Option<String>,
}

/// Columns selected by every `CalendarFederation` reader, in the order
/// [`federation_from_row`] expects.
const FEDERATION_COLUMNS: &str = "id, calendar_id, target_email, target_server_url, \
     sharing_type, permissions, status, sync_token, last_sync_at, created_at, \
     peer_domain, peer_fingerprint, capability_secret, direction";

fn federation_from_row(row: &rusqlite::Row) -> rusqlite::Result<CalendarFederation> {
    let perms_json: String = row.get(5)?;
    Ok(CalendarFederation {
        id: row.get(0)?,
        calendar_id: parse_id(1, &row.get::<_, String>(1)?)?,
        target_email: row.get(2)?,
        target_server_url: row.get(3)?,
        sharing_type: match row.get::<_, String>(4)?.as_str() {
            "delegation" => SharingType::Delegation,
            _ => SharingType::Sharing,
        },
        permissions: parse_permissions(5, &perms_json)?,
        status: row.get(6)?,
        sync_token: row.get(7)?,
        last_sync_at: row.get(8)?,
        created_at: row.get(9)?,
        peer_domain: row.get(10)?,
        peer_fingerprint: row.get(11)?,
        capability_secret: row.get(12)?,
        direction: row.get(13)?,
    })
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
    ///
    /// `owner_account_id` must own `calendar_id`; otherwise this returns
    /// [`StorageError::NotAuthorized`] and writes nothing. This is the
    /// authorization boundary — callers must pass the authenticated caller's
    /// account id, not the target's.
    pub async fn share_calendar(
        &self,
        calendar_id: CalendarId,
        owner_account_id: AccountId,
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
                // Only the owner may share a calendar. Guard the insert on
                // ownership so a caller cannot share someone else's calendar.
                let owns: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM calendars WHERE id = ?1 AND account_id = ?2)",
                    params![calendar_id.to_string(), owner_account_id.to_string()],
                    |row| row.get(0),
                )?;
                if !owns {
                    return Err(StorageError::NotAuthorized);
                }

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

    /// Accept a calendar sharing invitation addressed to `account_id`.
    ///
    /// Scoped to the recipient: accepting an invitation addressed to a
    /// different account returns [`StorageError::NotAuthorized`].
    pub async fn accept_sharing(
        &self,
        sharing_id: &str,
        account_id: AccountId,
    ) -> Result<(), StorageError> {
        let now = crate::unix_now();
        let sharing_id = sharing_id.to_string();

        self.db
            .call(move |conn| {
                let affected = conn.execute(
                    "UPDATE calendar_sharing SET status = 'accepted', accepted_at = ?1
                     WHERE id = ?2 AND shared_with_account_id = ?3",
                    params![now, sharing_id, account_id.to_string()],
                )?;
                if affected == 0 {
                    return Err(StorageError::NotAuthorized);
                }
                Ok(())
            })
            .await
    }

    /// Reject a calendar sharing invitation addressed to `account_id`.
    pub async fn reject_sharing(
        &self,
        sharing_id: &str,
        account_id: AccountId,
    ) -> Result<(), StorageError> {
        let sharing_id = sharing_id.to_string();

        self.db
            .call(move |conn| {
                let affected = conn.execute(
                    "UPDATE calendar_sharing SET status = 'rejected'
                     WHERE id = ?1 AND shared_with_account_id = ?2",
                    params![sharing_id, account_id.to_string()],
                )?;
                if affected == 0 {
                    return Err(StorageError::NotAuthorized);
                }
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
                        let permissions = parse_permissions(4, &perms_json)?;
                        Ok(CalendarSharing {
                            id: row.get(0)?,
                            calendar_id: parse_id(1, &row.get::<_, String>(1)?)?,
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

    /// Effective permissions `account_id` holds on `calendar_id`, or `None` if
    /// the account has no access.
    ///
    /// This is the single authorization decision point for calendar reads and
    /// writes: the owner gets full [`Permissions::owner`]; otherwise an
    /// *accepted* sharing row grants exactly its stored permissions; a pending,
    /// rejected, or revoked row grants nothing.
    pub async fn calendar_access(
        &self,
        account_id: AccountId,
        calendar_id: CalendarId,
    ) -> Result<Option<Permissions>, StorageError> {
        self.db
            .call(move |conn| {
                let is_owner: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM calendars WHERE id = ?1 AND account_id = ?2)",
                    params![calendar_id.to_string(), account_id.to_string()],
                    |row| row.get(0),
                )?;
                if is_owner {
                    return Ok(Some(Permissions::owner()));
                }

                let perms_json: Option<String> = conn
                    .query_row(
                        "SELECT permissions FROM calendar_sharing
                         WHERE calendar_id = ?1 AND shared_with_account_id = ?2
                           AND status = 'accepted'",
                        params![calendar_id.to_string(), account_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;

                match perms_json {
                    Some(json) => Ok(Some(parse_permissions(0, &json)?)),
                    None => Ok(None),
                }
            })
            .await
    }

    /// Calendars accepted-shared with `account_id`, returned as `(calendar_id,
    /// permissions)` pairs. Owned calendars are not included.
    pub async fn list_accepted_shared_calendar_ids(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(CalendarId, Permissions)>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT calendar_id, permissions FROM calendar_sharing
                     WHERE shared_with_account_id = ?1 AND status = 'accepted'",
                )?;
                let rows = stmt
                    .query_map(params![account_id.to_string()], |row| {
                        let calendar_id: CalendarId = parse_id(0, &row.get::<_, String>(0)?)?;
                        let permissions = parse_permissions(1, &row.get::<_, String>(1)?)?;
                        Ok((calendar_id, permissions))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
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
                            calendar_id: parse_id(1, &row.get::<_, String>(1)?)?,
                            inviter_account_id: parse_id(2, &row.get::<_, String>(2)?)?,
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

    /// Accept a federated invitation addressed to `account_id`.
    ///
    /// Scoped to the invitee: the invitation's `invitee_email` must match
    /// `account_id`'s address, otherwise this returns
    /// [`StorageError::NotAuthorized`]. Only pending invitations may be
    /// accepted.
    pub async fn accept_federation_invitation(
        &self,
        invitation_id: &str,
        account_id: AccountId,
    ) -> Result<(), StorageError> {
        let invitation_id = invitation_id.to_string();

        self.db
            .call(move |conn| {
                let affected = conn.execute(
                    "UPDATE calendar_invitations SET status = 'accepted'
                     WHERE id = ?1 AND status = 'pending'
                       AND invitee_email IN (SELECT email FROM accounts WHERE id = ?2)",
                    params![invitation_id, account_id.to_string()],
                )?;
                if affected == 0 {
                    return Err(StorageError::NotAuthorized);
                }
                Ok(())
            })
            .await
    }

    /// Reject a federated invitation addressed to `account_id`.
    pub async fn reject_invitation(
        &self,
        invitation_id: &str,
        account_id: AccountId,
    ) -> Result<(), StorageError> {
        let invitation_id = invitation_id.to_string();

        self.db
            .call(move |conn| {
                let affected = conn.execute(
                    "UPDATE calendar_invitations SET status = 'rejected'
                     WHERE id = ?1 AND status = 'pending'
                       AND invitee_email IN (SELECT email FROM accounts WHERE id = ?2)",
                    params![invitation_id, account_id.to_string()],
                )?;
                if affected == 0 {
                    return Err(StorageError::NotAuthorized);
                }
                Ok(())
            })
            .await
    }

    /// Create an **outbound** federation: we own `calendar_id` and will serve it
    /// to a peer. Generates the shared `federation_id` and a fresh capability
    /// secret (both handed to the peer in the signed invitation). Active
    /// immediately — possession of the capability plus the peer's server
    /// signature are the gates on the serve path.
    /// Returns `(federation_id, capability_secret)`; both are handed to the peer
    /// in the signed invitation. The capability is a fresh 256-bit secret.
    pub async fn create_outbound_federation(
        &self,
        calendar_id: CalendarId,
        target_email: &str,
        target_server_url: &str,
        sharing_type: SharingType,
        peer_domain: &str,
        peer_fingerprint: &str,
    ) -> Result<(String, String), StorageError> {
        let id = uuid::Uuid::now_v7().to_string();
        let capability = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let permissions = match sharing_type {
            SharingType::Sharing => Permissions::sharing(),
            SharingType::Delegation => Permissions::delegation(),
        };
        let permissions_json = serde_json::to_string(&permissions)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let (target_email, target_server_url, peer_domain, peer_fingerprint) = (
            target_email.to_owned(),
            target_server_url.to_owned(),
            peer_domain.to_owned(),
            peer_fingerprint.to_owned(),
        );
        let out = (id.clone(), capability.clone());
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO calendar_federation
                       (id, calendar_id, target_email, target_server_url, sharing_type,
                        permissions, status, created_at, peer_domain, peer_fingerprint,
                        capability_secret, direction)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'accepted', ?7, ?8, ?9, ?10, 'outbound')",
                    params![
                        id,
                        calendar_id.to_string(),
                        target_email,
                        target_server_url,
                        sharing_type.as_str(),
                        permissions_json,
                        crate::unix_now(),
                        peer_domain,
                        peer_fingerprint,
                        capability,
                    ],
                )?;
                Ok(out)
            })
            .await
    }

    /// Create an **inbound** federation: we subscribe to a peer's calendar and
    /// pull its events into the local mirror calendar `calendar_id`. Keyed on
    /// the shared `federation_id` minted by the serving peer. Starts `pending`
    /// until the local invitee accepts.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_inbound_federation(
        &self,
        federation_id: &str,
        calendar_id: CalendarId,
        source_email: &str,
        source_server_url: &str,
        sharing_type: SharingType,
        peer_domain: &str,
        peer_fingerprint: &str,
        capability_secret: &str,
    ) -> Result<(), StorageError> {
        let permissions = match sharing_type {
            SharingType::Sharing => Permissions::sharing(),
            SharingType::Delegation => Permissions::delegation(),
        };
        let permissions_json = serde_json::to_string(&permissions)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let (fed_id, source_email, source_server_url, peer_domain, peer_fingerprint, cap) = (
            federation_id.to_owned(),
            source_email.to_owned(),
            source_server_url.to_owned(),
            peer_domain.to_owned(),
            peer_fingerprint.to_owned(),
            capability_secret.to_owned(),
        );
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO calendar_federation
                       (id, calendar_id, target_email, target_server_url, sharing_type,
                        permissions, status, created_at, peer_domain, peer_fingerprint,
                        capability_secret, direction)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?9, ?10, 'inbound')",
                    params![
                        fed_id,
                        calendar_id.to_string(),
                        source_email,
                        source_server_url,
                        sharing_type.as_str(),
                        permissions_json,
                        crate::unix_now(),
                        peer_domain,
                        peer_fingerprint,
                        cap,
                    ],
                )?;
                Ok(())
            })
            .await
    }

    /// Accept an inbound federation, scoped to the account that owns the local
    /// mirror calendar. Flips `pending -> accepted`; the sync worker then pulls.
    pub async fn accept_inbound_federation(
        &self,
        federation_id: &str,
        account_id: AccountId,
    ) -> Result<(), StorageError> {
        let federation_id = federation_id.to_owned();
        self.db
            .call(move |conn| {
                let affected = conn.execute(
                    "UPDATE calendar_federation SET status = 'accepted'
                     WHERE id = ?1 AND direction = 'inbound' AND status = 'pending'
                       AND calendar_id IN (SELECT id FROM calendars WHERE account_id = ?2)",
                    params![federation_id, account_id.to_string()],
                )?;
                if affected == 0 {
                    return Err(StorageError::NotAuthorized);
                }
                Ok(())
            })
            .await
    }

    /// Reject a pending inbound federation, scoped to the mirror-calendar owner.
    pub async fn reject_inbound_federation(
        &self,
        federation_id: &str,
        account_id: AccountId,
    ) -> Result<(), StorageError> {
        let federation_id = federation_id.to_owned();
        self.db
            .call(move |conn| {
                let affected = conn.execute(
                    "UPDATE calendar_federation SET status = 'rejected'
                     WHERE id = ?1 AND direction = 'inbound' AND status = 'pending'
                       AND calendar_id IN (SELECT id FROM calendars WHERE account_id = ?2)",
                    params![federation_id, account_id.to_string()],
                )?;
                if affected == 0 {
                    return Err(StorageError::NotAuthorized);
                }
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
        let sql = format!("SELECT {FEDERATION_COLUMNS} FROM calendar_federation WHERE id = ?1");
        self.db
            .call(move |conn| {
                conn.query_row(&sql, [federation_id], federation_from_row)
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
                            parse_id(0, &row.get::<_, String>(0)?)?,
                            false, // is_deleted: would need soft delete tracking
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(events)
            })
            .await
    }

    /// Pending inbound federation invitations addressed to `account_id` (the
    /// local invitee, who owns the mirror calendar).
    pub async fn list_pending_inbound_federations(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<CalendarFederation>, StorageError> {
        let sql = format!(
            "SELECT {FEDERATION_COLUMNS} FROM calendar_federation
             WHERE direction = 'inbound' AND status = 'pending'
               AND calendar_id IN (SELECT id FROM calendars WHERE account_id = ?1)
             ORDER BY created_at"
        );
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(&sql)?;
                let feds = stmt
                    .query_map(params![account_id.to_string()], federation_from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(feds)
            })
            .await
    }

    /// Active **inbound** federations that need pulling (the subscriber side).
    pub async fn list_active_federations(&self) -> Result<Vec<CalendarFederation>, StorageError> {
        let sql = format!(
            "SELECT {FEDERATION_COLUMNS} FROM calendar_federation
             WHERE status IN ('accepted', 'syncing') AND direction = 'inbound'
             ORDER BY last_sync_at ASC NULLS FIRST"
        );
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(&sql)?;
                let federations = stmt
                    .query_map([], federation_from_row)?
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

        storage
            .accept_sharing(&sharing.id, bob.id)
            .await
            .expect("accept");

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

        // The invitee is bob@remote.example.com; accepting requires a local
        // account whose email matches. Create it, then accept as that account.
        let bob = storage
            .create_account("bob@remote.example.com", None)
            .await
            .expect("bob");
        storage
            .accept_federation_invitation(&invitation.id, bob.id)
            .await
            .expect("accept");

        storage.close();
    }

    #[tokio::test]
    async fn cannot_share_calendar_you_do_not_own() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let mallory = storage
            .create_account("mallory@example.com", None)
            .await
            .expect("mallory");

        // Alice owns the calendar.
        let calendar = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("calendar");

        // Mallory tries to share Alice's calendar with herself — must be denied
        // and must write nothing.
        let result = storage
            .share_calendar(
                calendar.id,
                mallory.id,
                mallory.id,
                super::SharingType::Delegation,
            )
            .await;
        assert!(matches!(
            result,
            Err(crate::error::StorageError::NotAuthorized)
        ));

        // Mallory gained no access.
        assert!(
            storage
                .calendar_access(mallory.id, calendar.id)
                .await
                .expect("access")
                .is_none()
        );
        assert_eq!(
            storage
                .get_shared_calendars(mallory.id)
                .await
                .expect("shared")
                .len(),
            0
        );

        storage.close();
    }

    #[tokio::test]
    async fn cannot_accept_sharing_addressed_to_another_account() {
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
        let mallory = storage
            .create_account("mallory@example.com", None)
            .await
            .expect("mallory");

        let calendar = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("calendar");

        // Alice shares with Bob.
        let sharing = storage
            .share_calendar(calendar.id, alice.id, bob.id, super::SharingType::Sharing)
            .await
            .expect("share");

        // Mallory tries to accept Bob's invitation — denied.
        let result = storage.accept_sharing(&sharing.id, mallory.id).await;
        assert!(matches!(
            result,
            Err(crate::error::StorageError::NotAuthorized)
        ));

        // Still pending; Mallory has no access.
        assert!(
            storage
                .calendar_access(mallory.id, calendar.id)
                .await
                .expect("access")
                .is_none()
        );

        storage.close();
    }

    #[tokio::test]
    async fn calendar_access_reflects_ownership_and_accepted_shares() {
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
        let stranger = storage
            .create_account("stranger@example.com", None)
            .await
            .expect("stranger");

        let calendar = storage
            .create_calendar(alice.id, "Personal".to_string(), None)
            .await
            .expect("calendar");

        // Owner has full access.
        let owner_perms = storage
            .calendar_access(alice.id, calendar.id)
            .await
            .expect("owner access")
            .expect("some");
        assert!(owner_perms.admin && owner_perms.edit_events);

        // Unrelated account: no access.
        assert!(
            storage
                .calendar_access(stranger.id, calendar.id)
                .await
                .expect("stranger access")
                .is_none()
        );

        // Pending share grants nothing yet.
        let sharing = storage
            .share_calendar(calendar.id, alice.id, bob.id, super::SharingType::Sharing)
            .await
            .expect("share");
        assert!(
            storage
                .calendar_access(bob.id, calendar.id)
                .await
                .expect("bob pending")
                .is_none()
        );

        // After accepting, Bob gets exactly the sharing (read-only) permissions.
        storage
            .accept_sharing(&sharing.id, bob.id)
            .await
            .expect("accept");
        let bob_perms = storage
            .calendar_access(bob.id, calendar.id)
            .await
            .expect("bob access")
            .expect("some");
        assert!(bob_perms.view_events);
        assert!(!bob_perms.edit_events);

        // And it surfaces in the accepted-shares list.
        let shared = storage
            .list_accepted_shared_calendar_ids(bob.id)
            .await
            .expect("list");
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].0, calendar.id);

        storage.close();
    }
}
