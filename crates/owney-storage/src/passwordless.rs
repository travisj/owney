//! Passwordless authentication storage: passkeys, recovery codes, devices, approvals.

use crate::error::StorageError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Stored passkey credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: Vec<u8>,
    pub account_id: String,
    pub device_name: String,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub aaguid: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub disabled: bool,
}

/// Stored recovery code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    pub id: String,
    pub account_id: String,
    pub code_hash: String,
    pub display_code: String, // "XXXX-XXXX-XXXX" format for user identification
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Paired device for approval requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePairing {
    pub id: String,
    pub account_id: String,
    pub device_name: String,
    pub device_type: String, // "ios", "android", "macos", etc.
    pub public_key: Vec<u8>,
    pub can_approve: bool,
    pub push_token: Option<String>,
    pub paired_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub disabled: bool,
}

/// Approval request for cross-device login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub account_id: String,
    pub source_device: String, // e.g., "San Francisco, CA (192.0.2.1)"
    pub request_type: String,  // "web_login", "app_login", etc.
    pub challenge: String,     // Random challenge for verification
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: String, // "pending", "approved", "denied", "expired"
    pub approved_by_device: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
}

impl crate::Storage {
    // ========================================================================
    // Passkey Credential Methods
    // ========================================================================

    /// Save a new passkey credential.
    pub async fn save_passkey_credential(
        &self,
        credential: &PasskeyCredential,
    ) -> Result<(), StorageError> {
        let cred = credential.clone();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO passkey_credentials
                     (id, account_id, device_name, public_key, counter,
                      backup_eligible, backup_state, aaguid, created_at, last_used_at, disabled)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rusqlite::params![
                        cred.id.as_slice(),
                        cred.account_id,
                        cred.device_name,
                        cred.public_key.as_slice(),
                        cred.counter,
                        if cred.backup_eligible { 1 } else { 0 },
                        if cred.backup_state { 1 } else { 0 },
                        cred.aaguid.as_deref(),
                        cred.created_at.timestamp(),
                        cred.last_used_at.map(|t| t.timestamp()),
                        if cred.disabled { 1 } else { 0 },
                    ],
                )
                .map_err(|e| StorageError::Corrupt(e.to_string()))?;
                Ok(())
            })
            .await
    }

    /// Retrieve a passkey credential by ID.
    pub async fn get_passkey_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, StorageError> {
        let id = credential_id.to_vec();
        self.db
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, account_id, device_name, public_key, counter,
                            backup_eligible, backup_state, aaguid, created_at, last_used_at, disabled
                     FROM passkey_credentials
                     WHERE id = ?1",
                    rusqlite::params![id.as_slice()],
                    |row| {
                        Ok(PasskeyCredential {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            device_name: row.get(2)?,
                            public_key: row.get(3)?,
                            counter: row.get(4)?,
                            backup_eligible: row.get::<_, i32>(5)? != 0,
                            backup_state: row.get::<_, i32>(6)? != 0,
                            aaguid: row.get(7)?,
                            created_at: DateTime::<Utc>::from_timestamp(row.get(8)?, 0)
                                .unwrap_or_else(Utc::now),
                            last_used_at: row
                                .get::<_, Option<i64>>(9)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                            disabled: row.get::<_, i32>(10)? != 0,
                        })
                    },
                )
                .optional()
                .map_err(|e| StorageError::Database(e.to_string()))
            })
            .await
    }

    /// List all active passkeys for an account.
    pub async fn list_passkeys_for_account(
        &self,
        account_id: String,
    ) -> Result<Vec<PasskeyCredential>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, account_id, device_name, public_key, counter,
                                backup_eligible, backup_state, aaguid, created_at, last_used_at, disabled
                         FROM passkey_credentials
                         WHERE account_id = ?1 AND disabled = 0
                         ORDER BY created_at DESC",
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                let credentials = stmt
                    .query_map(rusqlite::params![account_id], |row| {
                        Ok(PasskeyCredential {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            device_name: row.get(2)?,
                            public_key: row.get(3)?,
                            counter: row.get(4)?,
                            backup_eligible: row.get::<_, i32>(5)? != 0,
                            backup_state: row.get::<_, i32>(6)? != 0,
                            aaguid: row.get(7)?,
                            created_at: DateTime::<Utc>::from_timestamp(row.get(8)?, 0)
                                .unwrap_or_else(Utc::now),
                            last_used_at: row
                                .get::<_, Option<i64>>(9)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                            disabled: row.get::<_, i32>(10)? != 0,
                        })
                    })
                    .map_err(|e| StorageError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                Ok(credentials)
            })
            .await
    }

    /// Update passkey counter and last_used_at.
    pub async fn update_passkey_counter(
        &self,
        credential_id: &[u8],
        new_counter: u32,
    ) -> Result<(), StorageError> {
        let id = credential_id.to_vec();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE passkey_credentials
                     SET counter = ?1, last_used_at = ?2
                     WHERE id = ?3",
                    rusqlite::params![
                        new_counter,
                        Utc::now().timestamp(),
                        id.as_slice()
                    ],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    /// Disable a passkey (soft delete).
    pub async fn disable_passkey(&self, credential_id: &[u8]) -> Result<(), StorageError> {
        let id = credential_id.to_vec();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE passkey_credentials SET disabled = 1 WHERE id = ?1",
                    rusqlite::params![id.as_slice()],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    // ========================================================================
    // Recovery Code Methods
    // ========================================================================

    /// Save recovery codes (already hashed).
    pub async fn save_recovery_codes(
        &self,
        account_id: String,
        codes: &[RecoveryCode],
    ) -> Result<(), StorageError> {
        let codes = codes.to_vec();
        self.db
            .call(move |conn| {
                for code in &codes {
                    conn.execute(
                        "INSERT INTO recovery_codes
                         (id, account_id, code_hash, display_code, used, created_at)
                         VALUES (?, ?, ?, ?, ?, ?)",
                        rusqlite::params![
                            code.id,
                            account_id,
                            code.code_hash,
                            code.display_code,
                            if code.used { 1 } else { 0 },
                            code.created_at.timestamp(),
                        ],
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;
                }
                Ok(())
            })
            .await
    }

    /// List all recovery codes for an account.
    pub async fn get_recovery_codes(
        &self,
        account_id: String,
    ) -> Result<Vec<RecoveryCode>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, account_id, code_hash, display_code, used, used_at, created_at
                         FROM recovery_codes
                         WHERE account_id = ?1
                         ORDER BY created_at DESC",
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                let codes = stmt
                    .query_map(rusqlite::params![account_id], |row| {
                        Ok(RecoveryCode {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            code_hash: row.get(2)?,
                            display_code: row.get(3)?,
                            used: row.get::<_, i32>(4)? != 0,
                            used_at: row
                                .get::<_, Option<i64>>(5)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                            created_at: DateTime::<Utc>::from_timestamp(row.get(6)?, 0)
                                .unwrap_or_else(Utc::now),
                        })
                    })
                    .map_err(|e| StorageError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                Ok(codes)
            })
            .await
    }

    /// Get an unused recovery code by its hash.
    pub async fn get_recovery_code_by_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<RecoveryCode>, StorageError> {
        let hash = code_hash.to_string();
        self.db
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, account_id, code_hash, display_code, used, used_at, created_at
                     FROM recovery_codes
                     WHERE code_hash = ?1 AND used = 0",
                    rusqlite::params![hash],
                    |row| {
                        Ok(RecoveryCode {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            code_hash: row.get(2)?,
                            display_code: row.get(3)?,
                            used: row.get::<_, i32>(4)? != 0,
                            used_at: row
                                .get::<_, Option<i64>>(5)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                            created_at: DateTime::<Utc>::from_timestamp(row.get(6)?, 0)
                                .unwrap_or_else(Utc::now),
                        })
                    },
                )
                .optional()
                .map_err(|e| StorageError::Database(e.to_string()))
            })
            .await
    }

    /// Mark a recovery code as used.
    pub async fn mark_recovery_code_used(&self, code_id: &str) -> Result<(), StorageError> {
        let id = code_id.to_string();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE recovery_codes
                     SET used = 1, used_at = ?1
                     WHERE id = ?2",
                    rusqlite::params![Utc::now().timestamp(), id],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    // ========================================================================
    // Device Pairing Methods
    // ========================================================================

    /// Save a new device pairing.
    pub async fn save_device_pairing(&self, device: &DevicePairing) -> Result<(), StorageError> {
        let device = device.clone();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO device_pairings
                     (id, account_id, device_name, device_type, public_key,
                      can_approve, push_token, paired_at, last_used_at, disabled)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rusqlite::params![
                        device.id,
                        device.account_id,
                        device.device_name,
                        device.device_type,
                        device.public_key.as_slice(),
                        if device.can_approve { 1 } else { 0 },
                        device.push_token,
                        device.paired_at.timestamp(),
                        device.last_used_at.map(|t| t.timestamp()),
                        if device.disabled { 1 } else { 0 },
                    ],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    /// Get a device pairing by ID.
    pub async fn get_device_pairing(&self, device_id: &str) -> Result<Option<DevicePairing>, StorageError> {
        let id = device_id.to_string();
        self.db
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, account_id, device_name, device_type, public_key,
                            can_approve, push_token, paired_at, last_used_at, disabled
                     FROM device_pairings
                     WHERE id = ?1",
                    rusqlite::params![id],
                    |row| {
                        Ok(DevicePairing {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            device_name: row.get(2)?,
                            device_type: row.get(3)?,
                            public_key: row.get(4)?,
                            can_approve: row.get::<_, i32>(5)? != 0,
                            push_token: row.get(6)?,
                            paired_at: DateTime::<Utc>::from_timestamp(row.get(7)?, 0)
                                .unwrap_or_else(Utc::now),
                            last_used_at: row
                                .get::<_, Option<i64>>(8)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                            disabled: row.get::<_, i32>(9)? != 0,
                        })
                    },
                )
                .optional()
                .map_err(|e| StorageError::Database(e.to_string()))
            })
            .await
    }

    /// List all active devices for an account.
    pub async fn list_devices_for_account(
        &self,
        account_id: String,
    ) -> Result<Vec<DevicePairing>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, account_id, device_name, device_type, public_key,
                                can_approve, push_token, paired_at, last_used_at, disabled
                         FROM device_pairings
                         WHERE account_id = ?1 AND disabled = 0
                         ORDER BY paired_at DESC",
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                let devices = stmt
                    .query_map(rusqlite::params![account_id], |row| {
                        Ok(DevicePairing {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            device_name: row.get(2)?,
                            device_type: row.get(3)?,
                            public_key: row.get(4)?,
                            can_approve: row.get::<_, i32>(5)? != 0,
                            push_token: row.get(6)?,
                            paired_at: DateTime::<Utc>::from_timestamp(row.get(7)?, 0)
                                .unwrap_or_else(Utc::now),
                            last_used_at: row
                                .get::<_, Option<i64>>(8)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                            disabled: row.get::<_, i32>(9)? != 0,
                        })
                    })
                    .map_err(|e| StorageError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                Ok(devices)
            })
            .await
    }

    /// Update device last_used_at.
    pub async fn update_device_last_used(&self, device_id: &str) -> Result<(), StorageError> {
        let id = device_id.to_string();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE device_pairings SET last_used_at = ?1 WHERE id = ?2",
                    rusqlite::params![Utc::now().timestamp(), id],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    /// Disable a device (soft delete).
    pub async fn disable_device(&self, device_id: &str) -> Result<(), StorageError> {
        let id = device_id.to_string();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE device_pairings SET disabled = 1 WHERE id = ?1",
                    rusqlite::params![id],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    // ========================================================================
    // Approval Request Methods
    // ========================================================================

    /// Create an approval request.
    pub async fn save_approval_request(
        &self,
        request: &ApprovalRequest,
    ) -> Result<(), StorageError> {
        let req = request.clone();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO approval_requests
                     (id, account_id, source_device, request_type, challenge,
                      created_at, expires_at, status, approved_by_device, approved_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rusqlite::params![
                        req.id,
                        req.account_id,
                        req.source_device,
                        req.request_type,
                        req.challenge,
                        req.created_at.timestamp(),
                        req.expires_at.timestamp(),
                        req.status,
                        req.approved_by_device,
                        req.approved_at.map(|t| t.timestamp()),
                    ],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    /// Get an approval request by ID.
    pub async fn get_approval_request(
        &self,
        request_id: &str,
    ) -> Result<Option<ApprovalRequest>, StorageError> {
        let id = request_id.to_string();
        self.db
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, account_id, source_device, request_type, challenge,
                            created_at, expires_at, status, approved_by_device, approved_at
                     FROM approval_requests
                     WHERE id = ?1",
                    rusqlite::params![id],
                    |row| {
                        Ok(ApprovalRequest {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            source_device: row.get(2)?,
                            request_type: row.get(3)?,
                            challenge: row.get(4)?,
                            created_at: DateTime::<Utc>::from_timestamp(row.get(5)?, 0)
                                .unwrap_or_else(Utc::now),
                            expires_at: DateTime::<Utc>::from_timestamp(row.get(6)?, 0)
                                .unwrap_or_else(Utc::now),
                            status: row.get(7)?,
                            approved_by_device: row.get(8)?,
                            approved_at: row
                                .get::<_, Option<i64>>(9)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                        })
                    },
                )
                .optional()
                .map_err(|e| StorageError::Database(e.to_string()))
            })
            .await
    }

    /// List pending approval requests for an account.
    pub async fn get_pending_approval_requests(
        &self,
        account_id: String,
    ) -> Result<Vec<ApprovalRequest>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, account_id, source_device, request_type, challenge,
                                created_at, expires_at, status, approved_by_device, approved_at
                         FROM approval_requests
                         WHERE account_id = ?1 AND status = 'pending' AND expires_at > ?2
                         ORDER BY created_at DESC",
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                let now = Utc::now().timestamp();
                let requests = stmt
                    .query_map(rusqlite::params![account_id, now], |row| {
                        Ok(ApprovalRequest {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            source_device: row.get(2)?,
                            request_type: row.get(3)?,
                            challenge: row.get(4)?,
                            created_at: DateTime::<Utc>::from_timestamp(row.get(5)?, 0)
                                .unwrap_or_else(Utc::now),
                            expires_at: DateTime::<Utc>::from_timestamp(row.get(6)?, 0)
                                .unwrap_or_else(Utc::now),
                            status: row.get(7)?,
                            approved_by_device: row.get(8)?,
                            approved_at: row
                                .get::<_, Option<i64>>(9)?
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0)),
                        })
                    })
                    .map_err(|e| StorageError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                Ok(requests)
            })
            .await
    }

    /// Update an approval request status.
    pub async fn update_approval_request_status(
        &self,
        request_id: &str,
        status: &str,
        approved_by_device: Option<&str>,
    ) -> Result<(), StorageError> {
        let req_id = request_id.to_string();
        let st = status.to_string();
        let device_id = approved_by_device.map(|d| d.to_string());
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE approval_requests
                     SET status = ?1, approved_by_device = ?2, approved_at = ?3
                     WHERE id = ?4",
                    rusqlite::params![
                        st,
                        device_id,
                        Utc::now().timestamp(),
                        req_id
                    ],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    async fn open_storage(dir: &Path) -> crate::Storage {
        let events = owney_events::EventBus::new(64);
        crate::Storage::open(dir, events).expect("open")
    }

    #[tokio::test]
    async fn test_passkey_crud() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = open_storage(dir.path()).await;

        // Create account
        let account = storage
            .create_account("test@example.com", None)
            .await
            .expect("create account");

        // Create passkey
        let cred = PasskeyCredential {
            id: b"cred-123".to_vec(),
            account_id: account.id.to_string(),
            device_name: "iPhone 15".to_string(),
            public_key: b"pubkey-data".to_vec(),
            counter: 0,
            backup_eligible: true,
            backup_state: false,
            aaguid: Some(b"aaguid-data".to_vec()),
            created_at: Utc::now(),
            last_used_at: None,
            disabled: false,
        };

        // Save it
        storage.save_passkey_credential(&cred).await.expect("save");

        // Retrieve it
        let retrieved = storage
            .get_passkey_credential(&cred.id)
            .await
            .expect("get")
            .expect("found");

        assert_eq!(retrieved.id, cred.id);
        assert_eq!(retrieved.device_name, "iPhone 15");
        assert_eq!(retrieved.counter, 0);

        // Update counter
        storage
            .update_passkey_counter(&cred.id, 5)
            .await
            .expect("update");

        let updated = storage
            .get_passkey_credential(&cred.id)
            .await
            .expect("get")
            .expect("found");
        assert_eq!(updated.counter, 5);

        storage.close();
    }

    #[tokio::test]
    async fn test_recovery_codes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = open_storage(dir.path()).await;

        // Create account
        let account = storage
            .create_account("test@example.com", None)
            .await
            .expect("create account");

        // Create recovery codes
        let codes = vec![
            RecoveryCode {
                id: "code-1".to_string(),
                account_id: account.id.to_string(),
                code_hash: "hash1".to_string(),
                display_code: "XXXX-XXXX-XXXX".to_string(),
                used: false,
                used_at: None,
                created_at: Utc::now(),
            },
            RecoveryCode {
                id: "code-2".to_string(),
                account_id: account.id.to_string(),
                code_hash: "hash2".to_string(),
                display_code: "YYYY-YYYY-YYYY".to_string(),
                used: false,
                used_at: None,
                created_at: Utc::now(),
            },
        ];

        // Save them
        storage
            .save_recovery_codes(account.id.to_string(), &codes)
            .await
            .expect("save");

        // List them
        let retrieved = storage
            .get_recovery_codes(account.id.to_string())
            .await
            .expect("list");

        assert_eq!(retrieved.len(), 2);

        // Get by hash
        let by_hash = storage
            .get_recovery_code_by_hash("hash1")
            .await
            .expect("get")
            .expect("found");

        assert_eq!(by_hash.display_code, "XXXX-XXXX-XXXX");

        // Mark as used
        storage
            .mark_recovery_code_used(&by_hash.id)
            .await
            .expect("mark");

        // Shouldn't find it anymore (used)
        let not_found = storage
            .get_recovery_code_by_hash("hash1")
            .await
            .expect("get");

        assert!(not_found.is_none());

        storage.close();
    }

    #[tokio::test]
    async fn test_device_pairings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = open_storage(dir.path()).await;

        // Create account
        let account = storage
            .create_account("test@example.com", None)
            .await
            .expect("create account");

        // Create device
        let device = DevicePairing {
            id: "device-1".to_string(),
            account_id: account.id.to_string(),
            device_name: "iPhone 15".to_string(),
            device_type: "ios".to_string(),
            public_key: b"device-pubkey".to_vec(),
            can_approve: true,
            push_token: Some("fcm-token-123".to_string()),
            paired_at: Utc::now(),
            last_used_at: None,
            disabled: false,
        };

        // Save it
        storage.save_device_pairing(&device).await.expect("save");

        // Retrieve it
        let retrieved = storage
            .get_device_pairing("device-1")
            .await
            .expect("get")
            .expect("found");

        assert_eq!(retrieved.device_name, "iPhone 15");
        assert_eq!(retrieved.device_type, "ios");

        // List devices
        let devices = storage
            .list_devices_for_account(account.id.to_string())
            .await
            .expect("list");

        assert_eq!(devices.len(), 1);

        storage.close();
    }

    #[tokio::test]
    async fn test_approval_requests() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = open_storage(dir.path()).await;

        // Create account
        let account = storage
            .create_account("test@example.com", None)
            .await
            .expect("create account");

        // Create approval request
        let now = Utc::now();
        let request = ApprovalRequest {
            id: "req-1".to_string(),
            account_id: account.id.to_string(),
            source_device: "San Francisco, CA (192.0.2.1)".to_string(),
            request_type: "web_login".to_string(),
            challenge: "challenge-123".to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(10),
            status: "pending".to_string(),
            approved_by_device: None,
            approved_at: None,
        };

        // Save it
        storage
            .save_approval_request(&request)
            .await
            .expect("save");

        // Retrieve it
        let retrieved = storage
            .get_approval_request("req-1")
            .await
            .expect("get")
            .expect("found");

        assert_eq!(retrieved.status, "pending");
        assert_eq!(retrieved.request_type, "web_login");

        // Update status
        storage
            .update_approval_request_status("req-1", "approved", Some("device-1"))
            .await
            .expect("update");

        let updated = storage
            .get_approval_request("req-1")
            .await
            .expect("get")
            .expect("found");

        assert_eq!(updated.status, "approved");
        assert_eq!(updated.approved_by_device, Some("device-1".to_string()));

        storage.close();
    }
}
