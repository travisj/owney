//! PGP key persistence: pointers to (blob-store-encrypted) secret certs and
//! the harvested peer key table that Autocrypt maintains.

use owney_core::{AccountId, BlobId};
use rusqlite::{OptionalExtension, params};

use crate::error::StorageError;
use crate::{Storage, unix_now};

/// A harvested correspondent key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgpPeer {
    pub address: String,
    pub cert: Vec<u8>,
    pub fingerprint: String,
    pub prefer_encrypt: Option<String>,
    pub last_seen: i64,
}

impl Storage {
    pub async fn pgp_own_key(
        &self,
        account_id: AccountId,
    ) -> Result<Option<(String, BlobId)>, StorageError> {
        self.db
            .call(move |conn| {
                let row: Option<(String, String)> = conn
                    .query_row(
                        "SELECT fingerprint, blob_id FROM pgp_own_keys WHERE account_id = ?1",
                        [account_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match row {
                    Some((fingerprint, blob_hex)) => {
                        let blob_id = blob_hex.parse().map_err(|_| {
                            StorageError::Corrupt(format!("bad pgp blob id {blob_hex}"))
                        })?;
                        Ok(Some((fingerprint, blob_id)))
                    }
                    None => Ok(None),
                }
            })
            .await
    }

    pub async fn set_pgp_own_key(
        &self,
        account_id: AccountId,
        fingerprint: &str,
        blob_id: BlobId,
    ) -> Result<(), StorageError> {
        let fingerprint = fingerprint.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO pgp_own_keys (account_id, fingerprint, blob_id, created_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (account_id) DO UPDATE
                       SET fingerprint = excluded.fingerprint, blob_id = excluded.blob_id",
                    params![
                        account_id.to_string(),
                        fingerprint,
                        blob_id.to_hex(),
                        unix_now()
                    ],
                )?;
                Ok(())
            })
            .await
    }

    /// Record a harvested peer key. Returns true when the fingerprint changed
    /// for a previously known peer — the caller raises a SecurityEvent.
    pub async fn upsert_pgp_peer(
        &self,
        account_id: AccountId,
        address: &str,
        cert: Vec<u8>,
        fingerprint: &str,
        prefer_encrypt: Option<String>,
    ) -> Result<bool, StorageError> {
        let address = address.trim().to_lowercase();
        let fingerprint = fingerprint.to_owned();
        self.db
            .call(move |conn| {
                let previous: Option<String> = conn
                    .query_row(
                        "SELECT fingerprint FROM pgp_peers
                         WHERE account_id = ?1 AND address = ?2",
                        params![account_id.to_string(), address],
                        |row| row.get(0),
                    )
                    .optional()?;
                let changed = matches!(&previous, Some(old) if old != &fingerprint);

                conn.execute(
                    "INSERT INTO pgp_peers
                       (account_id, address, cert, fingerprint, prefer_encrypt, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT (account_id, address) DO UPDATE SET
                       cert = excluded.cert,
                       fingerprint = excluded.fingerprint,
                       prefer_encrypt = excluded.prefer_encrypt,
                       last_seen = excluded.last_seen",
                    params![
                        account_id.to_string(),
                        address,
                        cert,
                        fingerprint,
                        prefer_encrypt,
                        unix_now(),
                    ],
                )?;
                Ok(changed)
            })
            .await
    }

    pub async fn pgp_peer(
        &self,
        account_id: AccountId,
        address: &str,
    ) -> Result<Option<PgpPeer>, StorageError> {
        let address = address.trim().to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT address, cert, fingerprint, prefer_encrypt, last_seen
                         FROM pgp_peers WHERE account_id = ?1 AND address = ?2",
                        params![account_id.to_string(), address],
                        |row| {
                            Ok(PgpPeer {
                                address: row.get(0)?,
                                cert: row.get(1)?,
                                fingerprint: row.get(2)?,
                                prefer_encrypt: row.get(3)?,
                                last_seen: row.get(4)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    /// Record the PGP disposition of a stored message.
    pub async fn set_pgp_status(
        &self,
        email_id: owney_core::EmailId,
        status: &str,
    ) -> Result<(), StorageError> {
        let status = status.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE emails SET pgp_status = ?2 WHERE id = ?1",
                    params![email_id.to_string(), status],
                )?;
                Ok(())
            })
            .await
    }
}
