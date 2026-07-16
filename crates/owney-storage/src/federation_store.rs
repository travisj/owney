//! Storage for secure calendar federation: this server's identity keypair
//! pointer, pinned peer server certs, the replay-nonce cache, the remote-event
//! id mapping (which keeps a peer from ever addressing a local event by its raw
//! id), and the durable delivery outbox.

use owney_core::{BlobId, CalendarId, EventId};
use rusqlite::{OptionalExtension, params};

use crate::error::StorageError;
use crate::{Storage, unix_now};

/// A pinned peer server (public cert + verified origin), keyed by domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerServer {
    pub domain: String,
    pub server_url: String,
    pub cert: Vec<u8>,
    pub fingerprint: String,
    pub pinned_at: i64,
}

/// A claimed federation delivery ready to send.
#[derive(Debug, Clone)]
pub struct FederationOutboxItem {
    pub id: String,
    pub federation_id: String,
    pub peer_domain: String,
    pub payload: Vec<u8>,
    pub attempts: i64,
}

impl Storage {
    // ---- server identity -------------------------------------------------

    /// This server's PGP identity (fingerprint + blob pointer to the secret
    /// TSK), or `None` before first generation.
    pub async fn server_identity(&self) -> Result<Option<(String, BlobId)>, StorageError> {
        self.db
            .call(move |conn| {
                let row: Option<(String, String)> = conn
                    .query_row(
                        "SELECT fingerprint, blob_id FROM server_identity WHERE id = 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match row {
                    Some((fp, blob_hex)) => {
                        let blob_id = blob_hex.parse().map_err(|_| {
                            StorageError::Corrupt(format!("bad server identity blob id {blob_hex}"))
                        })?;
                        Ok(Some((fp, blob_id)))
                    }
                    None => Ok(None),
                }
            })
            .await
    }

    /// Persist the server identity (singleton row).
    pub async fn set_server_identity(
        &self,
        fingerprint: &str,
        blob_id: BlobId,
    ) -> Result<(), StorageError> {
        let fingerprint = fingerprint.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO server_identity (id, fingerprint, blob_id, created_at)
                     VALUES (1, ?1, ?2, ?3)
                     ON CONFLICT (id) DO UPDATE
                       SET fingerprint = excluded.fingerprint, blob_id = excluded.blob_id",
                    params![fingerprint, blob_id.to_hex(), unix_now()],
                )?;
                Ok(())
            })
            .await
    }

    // ---- peer server pinning --------------------------------------------

    /// Pin (or refresh) a peer server's public cert. Returns `true` when the
    /// fingerprint changed for an already-pinned domain — a key-swap the caller
    /// must treat as hostile (reject + raise a security event), never as an
    /// automatic update.
    pub async fn upsert_federation_peer(
        &self,
        domain: &str,
        server_url: &str,
        cert: Vec<u8>,
        fingerprint: &str,
    ) -> Result<bool, StorageError> {
        let domain = domain.trim().to_lowercase();
        let server_url = server_url.to_owned();
        let fingerprint = fingerprint.to_owned();
        self.db
            .call(move |conn| {
                let previous: Option<String> = conn
                    .query_row(
                        "SELECT fingerprint FROM federation_peers WHERE domain = ?1",
                        params![domain],
                        |row| row.get(0),
                    )
                    .optional()?;
                let changed = matches!(&previous, Some(old) if old != &fingerprint);

                conn.execute(
                    "INSERT INTO federation_peers
                       (domain, server_url, cert, fingerprint, pinned_at, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                     ON CONFLICT (domain) DO UPDATE SET
                       server_url = excluded.server_url,
                       cert = excluded.cert,
                       fingerprint = excluded.fingerprint,
                       last_seen = excluded.last_seen",
                    params![domain, server_url, cert, fingerprint, unix_now()],
                )?;
                Ok(changed)
            })
            .await
    }

    /// Look up a pinned peer server by domain.
    pub async fn federation_peer(&self, domain: &str) -> Result<Option<PeerServer>, StorageError> {
        let domain = domain.trim().to_lowercase();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT domain, server_url, cert, fingerprint, pinned_at
                         FROM federation_peers WHERE domain = ?1",
                        params![domain],
                        |row| {
                            Ok(PeerServer {
                                domain: row.get(0)?,
                                server_url: row.get(1)?,
                                cert: row.get(2)?,
                                fingerprint: row.get(3)?,
                                pinned_at: row.get(4)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    // ---- replay-nonce cache ---------------------------------------------

    /// Atomically record a request nonce. Returns `true` if it was fresh (and
    /// is now recorded), `false` if it was already seen — i.e. a replay.
    pub async fn check_and_record_nonce(
        &self,
        sender_fp: &str,
        nonce: &str,
        expires_at: i64,
    ) -> Result<bool, StorageError> {
        let sender_fp = sender_fp.to_owned();
        let nonce = nonce.to_owned();
        self.db
            .call(move |conn| {
                let inserted = conn.execute(
                    "INSERT INTO federation_replay_nonce (sender_fp, nonce, expires_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (sender_fp, nonce) DO NOTHING",
                    params![sender_fp, nonce, expires_at],
                )?;
                Ok(inserted == 1)
            })
            .await
    }

    /// Delete expired nonces (call periodically).
    pub async fn prune_expired_nonces(&self, now: i64) -> Result<usize, StorageError> {
        self.db
            .call(move |conn| {
                let n = conn.execute(
                    "DELETE FROM federation_replay_nonce WHERE expires_at <= ?1",
                    params![now],
                )?;
                Ok(n)
            })
            .await
    }

    // ---- remote-event id mapping ----------------------------------------

    /// The local event id a peer's `remote_uid` maps to within a federation,
    /// if any. Scoped to the federation so a remote uid can never resolve to
    /// an event outside the shared calendar.
    pub async fn federation_local_event(
        &self,
        federation_id: &str,
        remote_uid: &str,
    ) -> Result<Option<EventId>, StorageError> {
        let federation_id = federation_id.to_owned();
        let remote_uid = remote_uid.to_owned();
        self.db
            .call(move |conn| {
                let raw: Option<String> = conn
                    .query_row(
                        "SELECT local_event_id FROM federation_event_map
                         WHERE federation_id = ?1 AND remote_uid = ?2",
                        params![federation_id, remote_uid],
                        |row| row.get(0),
                    )
                    .optional()?;
                match raw {
                    Some(id) => id
                        .parse()
                        .map(Some)
                        .map_err(|_| StorageError::Corrupt(format!("bad mapped event id {id}"))),
                    None => Ok(None),
                }
            })
            .await
    }

    /// Record the mapping from a peer's `remote_uid` to a local event id.
    pub async fn set_federation_event_map(
        &self,
        federation_id: &str,
        remote_uid: &str,
        local_event_id: EventId,
        author_email: &str,
    ) -> Result<(), StorageError> {
        let federation_id = federation_id.to_owned();
        let remote_uid = remote_uid.to_owned();
        let author_email = author_email.to_owned();
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO federation_event_map
                       (federation_id, remote_uid, local_event_id, author_email, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (federation_id, remote_uid) DO UPDATE SET
                       local_event_id = excluded.local_event_id,
                       author_email = excluded.author_email,
                       updated_at = excluded.updated_at",
                    params![
                        federation_id,
                        remote_uid,
                        local_event_id.to_string(),
                        author_email,
                        unix_now()
                    ],
                )?;
                Ok(())
            })
            .await
    }

    // ---- delivery outbox -------------------------------------------------

    /// Enqueue a signed delivery to a peer.
    pub async fn fed_enqueue(
        &self,
        federation_id: &str,
        peer_domain: &str,
        payload: Vec<u8>,
    ) -> Result<String, StorageError> {
        let id = uuid::Uuid::now_v7().to_string();
        let federation_id = federation_id.to_owned();
        let peer_domain = peer_domain.to_owned();
        let out_id = id.clone();
        self.db
            .call(move |conn| {
                let now = unix_now();
                conn.execute(
                    "INSERT INTO federation_outbox
                       (id, federation_id, peer_domain, payload, attempts,
                        next_attempt, status, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, 0, ?5, 'queued', ?5, ?5)",
                    params![id, federation_id, peer_domain, payload, now],
                )?;
                Ok(out_id)
            })
            .await
    }

    /// Claim up to `limit` due deliveries, flipping them `queued -> sending`.
    pub async fn fed_due_items(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationOutboxItem>, StorageError> {
        self.db
            .call(move |conn| {
                let now = unix_now();
                let mut stmt = conn.prepare(
                    "UPDATE federation_outbox SET status = 'sending', updated_at = ?1
                     WHERE id IN (
                        SELECT id FROM federation_outbox
                        WHERE status = 'queued' AND next_attempt <= ?1
                        ORDER BY next_attempt
                        LIMIT ?2
                     )
                     RETURNING id, federation_id, peer_domain, payload, attempts",
                )?;
                let items = stmt
                    .query_map(params![now, limit as i64], |row| {
                        Ok(FederationOutboxItem {
                            id: row.get(0)?,
                            federation_id: row.get(1)?,
                            peer_domain: row.get(2)?,
                            payload: row.get(3)?,
                            attempts: row.get(4)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(items)
            })
            .await
    }

    /// Record the result of a delivery attempt. Success deletes the row; failure
    /// re-queues with exponential backoff until `max_attempts`, then marks
    /// `failed`.
    pub async fn fed_record_attempt(
        &self,
        id: &str,
        success: bool,
        error: Option<String>,
        max_attempts: i64,
    ) -> Result<(), StorageError> {
        let id = id.to_owned();
        self.db
            .call(move |conn| {
                if success {
                    conn.execute("DELETE FROM federation_outbox WHERE id = ?1", params![id])?;
                    return Ok(());
                }
                let attempts: i64 = conn.query_row(
                    "SELECT attempts FROM federation_outbox WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )?;
                let attempts = attempts + 1;
                if attempts >= max_attempts {
                    conn.execute(
                        "UPDATE federation_outbox
                         SET status = 'failed', attempts = ?2, last_error = ?3, updated_at = ?4
                         WHERE id = ?1",
                        params![id, attempts, error, unix_now()],
                    )?;
                } else {
                    // Exponential backoff capped at 1h: 2^attempts seconds.
                    let backoff = 2_i64.saturating_pow(attempts.min(12) as u32).min(3600);
                    let now = unix_now();
                    conn.execute(
                        "UPDATE federation_outbox
                         SET status = 'queued', attempts = ?2, last_error = ?3,
                             next_attempt = ?4, updated_at = ?5
                         WHERE id = ?1",
                        params![id, attempts, error, now + backoff, now],
                    )?;
                }
                Ok(())
            })
            .await
    }

    /// Return deliveries stuck in `sending` (e.g. a crash mid-send) to `queued`.
    pub async fn fed_reset_stale_claims(&self) -> Result<usize, StorageError> {
        self.db
            .call(move |conn| {
                let n = conn.execute(
                    "UPDATE federation_outbox SET status = 'queued', updated_at = ?1
                     WHERE status = 'sending'",
                    params![unix_now()],
                )?;
                Ok(n)
            })
            .await
    }

    /// Calendars that belong to `owner` and are federated outbound, with the
    /// peer to notify. Used by the realtime fan-out. (Defined here so the outbox
    /// path has everything it needs in one module.)
    pub async fn outbound_federations_for_calendar(
        &self,
        calendar_id: CalendarId,
    ) -> Result<Vec<(String, String)>, StorageError> {
        // Returns (federation_id, peer_domain).
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, peer_domain FROM calendar_federation
                     WHERE calendar_id = ?1 AND direction = 'outbound'
                       AND status IN ('accepted', 'syncing') AND peer_domain IS NOT NULL",
                )?;
                let rows = stmt
                    .query_map(params![calendar_id.to_string()], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    async fn harness(tmp: &tempfile::TempDir) -> (crate::Storage, owney_events::EventBus) {
        crate::tests::open(tmp.path()).await
    }

    #[tokio::test]
    async fn server_identity_persists_and_reloads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        assert!(storage.server_identity().await.expect("get").is_none());

        let blob = storage.put_blob(b"fake-tsk".to_vec()).await.expect("blob");
        storage
            .set_server_identity("ABCD1234", blob)
            .await
            .expect("set");

        let (fp, got_blob) = storage.server_identity().await.expect("get").expect("some");
        assert_eq!(fp, "ABCD1234");
        assert_eq!(got_blob, blob);

        storage.close();
    }

    #[tokio::test]
    async fn peer_pin_then_fingerprint_change_is_flagged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let changed = storage
            .upsert_federation_peer("b.com", "https://b.com", b"cert-v1".to_vec(), "FP1")
            .await
            .expect("pin");
        assert!(!changed, "first pin is not a change");

        // Same fingerprint again: not a change.
        let changed = storage
            .upsert_federation_peer("b.com", "https://b.com", b"cert-v1".to_vec(), "FP1")
            .await
            .expect("re-pin");
        assert!(!changed);

        // Different fingerprint for a pinned domain: hostile key-swap signal.
        let changed = storage
            .upsert_federation_peer("b.com", "https://b.com", b"cert-v2".to_vec(), "FP2")
            .await
            .expect("swap");
        assert!(changed, "fingerprint change must be flagged");

        let peer = storage
            .federation_peer("b.com")
            .await
            .expect("get")
            .expect("some");
        assert_eq!(peer.fingerprint, "FP2");

        storage.close();
    }

    #[tokio::test]
    async fn nonce_replay_is_rejected_and_prunes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        assert!(
            storage
                .check_and_record_nonce("FP", "n1", 1000)
                .await
                .expect("first")
        );
        // Same nonce again: replay.
        assert!(
            !storage
                .check_and_record_nonce("FP", "n1", 1000)
                .await
                .expect("replay")
        );
        // A different nonce is fine.
        assert!(
            storage
                .check_and_record_nonce("FP", "n2", 1000)
                .await
                .expect("fresh")
        );

        // Pruning past expiry frees the nonce for reuse.
        let pruned = storage.prune_expired_nonces(2000).await.expect("prune");
        assert_eq!(pruned, 2);
        assert!(
            storage
                .check_and_record_nonce("FP", "n1", 3000)
                .await
                .expect("after prune")
        );

        storage.close();
    }

    // The delivery outbox (fed_enqueue/fed_due_items/fed_record_attempt) has a
    // foreign key to calendar_federation, so it is exercised end-to-end in the
    // Phase 5 realtime tests where real federation rows exist.

    #[tokio::test]
    async fn remote_uid_colliding_with_local_event_id_does_not_touch_it() {
        // This is the regression test for the cross-tenant write bug: a peer's
        // remote_uid must map to a NEW local event, never address an existing
        // local event by id — even if the remote_uid equals that event's UUID.
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;

        let victim = storage.create_account("victim@x.test", None).await.unwrap();
        let subscriber = storage.create_account("bob@x.test", None).await.unwrap();

        // The victim's private calendar + event, in no way shared.
        let victim_cal = storage
            .create_calendar(victim.id, "Private".to_string(), None)
            .await
            .unwrap();
        let victim_event = storage
            .create_calendar_event(
                victim_cal.id,
                "Secret dentist".to_string(),
                None,
                10,
                20,
                None,
            )
            .await
            .unwrap();

        // A mirror calendar + inbound federation the subscriber holds.
        let mirror = storage
            .create_calendar(subscriber.id, "Shared".to_string(), None)
            .await
            .unwrap();
        let fed_id = "fed-collision-test";
        storage
            .create_inbound_federation(
                fed_id,
                mirror.id,
                "alice@peer.test",
                "https://peer.test",
                crate::SharingType::Sharing,
                "peer.test",
                "PEERFP",
                "cap",
            )
            .await
            .unwrap();

        // The malicious peer sends a remote event whose uid == the victim
        // event's local UUID. Apply it the way fed_apply does.
        let colliding_uid = victim_event.id.to_string();
        assert!(
            storage
                .federation_local_event(fed_id, &colliding_uid)
                .await
                .unwrap()
                .is_none()
        );
        let new_local = storage
            .create_remote_calendar_event(
                mirror.id,
                fed_id,
                "Injected".to_string(),
                None,
                999,
                1000,
                None,
            )
            .await
            .unwrap();
        storage
            .set_federation_event_map(fed_id, &colliding_uid, new_local, "alice@peer.test")
            .await
            .unwrap();

        // The victim's event is completely untouched.
        let still = storage
            .get_calendar_event(victim_event.id)
            .await
            .unwrap()
            .expect("victim event still exists");
        assert_eq!(still.title, "Secret dentist");
        assert_eq!(still.calendar_id, victim_cal.id);
        assert_eq!(still.start, 10);

        // The injected event is a distinct local id in the mirror calendar.
        assert_ne!(new_local, victim_event.id);
        let mirror_events = storage
            .list_calendar_events_page(mirror.id, 0, String::new(), 100, false)
            .await
            .unwrap();
        assert_eq!(mirror_events.len(), 1);
        assert_eq!(mirror_events[0].id, new_local);
        assert_eq!(mirror_events[0].title, "Injected");

        storage.close();
    }
}
