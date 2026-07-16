//! Inbound apply: turn a sealed sync page from a peer into local (read-only)
//! events. This is the subscriber side.
//!
//! Security-critical invariants enforced here:
//! - Each event is decrypted with *our* server secret cert and its author
//!   signature must verify (`open_event` rejects otherwise).
//! - The author's email domain must be the peer we federate with (a peer may
//!   only speak for its own users).
//! - The remote event id (`remote_uid`) is **never** used as a local primary
//!   key. It is mapped, per federation, to a local server-minted id — so a peer
//!   can never address, overwrite, or delete a local event outside the shared
//!   mirror calendar. This is the fix for the cross-tenant write bug.

use base64::Engine;
use owney_storage::{CalendarFederation, Storage};
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;
use serde::Deserialize;

/// One sealed event in a sync page.
#[derive(Debug, Clone, Deserialize)]
pub struct SealedItem {
    pub remote_uid: String,
    #[allow(dead_code)]
    pub updated_at: i64,
    pub sealed: String,
}

/// A page of the sync protocol response.
#[derive(Debug, Clone, Deserialize)]
pub struct SyncPage {
    #[serde(default)]
    pub author_cert: Option<String>,
    #[serde(default)]
    pub items: Vec<SealedItem>,
    #[serde(default)]
    pub next_since: i64,
    #[serde(default)]
    pub next_after: String,
    #[serde(default)]
    pub has_more: bool,
}

/// Decrypted event payload (as sealed by the serving side).
#[derive(Debug, Clone, Deserialize)]
struct EventPayload {
    title: String,
    description: Option<String>,
    start: i64,
    end: i64,
    rrule: Option<String>,
    author_email: String,
}

#[derive(Debug)]
pub enum ApplyError {
    Crypto(String),
    Storage(String),
    Untrusted(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::Crypto(m) => write!(f, "crypto: {m}"),
            ApplyError::Storage(m) => write!(f, "storage: {m}"),
            ApplyError::Untrusted(m) => write!(f, "untrusted: {m}"),
        }
    }
}

impl std::error::Error for ApplyError {}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn domain_of(email: &str) -> Option<String> {
    email.rsplit_once('@').map(|(_, d)| d.to_lowercase())
}

/// Apply one sync page into the federation's local mirror calendar. Returns the
/// number of events applied. Individual bad/untrusted events are skipped (and
/// logged) rather than failing the whole page.
pub async fn apply_page(
    storage: &Storage,
    server_secret: &Cert,
    federation: &CalendarFederation,
    page: &SyncPage,
) -> Result<usize, ApplyError> {
    let peer_domain = federation
        .peer_domain
        .clone()
        .ok_or_else(|| ApplyError::Untrusted("federation has no peer domain".into()))?;

    // The author cert the peer vouches for. Absent it, we cannot verify.
    let author_cert = match &page.author_cert {
        Some(armored) => {
            Cert::from_bytes(armored.as_bytes()).map_err(|e| ApplyError::Crypto(e.to_string()))?
        }
        None if page.items.is_empty() => return Ok(0),
        None => return Err(ApplyError::Untrusted("page missing author_cert".into())),
    };

    let mut applied = 0usize;
    for item in &page.items {
        match apply_one(
            storage,
            server_secret,
            federation,
            &peer_domain,
            &author_cert,
            item,
        )
        .await
        {
            Ok(()) => applied += 1,
            Err(e) => {
                tracing::warn!(
                    federation_id = %federation.id,
                    remote_uid = %item.remote_uid,
                    error = %e,
                    "skipping untrusted or invalid federated event"
                );
            }
        }
    }
    Ok(applied)
}

async fn apply_one(
    storage: &Storage,
    server_secret: &Cert,
    federation: &CalendarFederation,
    peer_domain: &str,
    author_cert: &Cert,
    item: &SealedItem,
) -> Result<(), ApplyError> {
    let ciphertext = b64()
        .decode(&item.sealed)
        .map_err(|e| ApplyError::Crypto(e.to_string()))?;

    // Decrypt with our server key; require a valid author signature.
    let plaintext = owney_pgp::ops::open_event(server_secret, author_cert, &ciphertext)
        .map_err(|e| ApplyError::Crypto(e.to_string()))?;
    let payload: EventPayload =
        serde_json::from_slice(&plaintext).map_err(|e| ApplyError::Crypto(e.to_string()))?;

    // Author-domain binding: the peer may only speak for its own users.
    let author_domain = domain_of(&payload.author_email)
        .ok_or_else(|| ApplyError::Untrusted("bad author".into()))?;
    if author_domain != peer_domain {
        return Err(ApplyError::Untrusted(format!(
            "author domain {author_domain} is not the federating peer {peer_domain}"
        )));
    }
    // The signing cert must actually be the claimed author's.
    let cert_matches_author = author_cert
        .userids()
        .any(|u| u.userid().to_string().contains(&payload.author_email));
    if !cert_matches_author {
        return Err(ApplyError::Untrusted(
            "author cert does not match author email".into(),
        ));
    }

    // Map the remote uid to a LOCAL event id, scoped to this federation. Never
    // trust the remote id as a local key.
    match storage
        .federation_local_event(&federation.id, &item.remote_uid)
        .await
        .map_err(|e| ApplyError::Storage(e.to_string()))?
    {
        Some(local_id) => {
            storage
                .update_remote_calendar_event(
                    local_id,
                    payload.title,
                    payload.description,
                    payload.start,
                    payload.end,
                    payload.rrule,
                )
                .await
                .map_err(|e| ApplyError::Storage(e.to_string()))?;
        }
        None => {
            let local_id = storage
                .create_remote_calendar_event(
                    federation.calendar_id,
                    &federation.id,
                    payload.title,
                    payload.description,
                    payload.start,
                    payload.end,
                    payload.rrule,
                )
                .await
                .map_err(|e| ApplyError::Storage(e.to_string()))?;
            storage
                .set_federation_event_map(
                    &federation.id,
                    &item.remote_uid,
                    local_id,
                    &payload.author_email,
                )
                .await
                .map_err(|e| ApplyError::Storage(e.to_string()))?;
        }
    }

    Ok(())
}
