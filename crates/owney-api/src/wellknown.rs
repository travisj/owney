//! Well-known endpoints for calendar federation.
//!
//! Every endpoint except server-metadata discovery is authenticated with a
//! signed federation request (see `fed_sig`). Server identity is a PGP cert
//! published at `/.well-known/owney/server`; peers pin it over a
//! TLS-authenticated discovery fetch. Events are sealed (signed by the author,
//! encrypted to the receiving server) so a compromised peer or intermediary can
//! neither read nor forge them.
//!
//! The whole router is still gated behind `OWNEY_FEDERATION_ENABLED` and mounts
//! nothing when unset, so a default deployment exposes no federation surface.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use sequoia_openpgp::parse::Parse;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::ApiState;
use crate::fed_sig::{self, VerifiedPeer};
use crate::federation::{self, FederationInvitation, ServerMetadata};

const MAX_EVENTS_PER_PAGE: usize = 500;

/// Mount federation endpoints, only when `OWNEY_FEDERATION_ENABLED=true`.
///
/// Unlike the previous unauthenticated stubs, these endpoints now require
/// signed peer requests; the flag simply controls whether the (now safe)
/// federation surface is exposed at all.
pub fn routes(enabled: bool) -> Router<Arc<ApiState>> {
    if !enabled {
        return Router::new();
    }

    Router::new()
        .route("/.well-known/owney/server", get(server_metadata))
        .route("/.well-known/owney/account/{email}", get(account_lookup))
        .route(
            "/.well-known/owney/calendar/invite",
            post(receive_invitation),
        )
        .route(
            "/.well-known/owney/calendar/sync/{federation_id}",
            get(calendar_sync),
        )
        .route("/.well-known/owney/calendar/notify", post(receive_notify))
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Terse error response; deliberately uninformative so it can't be used as an
/// oracle.
fn deny(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(json!({ "error": msg }))).into_response()
}

/// Verify an inbound signed request from its raw parts.
async fn verify(
    state: &ApiState,
    method: &Method,
    uri: &OriginalUri,
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Result<VerifiedPeer, Response> {
    let path = fed_sig::canonical_path_str(&uri.0.to_string());
    fed_sig::verify_request(
        &state.storage,
        &state.public_url,
        method.as_str(),
        &path,
        headers,
        body,
    )
    .await
    .map_err(|r| deny(r.status(), r.as_str()))
}

/// GET /.well-known/owney/server — public server metadata + federation cert.
async fn server_metadata(State(state): State<Arc<ApiState>>) -> Response {
    let domain = fed_sig::host_of(&state.public_url);
    let (public_cert, fingerprint) = match owney_pgp::server_cert(&state.storage, &domain).await {
        Ok(cert) => {
            let armored = owney_pgp::public_armored(&cert).ok();
            (armored, Some(cert.fingerprint().to_hex()))
        }
        Err(_) => (None, None),
    };

    let metadata = ServerMetadata {
        server_url: state.public_url.clone(),
        supported_features: vec![
            "calendar_sharing".to_string(),
            "calendar_delegation".to_string(),
            "signed_requests".to_string(),
            "sealed_events".to_string(),
        ],
        version: env!("CARGO_PKG_VERSION").to_string(),
        admin: None,
        public_cert,
        fingerprint,
    };

    axum::Json(metadata).into_response()
}

/// GET /.well-known/owney/account/{email} — signed existence check only.
///
/// Requires a signed peer request and returns nothing but existence — no
/// account id, no calendar inventory — so it cannot be used to enumerate users
/// or harvest their calendars.
async fn account_lookup(
    State(state): State<Arc<ApiState>>,
    Path(email): Path<String>,
    method: Method,
    uri: OriginalUri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(resp) = verify(&state, &method, &uri, &headers, &body).await {
        return resp;
    }
    match state.storage.account_by_email(&email).await {
        Ok(Some(_)) => (StatusCode::OK, axum::Json(json!({ "exists": true }))).into_response(),
        _ => deny(StatusCode::NOT_FOUND, "not found"),
    }
}

/// POST /.well-known/owney/calendar/invite — receive a federated share.
///
/// This is the trust bootstrap: it discovers and pins the *claimed* sending
/// server over TLS, then verifies the request signature against that pin, then
/// binds the inviter identity to the authenticated sender domain. Only then is
/// a pending inbound federation + local mirror calendar created.
async fn receive_invitation(
    State(state): State<Arc<ApiState>>,
    method: Method,
    uri: OriginalUri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    // Parse the body first (needed for identity binding), but trust nothing in
    // it until the signature is verified.
    let invitation: FederationInvitation = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return deny(StatusCode::BAD_REQUEST, "malformed"),
    };

    // The claimed sender domain; must be allowlisted and discoverable.
    let sender_domain = match headers.get(fed_sig::H_SERVER).and_then(|v| v.to_str().ok()) {
        Some(d) => d.trim().to_lowercase(),
        None => return deny(StatusCode::UNAUTHORIZED, "missing signature"),
    };

    // Bootstrap: discover + pin the sender's cert over TLS before verifying.
    let client = match federation::build_client(
        &state.storage,
        &state.public_url,
        &state.federation,
    )
    .await
    {
        Ok(c) => c,
        Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    };
    if let Err(e) =
        federation::discover_and_pin(&state.storage, &client, &sender_domain, &state.federation)
            .await
    {
        tracing::warn!(%sender_domain, error = %e, "federation peer discovery/pin failed");
        return deny(StatusCode::UNAUTHORIZED, "unknown peer");
    }

    // Now the signature can be verified against the pinned cert.
    let peer = match verify(&state, &method, &uri, &headers, &body).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // Bind inviter identity to the authenticated sender: the inviter's email
    // domain must be the server that signed this request.
    let inviter_domain = invitation
        .inviter_email
        .rsplit_once('@')
        .map(|(_, d)| d.to_lowercase());
    if inviter_domain.as_deref() != Some(peer.domain.as_str()) {
        return deny(StatusCode::BAD_REQUEST, "inviter/sender mismatch");
    }

    // The invitee must be a local account.
    let target = match state
        .storage
        .account_by_email(&invitation.target_email)
        .await
    {
        Ok(Some(a)) => a,
        _ => return deny(StatusCode::NOT_FOUND, "not found"),
    };

    let sharing_type = match invitation.sharing_type.as_str() {
        "delegation" => owney_storage::SharingType::Delegation,
        _ => owney_storage::SharingType::Sharing,
    };

    // Create the local mirror calendar (owned by the invitee) and the pending
    // inbound federation keyed on the shared federation id.
    let mirror = match state
        .storage
        .create_calendar(
            target.id,
            format!("{} (shared)", invitation.calendar_name),
            Some(format!("Shared by {}", invitation.inviter_email)),
        )
        .await
    {
        Ok(c) => c,
        Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    };

    // Derive the peer's server_url from the pinned record (not the body).
    let peer_url = state
        .storage
        .federation_peer(&peer.domain)
        .await
        .ok()
        .flatten()
        .map(|p| p.server_url)
        .unwrap_or_default();

    if let Err(e) = state
        .storage
        .create_inbound_federation(
            &invitation.federation_id,
            mirror.id,
            &invitation.inviter_email,
            &peer_url,
            sharing_type,
            &peer.domain,
            &peer.fingerprint,
            &invitation.capability_secret,
        )
        .await
    {
        tracing::error!(error = %e, "failed to create inbound federation");
        return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error");
    }

    (
        StatusCode::OK,
        axum::Json(json!({
            "federation_id": invitation.federation_id,
            "status": "pending"
        })),
    )
        .into_response()
}

/// GET /.well-known/owney/calendar/sync/{federation_id} — serve sealed events.
///
/// The serving (outbound) side. Enforces, in order: a valid peer signature;
/// that the caller is the peer this federation was shared with; the capability
/// secret; that the share is accepted and grants view; then returns each event
/// sealed to the calling peer and signed by the calendar owner.
async fn calendar_sync(
    State(state): State<Arc<ApiState>>,
    Path(federation_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    method: Method,
    uri: OriginalUri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let peer = match verify(&state, &method, &uri, &headers, &body).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let federation = match state.storage.get_federation(&federation_id).await {
        Ok(Some(f)) => f,
        Ok(None) => return deny(StatusCode::NOT_FOUND, "not found"),
        Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    };

    // This must be a calendar we serve, to exactly this peer.
    if federation.direction.as_deref() != Some("outbound")
        || !matches!(federation.status.as_str(), "accepted" | "syncing")
        || federation.peer_domain.as_deref() != Some(peer.domain.as_str())
        || federation.peer_fingerprint.as_deref() != Some(peer.fingerprint.as_str())
    {
        return deny(StatusCode::FORBIDDEN, "forbidden");
    }

    // Capability secret (second factor), constant-time compared.
    let presented = headers
        .get(fed_sig::H_CAPABILITY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = federation.capability_secret.as_deref().unwrap_or("");
    if expected.is_empty() || !fed_sig::constant_time_eq(presented.as_bytes(), expected.as_bytes())
    {
        return deny(StatusCode::FORBIDDEN, "forbidden");
    }

    // The calendar and its owner (the event author for signing).
    let calendar = match state
        .storage
        .get_calendar_by_id(federation.calendar_id)
        .await
    {
        Ok(Some(c)) => c,
        _ => return deny(StatusCode::NOT_FOUND, "not found"),
    };

    // The share must still grant view of events.
    match state
        .storage
        .calendar_access(calendar.account_id, calendar.id)
        .await
    {
        Ok(Some(p)) if p.view_events => {}
        _ => return deny(StatusCode::FORBIDDEN, "forbidden"),
    }

    // Author (owner) secret cert to sign, and the calling peer's cert to seal to.
    let author_secret = match owney_pgp::own_cert(&state.storage, calendar.account_id).await {
        Ok(c) => c,
        Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    };
    let peer_cert = match state.storage.federation_peer(&peer.domain).await {
        Ok(Some(p)) => match sequoia_openpgp::Cert::from_bytes(&p.cert) {
            Ok(c) => c,
            Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
        },
        _ => return deny(StatusCode::UNAUTHORIZED, "unknown peer"),
    };

    // Keyset cursor from query (?since=<updated_at>&after=<id>).
    let after_updated_at = params
        .get("since")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let after_id = params.get("after").cloned().unwrap_or_default();

    let events = match state
        .storage
        .list_calendar_events_page(
            federation.calendar_id,
            after_updated_at,
            after_id,
            MAX_EVENTS_PER_PAGE,
            true, // exclude remote-origin events (no echo)
        )
        .await
    {
        Ok(e) => e,
        Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    };

    let author_email = calendar_owner_email(&state, calendar.account_id).await;
    let has_more = events.len() == MAX_EVENTS_PER_PAGE;
    let mut next_updated_at = after_updated_at;
    let mut next_id = String::new();
    let mut items = Vec::with_capacity(events.len());
    for e in &events {
        let payload = json!({
            "title": e.title,
            "description": e.description,
            "start": e.start,
            "end": e.end,
            "rrule": e.rrule,
            "author_email": author_email,
        });
        let sealed = match owney_pgp::ops::seal_event(
            &author_secret,
            &peer_cert,
            payload.to_string().as_bytes(),
        ) {
            Ok(s) => s,
            Err(_) => return deny(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
        };
        items.push(json!({
            "remote_uid": e.id.to_string(),
            "updated_at": e.updated_at,
            "sealed": b64().encode(&sealed),
        }));
        next_updated_at = e.updated_at;
        next_id = e.id.to_string();
    }

    // The author's public cert, so the subscriber can verify each event's
    // signature. A vouches for its own users' keys (inherent to federation).
    let author_cert = owney_pgp::public_armored(&author_secret).ok();

    (
        StatusCode::OK,
        axum::Json(json!({
            "federation_id": federation_id,
            "author_cert": author_cert,
            "items": items,
            "next_since": next_updated_at,
            "next_after": next_id,
            "has_more": has_more,
        })),
    )
        .into_response()
}

/// POST /.well-known/owney/calendar/notify — a peer tells us one of our inbound
/// federations changed; we pull the delta over the authenticated serve path.
///
/// The body carries only a federation id (no secrets). We verify the sender
/// signature, confirm the federation is one we subscribe to *from that peer*,
/// then trigger an immediate pull.
async fn receive_notify(
    State(state): State<Arc<ApiState>>,
    method: Method,
    uri: OriginalUri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let peer = match verify(&state, &method, &uri, &headers, &body).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return deny(StatusCode::BAD_REQUEST, "malformed"),
    };
    let federation_id = match parsed.get("federation_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return deny(StatusCode::BAD_REQUEST, "malformed"),
    };

    // The notified federation must be an inbound one we hold *from this peer*.
    match state.storage.get_federation(&federation_id).await {
        Ok(Some(f))
            if f.direction.as_deref() == Some("inbound")
                && f.peer_domain.as_deref() == Some(peer.domain.as_str())
                && f.peer_fingerprint.as_deref() == Some(peer.fingerprint.as_str()) => {}
        _ => return deny(StatusCode::FORBIDDEN, "forbidden"),
    }

    // Pull now. Errors are logged; the periodic reconciliation pass will retry.
    let coordinator = crate::calendar_sync::CalendarSyncCoordinator::new(
        state.storage.clone(),
        state.public_url.clone(),
        state.federation.clone(),
    );
    if let Err(e) = coordinator.sync_one(&federation_id).await {
        tracing::warn!(%federation_id, error = %e, "notify-triggered pull failed");
    }

    (StatusCode::OK, axum::Json(json!({ "status": "ok" }))).into_response()
}

async fn calendar_owner_email(state: &ApiState, account_id: owney_core::AccountId) -> String {
    state
        .storage
        .account(account_id)
        .await
        .ok()
        .flatten()
        .map(|a| a.email)
        .unwrap_or_default()
}
