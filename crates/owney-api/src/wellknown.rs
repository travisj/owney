//! Well-known endpoints for calendar federation discovery.
//!
//! Implements:
//! - /.well-known/owney/server → server metadata
//! - /.well-known/owney/account/{email} → account info for discovery
//! - /.well-known/owney/calendar/invite → receive federated invitations

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{extract::Path, Router};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::federation::{AccountInfo, CalendarInfo, FederationInvitation, ServerMetadata};
use crate::ApiState;

/// Mount well-known endpoints on the router
pub fn routes() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/.well-known/owney/server", get(server_metadata))
        .route("/.well-known/owney/account/{email}", get(account_lookup))
        .route("/.well-known/owney/calendar/invite", post(receive_invitation))
        .route(
            "/.well-known/owney/calendar/sync/{federation_id}",
            get(calendar_sync),
        )
}

/// GET /.well-known/owney/server
/// Returns server metadata for federation discovery
async fn server_metadata(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let metadata = ServerMetadata {
        server_url: state.public_url.clone(),
        supported_features: vec![
            "calendar_sharing".to_string(),
            "calendar_delegation".to_string(),
            "federated_discovery".to_string(),
        ],
        version: env!("CARGO_PKG_VERSION").to_string(),
        admin: None, // Should be configured
    };

    axum::Json(metadata)
}

/// GET /.well-known/owney/account/{email}
/// Returns account info for federated discovery (read-only, public)
async fn account_lookup(
    State(state): State<Arc<ApiState>>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    let storage = &state.storage;
    // Note: This is a public endpoint, but should only return non-sensitive info
    // and the invitee should verify the actual invitation separately.

    match storage.account_by_email(&email).await {
        Ok(Some(account)) => {
            // Only return minimal info (don't expose auth details, etc.)
            let calendars = storage
                .list_calendars(account.id)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|c| CalendarInfo {
                    id: c.id.to_string(),
                    name: c.name,
                })
                .collect();

            let info = AccountInfo {
                account_id: account.id.to_string(),
                email: account.email.clone(),
                name: None, // Could be exposed, but we're keeping it minimal
                calendars,
            };

            (StatusCode::OK, axum::Json(info)).into_response()
        }
        Ok(None) | Err(_) => {
            (StatusCode::NOT_FOUND, axum::Json(json!({"error": "account not found"}))).into_response()
        }
    }
}

/// POST /.well-known/owney/calendar/invite
/// Receive a federated calendar invitation from a remote server
async fn receive_invitation(
    State(state): State<Arc<ApiState>>,
    axum::Json(invitation): axum::Json<FederationInvitation>,
) -> impl IntoResponse {
    let storage = &state.storage;
    // Extract domain from inviter_server_url for trust purposes
    // In production, would validate against allowlist

    match storage.account_by_email(&invitation.target_email).await {
        Ok(Some(_account)) => {
            // Create a pending invitation for the target account
            match storage
                .create_federation_invitation(
                    invitation.calendar_id.parse().unwrap_or_else(|_| owney_core::CalendarId::new()),
                    invitation.inviter_account_id.parse().unwrap_or_else(|_| owney_core::AccountId::new()),
                    format!(
                        "{}|{}",
                        invitation.inviter_account_id, invitation.inviter_server_url
                    ), // Federated identity
                    Some(invitation.inviter_server_url),
                    match invitation.sharing_type.as_str() {
                        "delegation" => owney_storage::SharingType::Delegation,
                        _ => owney_storage::SharingType::Sharing,
                    },
                )
                .await
            {
                Ok(inv) => {
                    (
                        StatusCode::OK,
                        axum::Json(json!({
                            "invitation_id": inv.id,
                            "status": "pending"
                        })),
                    )
                        .into_response()
                }
                Err(_) => {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({"error": "failed to create invitation"})),
                    )
                        .into_response()
                }
            }
        }
        Ok(None) => {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "account not found"})),
            )
                .into_response()
        }
        Err(_) => {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "account not found"})),
            )
                .into_response()
        }
    }
}

/// GET /.well-known/owney/calendar/sync/{federation_id}
/// Fetch calendar changes for federation sync (polling protocol).
/// Query params: token (optional sync token), since (optional unix timestamp)
async fn calendar_sync(
    State(state): State<Arc<ApiState>>,
    Path(federation_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let storage = &state.storage;
    let sync_token = params.get("token").cloned();
    let since_timestamp = params
        .get("since")
        .and_then(|s| s.parse::<i64>().ok());

    // Get federation record to verify it exists and has a calendar
    let federation = match storage.get_federation(&federation_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({
                    "error": "not_found",
                    "error_description": "Federation not found"
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "server_error"})),
            )
                .into_response();
        }
    };

    // Determine since_timestamp for sync
    let sync_since = if let Some(ts) = since_timestamp {
        // Use explicit timestamp
        ts
    } else if sync_token.is_none() {
        // Initial sync - fetch all events
        0
    } else {
        // Incremental sync - use federation's last sync time
        federation.last_sync_at.unwrap_or(0)
    };

    // Fetch events modified since sync_since
    let events = match storage.list_calendar_events_since(federation.calendar_id, sync_since).await {
        Ok(events) => events,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "server_error"})),
            )
                .into_response();
        }
    };

    // Convert events to sync response format
    let event_values: Vec<Value> = events
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id.to_string(),
                "title": e.title,
                "description": e.description,
                "start": e.start,
                "end": e.end,
                "rrule": e.rrule,
                "created_at": e.created_at,
                "updated_at": e.updated_at,
                "removed": false
            })
        })
        .collect();

    // Generate new sync token (format: timestamp:counter)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let new_sync_token = format!("{}:v1", now);

    // Get calendar info
    let calendar = match storage.get_calendar_by_id(federation.calendar_id).await {
        Ok(Some(c)) => c,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error": "not_found"})),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        axum::Json(json!({
            "federation_id": federation_id,
            "sync_token": new_sync_token,
            "calendar": {
                "id": calendar.id.to_string(),
                "name": calendar.name,
                "description": calendar.description,
                "updated_at": calendar.updated_at
            },
            "events": event_values,
            "removed_event_ids": [],
            "has_more_changes": false
        })),
    )
        .into_response()
}
