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
use serde_json::json;
use std::sync::Arc;

use owney_storage::Storage;

use crate::federation::{AccountInfo, CalendarInfo, FederationInvitation, ServerMetadata};

/// Mount well-known endpoints on the router
pub fn routes() -> Router {
    Router::new()
        .route("/.well-known/owney/server", get(server_metadata))
        .route("/.well-known/owney/account/:email", get(account_lookup))
        .route("/.well-known/owney/calendar/invite", post(receive_invitation))
}

/// GET /.well-known/owney/server
/// Returns server metadata for federation discovery
async fn server_metadata(State(storage): State<Arc<Storage>>) -> impl IntoResponse {
    let metadata = ServerMetadata {
        server_url: "https://owney.example.com".to_string(), // Should be configured
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

/// GET /.well-known/owney/account/:email
/// Returns account info for federated discovery (read-only, public)
async fn account_lookup(
    State(storage): State<Arc<Storage>>,
    Path(email): Path<String>,
) -> impl IntoResponse {
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
        Err(_) => {
            (StatusCode::NOT_FOUND, axum::Json(json!({"error": "account not found"}))).into_response()
        }
    }
}

/// POST /.well-known/owney/calendar/invite
/// Receive a federated calendar invitation from a remote server
async fn receive_invitation(
    State(storage): State<Arc<Storage>>,
    axum::Json(invitation): axum::Json<FederationInvitation>,
) -> impl IntoResponse {
    // Extract domain from inviter_server_url for trust purposes
    // In production, would validate against allowlist

    match storage.account_by_email(&invitation.target_email).await {
        Ok(Some(account)) => {
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
