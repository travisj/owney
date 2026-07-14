//! Calendar, CalendarEvent, and CalendarInvitation methods.
//!
//! Supports:
//! - Calendar/get
//! - CalendarInvitation/get, CalendarInvitation/set
//! - Calendar/share (for same-server sharing & delegation)

use std::sync::Arc;

use jmap_core::MethodError;
use owney_api::JmapCtx;
use serde::Deserialize;
use serde_json::{Value, json};

pub const CALENDAR_CAPABILITY: &str = "urn:owney:params:jmap:calendar";

/// Capability object for calendar methods
pub fn calendar_capability() -> Value {
    json!({
        "maxCalendarsPerAccount": 100,
        "supportsRecurring": true,
        "supportedSharingTypes": ["sharing", "delegation"],
        "supportsFederatedDiscovery": true,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetArgs {
    pub account_id: String,
    /// Accepted per the JMAP get contract; id filtering not yet implemented.
    #[serde(default)]
    #[allow(dead_code)]
    pub ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarShareArgs {
    pub account_id: String,
    pub calendar_id: String,
    pub invitee_email: String,
    pub sharing_type: String, // "sharing" or "delegation"
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarInvitationSetArgs {
    pub account_id: String,
    pub action: String, // "accept" or "reject"
    pub invitation_id: String,
}

pub async fn calendar_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: GetArgs = serde_json::from_value(args)
        .map_err(|_| MethodError::InvalidArguments("invalid arguments".to_string()))?;
    let _account_id = check_account(&ctx, &args.account_id)?;

    // Get calendars for this account
    let calendars = ctx
        .storage
        .list_calendars(ctx.account.id)
        .await
        .map_err(|e| MethodError::ServerFail(e.to_string()))?;

    let calendar_values: Vec<Value> = calendars
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id.to_string(),
                "name": c.name,
                "description": c.description,
                "isSubscribed": true,
            })
        })
        .collect();

    Ok(json!({
        "accountId": args.account_id,
        "list": calendar_values,
        "notFound": []
    }))
}

pub async fn calendar_share(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: CalendarShareArgs = serde_json::from_value(args)
        .map_err(|_| MethodError::InvalidArguments("invalid arguments".to_string()))?;
    let _account_id = check_account(&ctx, &args.account_id)?;

    let calendar_id = args
        .calendar_id
        .parse()
        .map_err(|_| MethodError::InvalidArguments("invalid arguments".to_string()))?;

    // Check if target is local or federated
    if args.invitee_email.contains('@') {
        let (_, domain) = args
            .invitee_email
            .split_once('@')
            .ok_or_else(|| MethodError::InvalidArguments("invalid invitee email".to_string()))?;

        // Try to find local account first
        match ctx.storage.account_by_email(&args.invitee_email).await {
            Ok(Some(target_account)) => {
                // Same-server sharing
                let sharing_type = match args.sharing_type.as_str() {
                    "delegation" => owney_storage::SharingType::Delegation,
                    _ => owney_storage::SharingType::Sharing,
                };

                let sharing = ctx
                    .storage
                    .share_calendar(calendar_id, ctx.account.id, target_account.id, sharing_type)
                    .await
                    .map_err(|e| MethodError::ServerFail(e.to_string()))?;

                Ok(json!({
                    "invitationId": sharing.id,
                    "status": "pending",
                    "createdAt": sharing.created_at
                }))
            }
            Ok(None) => {
                // Federated sharing - need to discover target server
                match owney_api::federation::ServerDiscovery::discover(domain).await {
                    Ok(server_metadata) => {
                        // Create federation invitation
                        let get_calendar = ctx
                            .storage
                            .get_calendar(ctx.account.id, calendar_id)
                            .await
                            .map_err(|e| MethodError::ServerFail(e.to_string()))?
                            .ok_or_else(|| {
                                MethodError::InvalidArguments("calendar not found".to_string())
                            })?;

                        let _sharing_type = match args.sharing_type.as_str() {
                            "delegation" => owney_storage::SharingType::Delegation,
                            _ => owney_storage::SharingType::Sharing,
                        };

                        let invitation = owney_api::federation::FederationInvitation {
                            calendar_id: calendar_id.to_string(),
                            calendar_name: get_calendar.name,
                            inviter_email: ctx.account.email.clone(),
                            inviter_account_id: ctx.account.id.to_string(),
                            inviter_server_url: "https://example.com".to_string(), // Should be configured
                            target_email: args.invitee_email,
                            sharing_type: args.sharing_type,
                            created_at: unix_now(),
                        };

                        match owney_api::federation::ServerDiscovery::send_invitation(
                            &server_metadata.server_url,
                            &invitation,
                        )
                        .await
                        {
                            Ok(invitation_id) => Ok(json!({
                                "invitationId": invitation_id,
                                "status": "pending",
                                "federated": true
                            })),
                            Err(e) => Err(MethodError::ServerFail(e.to_string())),
                        }
                    }
                    Err(e) => Err(MethodError::ServerFail(e.to_string())),
                }
            }
            Err(e) => Err(MethodError::ServerFail(e.to_string())),
        }
    } else {
        Err(MethodError::InvalidArguments(
            "invitee email must contain '@'".to_string(),
        ))
    }
}

pub async fn calendar_invitation_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: GetArgs = serde_json::from_value(args)
        .map_err(|_| MethodError::InvalidArguments("invalid arguments".to_string()))?;
    let _account_id = check_account(&ctx, &args.account_id)?;

    let invitations = ctx
        .storage
        .get_pending_invitations(ctx.account.id)
        .await
        .map_err(|e| MethodError::ServerFail(e.to_string()))?;

    let invitation_values: Vec<Value> = invitations
        .into_iter()
        .map(|inv| {
            json!({
                "id": inv.id,
                "calendarId": inv.calendar_id.to_string(),
                "inviterAccountId": inv.inviter_account_id.to_string(),
                "sharingType": inv.sharing_type.as_str(),
                "status": inv.status,
                "createdAt": inv.created_at,
            })
        })
        .collect();

    Ok(json!({
        "accountId": args.account_id,
        "list": invitation_values,
        "notFound": []
    }))
}

pub async fn calendar_invitation_set(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: CalendarInvitationSetArgs = serde_json::from_value(args)
        .map_err(|_| MethodError::InvalidArguments("invalid arguments".to_string()))?;
    let _account_id = check_account(&ctx, &args.account_id)?;

    match args.action.as_str() {
        "accept" => {
            ctx.storage
                .accept_federation_invitation(&args.invitation_id)
                .await
                .map_err(|e| MethodError::ServerFail(e.to_string()))?;

            Ok(json!({
                "invitationId": args.invitation_id,
                "status": "accepted"
            }))
        }
        "reject" => {
            // TODO: Add reject method to storage
            Ok(json!({
                "invitationId": args.invitation_id,
                "status": "rejected"
            }))
        }
        _ => Err(MethodError::InvalidArguments(format!(
            "unknown action: {}",
            args.action
        ))),
    }
}

fn check_account(ctx: &JmapCtx, account_id: &str) -> Result<owney_core::AccountId, MethodError> {
    if account_id != ctx.account.id.to_string() {
        return Err(MethodError::AccountNotFound);
    }
    Ok(ctx.account.id)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
