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

    // Calendars this account owns.
    let owned = ctx
        .storage
        .list_calendars(ctx.account.id)
        .await
        .map_err(storage_err)?;

    let mut calendar_values: Vec<Value> = owned
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id.to_string(),
                "name": c.name,
                "description": c.description,
                "isSubscribed": true,
                "myRights": owner_rights(),
            })
        })
        .collect();

    // Calendars shared with this account. Only *accepted* shares appear, and
    // only when the share actually grants view access — this is where the
    // stored permission bits become load-bearing.
    let shared = ctx
        .storage
        .list_accepted_shared_calendar_ids(ctx.account.id)
        .await
        .map_err(storage_err)?;

    for (calendar_id, perms) in shared {
        if !perms.view_calendar {
            continue;
        }
        // The shared calendar is owned by another account, so fetch it by id.
        if let Some(c) = ctx
            .storage
            .get_calendar_by_id(calendar_id)
            .await
            .map_err(storage_err)?
        {
            calendar_values.push(json!({
                "id": c.id.to_string(),
                "name": c.name,
                "description": c.description,
                "isSubscribed": true,
                "myRights": rights_json(&perms),
            }));
        }
    }

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

    // Authorization: only the calendar's owner may share it. Verify ownership
    // up front so it covers both the local and federated paths below.
    if ctx
        .storage
        .get_calendar(ctx.account.id, calendar_id)
        .await
        .map_err(storage_err)?
        .is_none()
    {
        return Err(MethodError::Forbidden);
    }

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
                    .map_err(storage_err)?;

                Ok(json!({
                    "invitationId": sharing.id,
                    "status": "pending",
                    "createdAt": sharing.created_at
                }))
            }
            Ok(None) => {
                // Federated sharing: discover + pin the target server, create an
                // outbound federation (minting the capability), and deliver a
                // signed invitation.
                let calendar = ctx
                    .storage
                    .get_calendar(ctx.account.id, calendar_id)
                    .await
                    .map_err(storage_err)?
                    .ok_or_else(|| {
                        MethodError::InvalidArguments("calendar not found".to_string())
                    })?;

                let sharing_type = match args.sharing_type.as_str() {
                    "delegation" => owney_storage::SharingType::Delegation,
                    _ => owney_storage::SharingType::Sharing,
                };

                let client = owney_api::federation::build_client(
                    &ctx.storage,
                    &ctx.public_url,
                    &ctx.federation,
                )
                .await
                .map_err(|e| MethodError::ServerFail(e.to_string()))?;
                let peer = owney_api::federation::discover_and_pin(
                    &ctx.storage,
                    &client,
                    domain,
                    &ctx.federation,
                )
                .await
                .map_err(|e| MethodError::ServerFail(e.to_string()))?;

                let (federation_id, capability_secret) = ctx
                    .storage
                    .create_outbound_federation(
                        calendar_id,
                        &args.invitee_email,
                        &peer.server_url,
                        sharing_type,
                        &peer.domain,
                        &peer.fingerprint,
                    )
                    .await
                    .map_err(storage_err)?;

                let invitation = owney_api::federation::FederationInvitation {
                    federation_id: federation_id.clone(),
                    capability_secret,
                    calendar_name: calendar.name,
                    inviter_email: ctx.account.email.clone(),
                    target_email: args.invitee_email.clone(),
                    sharing_type: args.sharing_type.clone(),
                    created_at: unix_now(),
                };
                let body = serde_json::to_vec(&invitation)
                    .map_err(|e| MethodError::ServerFail(e.to_string()))?;
                let invite_url = format!("{}/.well-known/owney/calendar/invite", peer.server_url);
                let resp = client
                    .post_json(&invite_url, &peer.domain, &body)
                    .await
                    .map_err(|e| MethodError::ServerFail(e.to_string()))?;
                if !resp.status().is_success() {
                    return Err(MethodError::ServerFail(format!(
                        "peer rejected invitation: {}",
                        resp.status()
                    )));
                }

                Ok(json!({
                    "invitationId": federation_id,
                    "status": "pending",
                    "federated": true
                }))
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

    // Pending federated invitations are represented as pending inbound
    // federations addressed to this account (the mirror-calendar owner).
    let invitations = ctx
        .storage
        .list_pending_inbound_federations(ctx.account.id)
        .await
        .map_err(storage_err)?;

    let invitation_values: Vec<Value> = invitations
        .into_iter()
        .map(|fed| {
            json!({
                "id": fed.id,
                "calendarId": fed.calendar_id.to_string(),
                "inviterEmail": fed.target_email,
                "sharingType": fed.sharing_type.as_str(),
                "status": fed.status,
                "createdAt": fed.created_at,
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
            // Accepting flips the pending inbound federation to accepted; the
            // sync worker then begins pulling. Scoped to the mirror-calendar
            // owner, so one account cannot accept another's invitation.
            ctx.storage
                .accept_inbound_federation(&args.invitation_id, ctx.account.id)
                .await
                .map_err(storage_err)?;

            Ok(json!({
                "invitationId": args.invitation_id,
                "status": "accepted"
            }))
        }
        "reject" => {
            ctx.storage
                .reject_inbound_federation(&args.invitation_id, ctx.account.id)
                .await
                .map_err(storage_err)?;

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

/// Map a storage error to a method error, preserving the authorization
/// boundary: a `NotAuthorized` storage failure becomes `Forbidden`, not a
/// generic server failure.
fn storage_err(e: owney_storage::StorageError) -> MethodError {
    match e {
        owney_storage::StorageError::NotAuthorized => MethodError::Forbidden,
        other => MethodError::ServerFail(other.to_string()),
    }
}

/// JMAP `myRights` object for a calendar the account owns.
fn owner_rights() -> Value {
    rights_json(&owney_storage::Permissions::owner())
}

/// JMAP `myRights` object derived from a [`Permissions`] grant.
fn rights_json(perms: &owney_storage::Permissions) -> Value {
    json!({
        "mayReadItems": perms.view_events,
        "mayWriteItems": perms.edit_events,
        "mayDeleteItems": perms.delete_events,
        "mayAdmin": perms.admin,
        "mayShare": perms.change_sharing,
    })
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use owney_storage::{Account, Storage};
    use std::sync::Arc;

    async fn setup() -> (tempfile::TempDir, Arc<Storage>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let events = owney_events::EventBus::new(64);
        let storage = Storage::open(dir.path(), events).expect("open storage");
        (dir, Arc::new(storage))
    }

    fn ctx_for(storage: &Arc<Storage>, account: Account) -> Arc<JmapCtx> {
        Arc::new(JmapCtx {
            account,
            storage: storage.clone(),
            submitter: None,
            public_url: "https://test.local".to_string(),
            federation: Default::default(),
        })
    }

    fn share_args(account: &Account, calendar_id: &str, invitee: &str, ty: &str) -> Value {
        json!({
            "accountId": account.id.to_string(),
            "calendarId": calendar_id,
            "inviteeEmail": invitee,
            "sharingType": ty,
        })
    }

    #[tokio::test]
    async fn owner_can_share_but_non_owner_is_forbidden() {
        let (_dir, storage) = setup().await;

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
        let cal_id = calendar.id.to_string();

        // Owner (alice) shares her calendar with local account bob: succeeds.
        let ok = calendar_share(
            share_args(&alice, &cal_id, "bob@example.com", "sharing"),
            ctx_for(&storage, alice.clone()),
        )
        .await
        .expect("owner share ok");
        assert_eq!(ok["status"], "pending");

        // Non-owner (mallory), authenticated as herself, tries to share alice's
        // calendar. Must be rejected at the authorization boundary.
        let err = calendar_share(
            share_args(&mallory, &cal_id, "mallory@example.com", "delegation"),
            ctx_for(&storage, mallory.clone()),
        )
        .await
        .expect_err("non-owner share must fail");
        assert!(matches!(err, MethodError::Forbidden));

        // And mallory truly gained nothing.
        assert!(
            storage
                .calendar_access(mallory.id, calendar.id)
                .await
                .expect("access")
                .is_none()
        );

        let _ = bob;
    }

    #[tokio::test]
    async fn calendar_get_shows_accepted_shares_not_pending() {
        let (_dir, storage) = setup().await;

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
        let cal_id = calendar.id.to_string();

        // Alice shares with bob (pending).
        let shared = calendar_share(
            share_args(&alice, &cal_id, "bob@example.com", "sharing"),
            ctx_for(&storage, alice.clone()),
        )
        .await
        .expect("share");
        let invitation_id = shared["invitationId"].as_str().unwrap().to_string();

        // While pending, bob's Calendar/get shows only… nothing shared.
        let bob_ctx = ctx_for(&storage, bob.clone());
        let before = calendar_get(json!({"accountId": bob.id.to_string()}), bob_ctx.clone())
            .await
            .expect("get before");
        assert_eq!(before["list"].as_array().unwrap().len(), 0);

        // Bob accepts.
        storage
            .accept_sharing(&invitation_id, bob.id)
            .await
            .expect("accept");

        // Now the shared calendar appears with read-only rights.
        let after = calendar_get(json!({"accountId": bob.id.to_string()}), bob_ctx)
            .await
            .expect("get after");
        let list = after["list"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], cal_id);
        assert_eq!(list[0]["myRights"]["mayReadItems"], true);
        assert_eq!(list[0]["myRights"]["mayWriteItems"], false);
    }
}
