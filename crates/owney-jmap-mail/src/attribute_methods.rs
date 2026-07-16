//! Server-added email attribute methods.
//!
//! Attributes are read through `Email/get` (the `serverAttributes` property);
//! the only client mutation is dismissal. Dismissing bumps the Email modseq,
//! so other clients pick the change up through `Email/changes` + push.

use std::sync::Arc;

use jmap_core::MethodError;
use owney_api::JmapCtx;
use owney_core::DataType;
use serde::Deserialize;
use serde_json::{Value, json};

pub const ATTRIBUTES_CAPABILITY: &str = "urn:owney:params:jmap:attributes";

/// Capability object for server-attribute methods.
pub fn attributes_capability() -> Value {
    json!({
        "kinds": ["unsubscribe", "summary", "calendarInvite"],
        "mayDismiss": true,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DismissArgs {
    account_id: String,
    email_id: String,
    kind: String,
}

pub async fn email_attribute_dismiss(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: DismissArgs = serde_json::from_value(args)
        .map_err(|_| MethodError::InvalidArguments("invalid arguments".to_string()))?;
    let account_id = check_account(&ctx, &args.account_id)?;

    let email_id = args
        .email_id
        .parse()
        .map_err(|_| MethodError::InvalidArguments(format!("bad email id {}", args.email_id)))?;

    ctx.storage
        .dismiss_email_attribute(account_id, email_id, &args.kind)
        .await
        .map_err(storage_err)?;

    let state = ctx
        .storage
        .state(account_id, DataType::Email)
        .await
        .map_err(storage_err)?;

    Ok(json!({
        "emailId": args.email_id,
        "kind": args.kind,
        "dismissed": true,
        "newState": state.to_string(),
    }))
}

fn check_account(ctx: &JmapCtx, account_id: &str) -> Result<owney_core::AccountId, MethodError> {
    if account_id != ctx.account.id.to_string() {
        return Err(MethodError::AccountNotFound);
    }
    Ok(ctx.account.id)
}

/// Preserve the authorization boundary: `NotAuthorized` becomes `Forbidden`,
/// a bad kind becomes `InvalidArguments`, everything else is a server fail.
fn storage_err(e: owney_storage::StorageError) -> MethodError {
    match e {
        owney_storage::StorageError::NotAuthorized => MethodError::Forbidden,
        owney_storage::StorageError::BadInput(msg) => MethodError::InvalidArguments(msg),
        other => MethodError::ServerFail(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use owney_storage::{Account, Storage};

    use super::*;

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

    async fn ingest(storage: &Storage, account: &Account) -> owney_core::EmailId {
        storage
            .ingest_email(
                account.id,
                b"Subject: hi\r\nMessage-ID: <a@x>\r\n\r\nbody".to_vec(),
                "inbox",
                None,
            )
            .await
            .expect("ingest")
            .id
    }

    #[tokio::test]
    async fn email_get_returns_and_projects_server_attributes() {
        let (_dir, storage) = setup().await;
        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let email_id = ingest(&storage, &alice).await;
        storage
            .set_email_attribute(
                alice.id,
                email_id,
                "unsubscribe",
                r#"{"http":"https://x/u","mailto":null,"oneClick":true}"#,
            )
            .await
            .expect("set");

        let ctx = ctx_for(&storage, alice.clone());
        let full = crate::email_get(
            json!({
                "accountId": alice.id.to_string(),
                "ids": [email_id.to_string()],
            }),
            ctx.clone(),
        )
        .await
        .expect("get");
        let attr = &full["list"][0]["serverAttributes"]["unsubscribe"];
        assert_eq!(attr["value"]["oneClick"], true);
        assert_eq!(attr["dismissed"], false);

        // Explicit selection returns it; omitting it excludes it.
        let selected = crate::email_get(
            json!({
                "accountId": alice.id.to_string(),
                "ids": [email_id.to_string()],
                "properties": ["id", "serverAttributes"],
            }),
            ctx.clone(),
        )
        .await
        .expect("get selected");
        let obj = selected["list"][0].as_object().expect("object");
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("serverAttributes"));

        let excluded = crate::email_get(
            json!({
                "accountId": alice.id.to_string(),
                "ids": [email_id.to_string()],
                "properties": ["id"],
            }),
            ctx,
        )
        .await
        .expect("get excluded");
        assert!(
            !excluded["list"][0]
                .as_object()
                .expect("object")
                .contains_key("serverAttributes")
        );
    }

    #[tokio::test]
    async fn dismiss_round_trip_advances_state() {
        let (_dir, storage) = setup().await;
        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let email_id = ingest(&storage, &alice).await;
        storage
            .set_email_attribute(alice.id, email_id, "calendarInvite", r#"{"uid":"1"}"#)
            .await
            .expect("set");
        let before = storage
            .state(alice.id, DataType::Email)
            .await
            .expect("state");

        let ctx = ctx_for(&storage, alice.clone());
        let result = email_attribute_dismiss(
            json!({
                "accountId": alice.id.to_string(),
                "emailId": email_id.to_string(),
                "kind": "calendarInvite",
            }),
            ctx.clone(),
        )
        .await
        .expect("dismiss");
        assert_eq!(result["dismissed"], true);
        assert_eq!(result["newState"], (before.0 + 1).to_string());

        let full = crate::email_get(
            json!({
                "accountId": alice.id.to_string(),
                "ids": [email_id.to_string()],
            }),
            ctx,
        )
        .await
        .expect("get");
        assert_eq!(
            full["list"][0]["serverAttributes"]["calendarInvite"]["dismissed"],
            true
        );
    }

    #[tokio::test]
    async fn cross_account_dismiss_is_rejected() {
        let (_dir, storage) = setup().await;
        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let mallory = storage
            .create_account("mallory@example.com", None)
            .await
            .expect("mallory");
        let email_id = ingest(&storage, &alice).await;
        storage
            .set_email_attribute(alice.id, email_id, "summary", "\"s\"")
            .await
            .expect("set");

        // Mallory with her own accountId against alice's email: Forbidden.
        let err = email_attribute_dismiss(
            json!({
                "accountId": mallory.id.to_string(),
                "emailId": email_id.to_string(),
                "kind": "summary",
            }),
            ctx_for(&storage, mallory.clone()),
        )
        .await
        .expect_err("must fail");
        assert!(matches!(err, MethodError::Forbidden));

        // Mallory impersonating alice's accountId: rejected at the account
        // check before storage is touched.
        let err = email_attribute_dismiss(
            json!({
                "accountId": alice.id.to_string(),
                "emailId": email_id.to_string(),
                "kind": "summary",
            }),
            ctx_for(&storage, mallory),
        )
        .await
        .expect_err("must fail");
        assert!(matches!(err, MethodError::AccountNotFound));

        // Alice's attribute is untouched.
        let attrs = storage
            .list_email_attributes(alice.id, email_id)
            .await
            .expect("list");
        assert_eq!(attrs[0].dismissed_at, None);
    }
}
