//! Drive the MCP server exactly as an agent would: initialize, list tools,
//! then call tools that read, mutate (undoably), and are gated by scope.

use std::sync::Arc;

use owney_core::AccountId;
use owney_events::EventBus;
use owney_mcp::{McpCtx, handle};
use owney_storage::Storage;
use serde_json::{Value, json};

struct Harness {
    ctx: McpCtx,
    storage: Arc<Storage>,
    account_id: AccountId,
    _dir: tempfile::TempDir,
}

async fn harness(may_send: bool) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(16)).expect("open"));
    let account = storage
        .create_account("alice@example.com", None)
        .await
        .expect("account");

    for (from, subject, body) in [
        ("bob@remote.test", "Lunch?", "Are you free Thursday?"),
        ("news@list.test", "Weekly digest", "Lots of news this week."),
    ] {
        let raw = format!(
            "From: <{from}>\r\nTo: alice@example.com\r\nSubject: {subject}\r\n\
             Message-ID: <{subject}@{from}>\r\n\r\n{body}\r\n"
        );
        storage
            .ingest_email(account.id, raw.into_bytes(), "inbox", None)
            .await
            .expect("ingest");
    }

    let ctx = McpCtx {
        account_id: account.id,
        account_email: "alice@example.com".into(),
        storage: storage.clone(),
        submitter: None,
        may_send,
    };
    Harness {
        ctx,
        storage,
        account_id: account.id,
        _dir: dir,
    }
}

async fn call(h: &Harness, name: &str, args: Value) -> Value {
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    });
    let response = handle(&h.ctx, &request).await.expect("response");
    let result = &response["result"];
    assert_eq!(result["isError"], false, "tool {name} errored: {result}");
    // Tool text content is JSON we produced; parse it back.
    serde_json::from_str(result["content"][0]["text"].as_str().expect("text")).expect("json")
}

#[tokio::test]
async fn initialize_and_list_tools() {
    let h = harness(false).await;
    let init = handle(
        &h.ctx,
        &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}),
    )
    .await
    .expect("init");
    assert_eq!(
        init["result"]["protocolVersion"],
        owney_mcp::PROTOCOL_VERSION
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "mailserver");

    let list = handle(
        &h.ctx,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
    )
    .await
    .expect("list");
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert!(names.contains(&"search_email"));
    assert!(names.contains(&"undo_action"));
}

#[tokio::test]
async fn notification_gets_no_reply() {
    let h = harness(false).await;
    // No id → notification.
    let response = handle(
        &h.ctx,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert!(response.is_none());
}

#[tokio::test]
async fn read_search_and_get() {
    let h = harness(false).await;
    let mailboxes = call(&h, "list_mailboxes", json!({})).await;
    assert!(
        mailboxes
            .as_array()
            .expect("array")
            .iter()
            .any(|m| m["role"] == "inbox")
    );

    let results = call(&h, "search_email", json!({"mailbox": "inbox"})).await;
    assert_eq!(results["total"], 2);
    let first_id = results["results"][0]["id"].as_str().expect("id").to_owned();

    let email = call(&h, "get_email", json!({"id": first_id})).await;
    assert!(email["body"].as_str().expect("body").len() > 5);
    assert!(email["subject"].is_string());
}

#[tokio::test]
async fn move_and_undo_via_activity_feed() {
    let h = harness(false).await;
    let results = call(&h, "search_email", json!({"mailbox": "inbox"})).await;
    let id = results["results"][0]["id"].as_str().expect("id").to_owned();

    call(&h, "move_email", json!({"id": id, "mailbox": "archive"})).await;
    let archived = call(&h, "search_email", json!({"mailbox": "archive"})).await;
    assert_eq!(archived["total"], 1, "moved to archive");

    // The move shows up in the activity feed and is undoable.
    let activity = call(&h, "get_ai_activity", json!({})).await;
    let action = activity
        .as_array()
        .expect("array")
        .iter()
        .find(|a| a["skill"] == "mcp:move")
        .expect("move action");
    assert_eq!(action["undoable"], true);
    let action_id = action["id"].as_str().expect("id").to_owned();

    call(&h, "undo_action", json!({"actionId": action_id})).await;
    let inbox = call(&h, "search_email", json!({"mailbox": "inbox"})).await;
    assert_eq!(inbox["total"], 2, "undo restored it to the inbox");
}

#[tokio::test]
async fn mark_read_clears_unread() {
    let h = harness(false).await;
    let before = call(&h, "list_mailboxes", json!({})).await;
    let inbox_unread = before
        .as_array()
        .expect("array")
        .iter()
        .find(|m| m["role"] == "inbox")
        .expect("inbox")["unread"]
        .as_u64()
        .expect("unread");
    assert_eq!(inbox_unread, 2);

    let results = call(&h, "search_email", json!({"mailbox": "inbox"})).await;
    let id = results["results"][0]["id"].as_str().expect("id").to_owned();
    call(&h, "mark_read", json!({"id": id})).await;

    let after = call(&h, "list_mailboxes", json!({})).await;
    let inbox_unread = after
        .as_array()
        .expect("array")
        .iter()
        .find(|m| m["role"] == "inbox")
        .expect("inbox")["unread"]
        .as_u64()
        .expect("unread");
    assert_eq!(inbox_unread, 1, "one message now read");
}

#[tokio::test]
async fn create_draft_stores_it() {
    let h = harness(false).await;
    let draft = call(
        &h,
        "create_draft",
        json!({"to": ["carol@remote.test"], "subject": "hi", "body": "drafted by an agent"}),
    )
    .await;
    assert!(draft["draftId"].is_string());
    let drafts = call(&h, "search_email", json!({"mailbox": "drafts"})).await;
    assert_eq!(drafts["total"], 1);
}

#[tokio::test]
async fn send_is_scope_gated() {
    // Without send scope, send_email is refused in-band.
    let h = harness(false).await;
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "send_email", "arguments":
            {"to": ["x@y.test"], "subject": "s", "body": "b"}},
    });
    let response = handle(&h.ctx, &request).await.expect("response");
    assert_eq!(response["result"]["isError"], true);
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("not permitted")
    );
    let _ = &h.storage;
    let _ = h.account_id;
}

#[tokio::test]
async fn unknown_method_is_a_protocol_error() {
    let h = harness(false).await;
    let response = handle(
        &h.ctx,
        &json!({"jsonrpc": "2.0", "id": 5, "method": "nonsense", "params": {}}),
    )
    .await
    .expect("response");
    assert_eq!(response["error"]["code"], -32601);
}
