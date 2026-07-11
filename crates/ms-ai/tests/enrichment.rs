//! The AI enrichment pass, end to end with a mock provider: screening,
//! categorization, summaries, unsubscribe detection — and undo.

use std::sync::Arc;

use ms_ai::worker::{AiConfig, process_new_mail};
use ms_ai::{MockProvider, provider::AiProvider};
use ms_core::AccountId;
use ms_events::EventBus;
use ms_storage::Storage;
use serde_json::json;

struct Harness {
    storage: Arc<Storage>,
    account_id: AccountId,
    provider: Arc<MockProvider>,
    config: AiConfig,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(64)).expect("open"));
    let account = storage
        .create_account("alice@example.com", None)
        .await
        .expect("account");
    Harness {
        storage,
        account_id: account.id,
        provider: Arc::new(MockProvider::default()),
        config: AiConfig::default(),
        _dir: dir,
    }
}

async fn ingest(h: &Harness, from: &str, subject: &str, body: &str, extra_headers: &str) {
    let raw = format!(
        "From: <{from}>\r\nTo: alice@example.com\r\nSubject: {subject}\r\n\
         Message-ID: <{subject}@{from}>\r\n{extra_headers}\r\n{body}\r\n"
    );
    h.storage
        .ingest_email(h.account_id, raw.into_bytes(), "inbox", None)
        .await
        .expect("ingest");
}

async fn run(h: &Harness) -> usize {
    process_new_mail(
        &h.storage,
        Some(h.provider.as_ref() as &dyn AiProvider),
        h.account_id,
        &h.config,
    )
    .await
    .expect("process")
}

async fn mailbox_of(h: &Harness, role: &str) -> String {
    h.storage
        .mailbox_id_by_role(h.account_id, role)
        .await
        .expect("role")
        .expect("exists")
}

#[tokio::test]
async fn first_time_sender_goes_to_screener_and_undo_restores() {
    let h = harness().await;
    h.provider.queue(json!({"category": "personal"}));

    ingest(
        &h,
        "stranger@remote.test",
        "hi there",
        "you do not know me",
        "",
    )
    .await;
    assert_eq!(run(&h).await, 1);

    let screener = mailbox_of(&h, "screener").await;
    let inbox = mailbox_of(&h, "inbox").await;
    let screener_mail = h
        .storage
        .list_mailbox(h.account_id, "screener", 10)
        .await
        .expect("list");
    assert_eq!(screener_mail.len(), 1, "first contact screened");
    let email_id = screener_mail[0].id;

    // The action is recorded and undoable.
    let actions = h
        .storage
        .ai_actions(h.account_id, 10)
        .await
        .expect("actions");
    let screen_action = actions
        .iter()
        .find(|a| a.skill == "screener")
        .expect("screener action");
    assert!(screen_action.description.contains("stranger@remote.test"));

    ms_ai::undo_action(&h.storage, h.account_id, screen_action.id)
        .await
        .expect("undo");
    let rows = h
        .storage
        .emails_by_ids(h.account_id, vec![email_id])
        .await
        .expect("rows");
    assert_eq!(
        rows[0].mailbox_ids,
        vec![inbox.clone()],
        "back in the inbox"
    );
    assert_ne!(rows[0].mailbox_ids, vec![screener], "out of the screener");
}

#[tokio::test]
async fn known_sender_stays_in_inbox_and_gets_categorized() {
    let h = harness().await;
    // Two messages from the same sender: second is not first contact.
    h.provider.queue(json!({"category": "personal"}));
    h.provider.queue(json!({"category": "newsletter"}));

    ingest(&h, "friend@remote.test", "one", "hello", "").await;
    run(&h).await;
    ingest(&h, "friend@remote.test", "two", "hello again", "").await;
    run(&h).await;

    let inbox = h
        .storage
        .list_mailbox(h.account_id, "inbox", 10)
        .await
        .expect("list");
    assert_eq!(inbox.len(), 1, "second message stays in inbox");

    let rows = h
        .storage
        .emails_by_ids(h.account_id, vec![inbox[0].id])
        .await
        .expect("rows");
    assert!(
        rows[0].keywords.iter().any(|k| k == "ai:newsletter"),
        "category keyword applied: {:?}",
        rows[0].keywords
    );
}

#[tokio::test]
async fn long_message_gets_summary_and_unsubscribe_is_detected() {
    let h = harness().await;
    h.provider.queue(json!({"category": "newsletter"}));
    h.provider
        .queue(json!({"summary": "A long newsletter about Rust.", "actionItems": []}));

    let long_body = "Rust news. ".repeat(200);
    ingest(
        &h,
        "news@list.test",
        "Weekly Digest",
        &long_body,
        "List-Unsubscribe: <https://list.test/unsub?u=1>, <mailto:unsub@list.test>\r\n\
         List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
    )
    .await;
    run(&h).await;

    let screener = h
        .storage
        .list_mailbox(h.account_id, "screener", 10)
        .await
        .expect("list");
    let email_id = screener[0].id; // first contact → screener, fine

    let annotations = h.storage.annotations(email_id).await.expect("annotations");
    let summary = annotations
        .iter()
        .find(|(kind, _)| kind == "summary")
        .expect("summary");
    assert!(summary.1.contains("Rust"), "{}", summary.1);

    let unsub = annotations
        .iter()
        .find(|(kind, _)| kind == "unsubscribe")
        .expect("unsubscribe annotation");
    let unsub: serde_json::Value = serde_json::from_str(&unsub.1).expect("json");
    assert_eq!(unsub["http"], "https://list.test/unsub?u=1");
    assert_eq!(unsub["mailto"], "unsub@list.test");
    assert_eq!(unsub["oneClick"], true, "RFC 8058 one-click detected");
}

#[tokio::test]
async fn provider_failure_never_blocks_processing() {
    let h = harness().await;
    // Queue nothing: every model call errors ("mock exhausted").
    ingest(&h, "someone@remote.test", "hello", "body", "").await;
    let processed = run(&h).await;
    assert_eq!(processed, 1, "message still processed (fail open)");

    // Deterministic screener still ran.
    let screener = h
        .storage
        .list_mailbox(h.account_id, "screener", 10)
        .await
        .expect("list");
    assert_eq!(screener.len(), 1);
}

#[tokio::test]
async fn cursor_prevents_reprocessing() {
    let h = harness().await;
    h.provider.queue(json!({"category": "personal"}));
    ingest(&h, "x@remote.test", "once", "body", "").await;
    assert_eq!(run(&h).await, 1);
    assert_eq!(run(&h).await, 0, "nothing new on the second pass");

    // Our own keyword updates must not loop the worker.
    let actions = h
        .storage
        .ai_actions(h.account_id, 10)
        .await
        .expect("actions");
    assert_eq!(
        actions.iter().filter(|a| a.skill == "categorizer").count(),
        1,
        "exactly one categorization"
    );
}
