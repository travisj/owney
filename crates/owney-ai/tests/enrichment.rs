//! The AI enrichment pass, end to end with a mock provider: screening,
//! categorization, summaries, unsubscribe detection — and undo.

use std::sync::Arc;

use owney_ai::worker::{AiConfig, process_new_mail};
use owney_ai::{MockProvider, provider::AiProvider};
use owney_core::AccountId;
use owney_events::EventBus;
use owney_storage::Storage;
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

    owney_ai::undo_action(&h.storage, h.account_id, screen_action.id)
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

    let attributes = h
        .storage
        .list_email_attributes(h.account_id, email_id)
        .await
        .expect("attributes");
    let summary = attributes
        .iter()
        .find(|attr| attr.kind == "summary")
        .expect("summary");
    assert!(summary.content.contains("Rust"), "{}", summary.content);

    let unsub = attributes
        .iter()
        .find(|attr| attr.kind == "unsubscribe")
        .expect("unsubscribe attribute");
    let unsub: serde_json::Value = serde_json::from_str(&unsub.content).expect("json");
    assert_eq!(unsub["http"], "https://list.test/unsub?u=1");
    assert_eq!(unsub["mailto"], "unsub@list.test");
    assert_eq!(unsub["oneClick"], true, "RFC 8058 one-click detected");
}

#[tokio::test]
async fn calendar_invite_in_mime_part_is_detected() {
    let h = harness().await;
    h.provider.queue(json!({"category": "personal"}));

    let raw = "From: <bob@example.com>\r\n\
               To: alice@example.com\r\n\
               Subject: Team sync\r\n\
               Message-ID: <invite-1@example.com>\r\n\
               MIME-Version: 1.0\r\n\
               Content-Type: multipart/mixed; boundary=\"BB\"\r\n\
               \r\n\
               --BB\r\n\
               Content-Type: text/plain\r\n\
               \r\n\
               Join me for a sync.\r\n\
               --BB\r\n\
               Content-Type: text/calendar; method=REQUEST; charset=UTF-8\r\n\
               \r\n\
               BEGIN:VCALENDAR\r\n\
               METHOD:REQUEST\r\n\
               BEGIN:VEVENT\r\n\
               UID:invite-1@cal.example.com\r\n\
               SUMMARY:Team sync\r\n  (quarterly)\r\n\
               ORGANIZER:mailto:bob@example.com\r\n\
               DTSTART:20260720T150000Z\r\n\
               DTEND:20260720T160000Z\r\n\
               END:VEVENT\r\n\
               END:VCALENDAR\r\n\
               --BB--\r\n";
    h.storage
        .ingest_email(h.account_id, raw.as_bytes().to_vec(), "inbox", None)
        .await
        .expect("ingest");
    run(&h).await;

    let screener = h
        .storage
        .list_mailbox(h.account_id, "screener", 10)
        .await
        .expect("list");
    let email_id = screener[0].id; // first contact → screener

    let attributes = h
        .storage
        .list_email_attributes(h.account_id, email_id)
        .await
        .expect("attributes");
    let invite = attributes
        .iter()
        .find(|attr| attr.kind == "calendarInvite")
        .expect("calendarInvite attribute");
    let invite: serde_json::Value = serde_json::from_str(&invite.content).expect("json");
    assert_eq!(invite["method"], "REQUEST");
    assert_eq!(invite["uid"], "invite-1@cal.example.com");
    assert_eq!(
        invite["summary"], "Team sync (quarterly)",
        "folded line unfolds"
    );
    assert_eq!(invite["organizer"], "mailto:bob@example.com");
    assert_eq!(invite["startAt"], 1_784_559_600);
    assert_eq!(invite["endAt"], 1_784_563_200);
}

#[tokio::test]
async fn plain_message_gets_no_calendar_invite() {
    let h = harness().await;
    h.provider.queue(json!({"category": "personal"}));
    ingest(&h, "bob@example.com", "no ics here", "just text", "").await;
    run(&h).await;

    let screener = h
        .storage
        .list_mailbox(h.account_id, "screener", 10)
        .await
        .expect("list");
    let attributes = h
        .storage
        .list_email_attributes(h.account_id, screener[0].id)
        .await
        .expect("attributes");
    assert!(
        !attributes.iter().any(|attr| attr.kind == "calendarInvite"),
        "{attributes:?}"
    );
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
