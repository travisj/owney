//! JMAP mail methods end-to-end: ingest real messages, then drive the
//! dispatcher exactly as a client would (including chained result refs).

use std::sync::Arc;

use jmap_core::{CORE_CAPABILITY, Dispatcher};
use ms_api::JmapCtx;
use ms_events::EventBus;
use ms_jmap_mail::MAIL_CAPABILITY;
use ms_storage::Storage;
use serde_json::{Value, json};

/// (mail_from, recipients) pairs seen by the mock submitter.
type Submitted = Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>;

struct Harness {
    dispatcher: Dispatcher<JmapCtx>,
    ctx: Arc<JmapCtx>,
    account_id: String,
    submitted: Submitted,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(64)).expect("open"));
    let account = storage
        .create_account("alice@example.com", None)
        .await
        .expect("account");

    for (message_id, subject, references, body) in [
        ("m1@remote.test", "Hello", "", "first message body"),
        (
            "m2@remote.test",
            "Re: Hello",
            "<m1@remote.test>",
            "the reply",
        ),
        ("m3@remote.test", "Unrelated", "", "other thread"),
    ] {
        let refs = if references.is_empty() {
            String::new()
        } else {
            format!("References: {references}\r\n")
        };
        let raw = format!(
            "From: Bob Remote <bob@remote.test>\r\nTo: alice@example.com\r\n\
             Message-ID: <{message_id}>\r\nSubject: {subject}\r\n{refs}\r\n{body}\r\n"
        );
        storage
            .ingest_email(account.id, raw.into_bytes(), "inbox", None)
            .await
            .expect("ingest");
    }

    let mut dispatcher: Dispatcher<JmapCtx> = Dispatcher::new("s0");
    ms_jmap_mail::register(&mut dispatcher);

    let account_id = account.id.to_string();
    let submitted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ctx = Arc::new(JmapCtx {
        account,
        storage,
        submitter: Some(Arc::new(MockSubmitter {
            submitted: submitted.clone(),
        })),
    });
    Harness {
        dispatcher,
        ctx,
        account_id,
        submitted,
        _dir: dir,
    }
}

/// Records submissions instead of delivering them.
struct MockSubmitter {
    submitted: Submitted,
}

impl ms_delivery::Submitter for MockSubmitter {
    fn submit(
        &self,
        _account_id: ms_core::AccountId,
        mail_from: String,
        recipients: Vec<String>,
        _raw: Vec<u8>,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<uuid::Uuid>, ms_delivery::SubmitError>> + Send + '_>,
    > {
        self.submitted
            .lock()
            .expect("lock")
            .push((mail_from, recipients));
        Box::pin(async { Ok(vec![uuid::Uuid::now_v7()]) })
    }
}

impl Harness {
    async fn call(&self, calls: Value) -> Vec<jmap_core::Invocation> {
        let request = serde_json::from_value(json!({
            "using": [CORE_CAPABILITY, MAIL_CAPABILITY, ms_jmap_mail::SUBMISSION_CAPABILITY],
            "methodCalls": calls,
        }))
        .expect("request");
        self.dispatcher
            .process(request, self.ctx.clone())
            .await
            .expect("process")
            .method_responses
    }
}

#[tokio::test]
async fn mailbox_get_shows_counts() {
    let h = harness().await;
    let responses = h
        .call(json!([["Mailbox/get", {"accountId": h.account_id}, "c1"]]))
        .await;

    let list = responses[0].arguments()["list"]
        .as_array()
        .expect("list")
        .clone();
    assert_eq!(list.len(), 7, "default mailbox set");
    let inbox = list
        .iter()
        .find(|m| m["role"] == "inbox")
        .expect("inbox present");
    assert_eq!(inbox["totalEmails"], 3);
    assert_eq!(inbox["unreadEmails"], 3, "nothing seen yet");
}

#[tokio::test]
async fn query_then_get_via_result_reference() {
    let h = harness().await;
    let responses = h
        .call(json!([
            ["Email/query", {"accountId": h.account_id, "limit": 10}, "c1"],
            ["Email/get", {
                "accountId": h.account_id,
                "#ids": {"resultOf": "c1", "name": "Email/query", "path": "/ids"},
                "fetchTextBodyValues": true,
            }, "c2"],
        ]))
        .await;

    assert_eq!(responses[0].arguments()["total"], 3);
    let list = responses[1].arguments()["list"].as_array().expect("list");
    assert_eq!(list.len(), 3);

    let newest = &list[0];
    assert_eq!(newest["subject"], "Unrelated", "newest first");
    assert_eq!(newest["from"][0]["email"], "bob@remote.test");
    assert_eq!(newest["from"][0]["name"], "Bob Remote");
    assert_eq!(newest["to"][0]["email"], "alice@example.com");
    assert!(
        newest["bodyValues"]["1"]["value"]
            .as_str()
            .expect("body")
            .contains("other thread")
    );
    assert!(
        newest["preview"]
            .as_str()
            .expect("preview")
            .contains("other thread")
    );
}

#[tokio::test]
async fn threads_group_replies() {
    let h = harness().await;
    let responses = h
        .call(json!([
            ["Email/query", {"accountId": h.account_id}, "c1"],
            ["Email/get", {
                "accountId": h.account_id,
                "#ids": {"resultOf": "c1", "name": "Email/query", "path": "/ids"},
            }, "c2"],
        ]))
        .await;
    let list = responses[1].arguments()["list"].as_array().expect("list");

    // Hello + its reply share a thread; Unrelated is alone.
    let hello_thread = list
        .iter()
        .find(|e| e["subject"] == "Hello")
        .expect("hello")["threadId"]
        .as_str()
        .expect("thread id")
        .to_owned();

    let responses = h
        .call(json!([["Thread/get", {"accountId": h.account_id, "ids": [hello_thread]}, "c1"]]))
        .await;
    let thread = &responses[0].arguments()["list"][0];
    assert_eq!(
        thread["emailIds"].as_array().expect("email ids").len(),
        2,
        "reply joined the thread"
    );
}

#[tokio::test]
async fn set_keywords_marks_read_and_changes_track_it() {
    let h = harness().await;
    let responses = h
        .call(json!([["Email/query", {"accountId": h.account_id, "limit": 1}, "c1"]]))
        .await;
    let email_id = responses[0].arguments()["ids"][0]
        .as_str()
        .expect("id")
        .to_owned();
    let state_before = h
        .call(json!([["Email/get", {"accountId": h.account_id, "ids": []}, "c1"]]))
        .await[0]
        .arguments()["state"]
        .as_str()
        .expect("state")
        .to_owned();

    // Mark read via per-keyword patch.
    let responses = h
        .call(json!([["Email/set", {
            "accountId": h.account_id,
            "update": {email_id.clone(): {"keywords/$seen": true}},
        }, "c1"]]))
        .await;
    assert!(
        responses[0].arguments()["updated"]
            .as_object()
            .expect("updated")
            .contains_key(&email_id),
        "{:?}",
        responses[0]
    );

    // The email now reports $seen; inbox unread count dropped.
    let responses = h
        .call(json!([
            ["Email/get", {"accountId": h.account_id, "ids": [email_id]}, "c1"],
            ["Mailbox/get", {"accountId": h.account_id}, "c2"],
            ["Email/changes", {"accountId": h.account_id, "sinceState": state_before}, "c3"],
        ]))
        .await;
    assert_eq!(
        responses[0].arguments()["list"][0]["keywords"]["$seen"],
        true
    );
    let mailboxes = responses[1].arguments()["list"].as_array().expect("list");
    let inbox = mailboxes
        .iter()
        .find(|m| m["role"] == "inbox")
        .expect("inbox");
    assert_eq!(inbox["unreadEmails"], 2);

    let changes = responses[2].arguments();
    assert_eq!(
        changes["updated"].as_array().expect("updated"),
        &vec![json!(email_id)]
    );
    assert!(changes["created"].as_array().expect("created").is_empty());
}

#[tokio::test]
async fn changes_from_zero_report_all_as_created() {
    let h = harness().await;
    let responses = h
        .call(json!([["Email/changes", {"accountId": h.account_id, "sinceState": "0"}, "c1"]]))
        .await;
    let changes = responses[0].arguments();
    assert_eq!(changes["created"].as_array().expect("created").len(), 3);
    assert!(changes["updated"].as_array().expect("updated").is_empty());
    assert_eq!(changes["hasMoreChanges"], false);
}

#[tokio::test]
async fn compose_draft_then_submit() {
    let h = harness().await;
    // Find the Drafts mailbox.
    let responses = h
        .call(json!([["Mailbox/get", {"accountId": h.account_id}, "c1"]]))
        .await;
    let drafts_id = responses[0].arguments()["list"]
        .as_array()
        .expect("list")
        .iter()
        .find(|m| m["role"] == "drafts")
        .expect("drafts mailbox")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Create the draft with a body.
    let responses = h
        .call(json!([
            ["Email/set", {
                "accountId": h.account_id,
                "create": {"d1": {
                    "mailboxIds": {drafts_id.clone(): true},
                    "keywords": {"$draft": true, "$seen": true},
                    "to": [{"name": "Carol", "email": "carol@remote.test"}],
                    "subject": "Composed over JMAP",
                    "textBody": [{"partId": "1"}],
                    "bodyValues": {"1": {"value": "Written in a client,\nsent by the server."}},
                }},
            }, "c1"],
        ]))
        .await;

    let created = &responses[0].arguments()["created"]["d1"];
    assert!(
        created["id"].is_string(),
        "draft created: {:?}",
        responses[0]
    );
    let draft_id = created["id"].as_str().expect("id").to_owned();

    // Submit it (creation-id back-references arrive with createdIds support).
    let responses = h
        .call(json!([
            ["EmailSubmission/set", {
                "accountId": h.account_id,
                "create": {"s1": {"emailId": draft_id.clone()}},
            }, "c2"],
        ]))
        .await;
    let submission = &responses[0].arguments()["created"]["s1"];
    assert!(
        submission["id"].is_string(),
        "submitted: {:?}",
        responses[0]
    );

    // The mock submitter saw the right envelope (recipients from headers).
    {
        let submitted = h.submitted.lock().expect("lock");
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].0, "alice@example.com");
        assert_eq!(submitted[0].1, vec!["carol@remote.test".to_owned()]);
    }

    // The draft is readable with its keywords and body.
    let responses = h
        .call(json!([["Email/get", {
            "accountId": h.account_id,
            "ids": [draft_id],
            "fetchTextBodyValues": true,
        }, "c1"]]))
        .await;
    let draft = &responses[0].arguments()["list"][0];
    assert_eq!(draft["keywords"]["$draft"], true);
    assert_eq!(draft["subject"], "Composed over JMAP");
    assert!(
        draft["bodyValues"]["1"]["value"]
            .as_str()
            .expect("body")
            .contains("Written in a client")
    );
}

#[tokio::test]
async fn identity_get_returns_account_identity() {
    let h = harness().await;
    let responses = h
        .call(json!([["Identity/get", {"accountId": h.account_id}, "c1"]]))
        .await;
    let identity = &responses[0].arguments()["list"][0];
    assert_eq!(identity["email"], "alice@example.com");
    assert_eq!(identity["mayDelete"], false);
}

#[tokio::test]
async fn wrong_account_is_rejected() {
    let h = harness().await;
    let responses = h
        .call(json!([["Mailbox/get", {"accountId": "someone-else"}, "c1"]]))
        .await;
    assert_eq!(responses[0].name(), "error");
    assert_eq!(responses[0].arguments()["type"], "accountNotFound");
}

#[tokio::test]
async fn email_query_rejects_unknown_filter_key() {
    let h = harness().await;
    let account_id = h.account_id.clone();

    let responses = h.call(json!([
        ["Email/query", {
            "accountId": account_id,
            "filter": {"typo_field": "value", "inMailbox": "ignored"},
            "limit": 5
        }, "c1"]
    ])).await;

    assert_eq!(responses[0].name(), "error");
    assert_eq!(
        responses[0].arguments()["type"], "invalidArguments",
        "got {responses:?}"
    );
}
