//! Full outbound → inbound loopback: submit on server A, deliver over real
//! TCP to server B's SMTP listener, then verify A's DKIM signature on what B
//! received — using B-side DNS injected from A's published record. No network.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use mail_auth::common::parse::TxtRecordParser;
use owney_authn::cache::DnsCaches;
use owney_authn::{AuthInput, Authenticator};
use owney_core::AccountId;
use owney_delivery::{DeliveryParams, DeliveryService, DkimKeys, Relay, StaticRouter};
use owney_events::EventBus;
use owney_smtp_in::{DeliverError, InboundMail, MailHandler, RcptVerdict, SmtpParams};
use owney_storage::Storage;

/// Receiver-side handler: accept everything for b.test, ingest into inbox.
struct ReceiverCore {
    storage: Arc<Storage>,
    account_id: AccountId,
}

impl MailHandler for ReceiverCore {
    async fn rcpt(&self, address: &str) -> RcptVerdict {
        if address.ends_with("@b.test") {
            RcptVerdict::Accept
        } else {
            RcptVerdict::NotLocal
        }
    }

    async fn deliver(&self, mail: InboundMail) -> Result<(), DeliverError> {
        self.storage
            .ingest_email(self.account_id, mail.raw, "inbox", None)
            .await
            .map_err(|err| DeliverError::Temporary(err.to_string()))?;
        Ok(())
    }
}

struct Receiver {
    storage: Arc<Storage>,
    account_id: AccountId,
    relay: Relay,
    _dir: tempfile::TempDir,
}

async fn start_receiver() -> Receiver {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(64)).expect("open"));
    let account = storage
        .create_account("bob@b.test", None)
        .await
        .expect("account");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let params = Arc::new(SmtpParams {
        hostname: "mx.b.test".into(),
        max_message_size: 1024 * 1024,
        max_recipients: 10,
        max_errors: 5,
        read_timeout: Duration::from_secs(5),
        tls: None,
    });
    let handler = Arc::new(ReceiverCore {
        storage: storage.clone(),
        account_id: account.id,
    });
    tokio::spawn(owney_smtp_in::server::run_listener(
        listener, params, handler,
    ));

    Receiver {
        storage,
        account_id: account.id,
        relay: Relay {
            host: "127.0.0.1".into(),
            port,
        },
        _dir: dir,
    }
}

struct Sender {
    service: DeliveryService<StaticRouter>,
    account_id: AccountId,
    _worker: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

async fn start_sender(relay: Relay) -> Sender {
    let dir = tempfile::tempdir().expect("tempdir");
    let events = EventBus::new(64);
    let storage = Arc::new(Storage::open(dir.path(), events.clone()).expect("open"));
    let account = storage
        .create_account("alice@a.test", None)
        .await
        .expect("account");
    let dkim = DkimKeys::load_or_generate(dir.path(), "a.test").expect("dkim");
    let router = Arc::new(StaticRouter { relay });
    let params = DeliveryParams {
        hostname: "mx.a.test".into(),
        poll_interval: Duration::from_millis(100),
        allow_invalid_certs: true,
    };
    let wake = Arc::new(tokio::sync::Notify::new());
    let worker = owney_delivery::spawn_worker(
        storage.clone(),
        events.clone(),
        router.clone(),
        params.clone(),
        wake.clone(),
    );
    Sender {
        service: DeliveryService {
            storage,
            events,
            dkim,
            router,
            params,
            wake,
        },
        account_id: account.id,
        _worker: worker,
        _dir: dir,
    }
}

fn test_message() -> Vec<u8> {
    format!(
        "From: Alice <alice@a.test>\r\nTo: Bob <bob@b.test>\r\n\
         Subject: loopback\r\nMessage-ID: <loop1@a.test>\r\nDate: {}\r\n\r\n\
         Sent by the delivery worker.\r\n",
        owney_core::time::rfc2822_utc(1_783_137_275),
    )
    .into_bytes()
}

#[tokio::test]
async fn submit_deliver_receive_and_dkim_verifies() {
    let receiver = start_receiver().await;
    let sender = start_sender(receiver.relay.clone()).await;

    let queued = sender
        .service
        .submit(
            sender.account_id,
            "alice@a.test",
            &["bob@b.test".to_owned()],
            test_message(),
        )
        .await
        .expect("submit");
    assert_eq!(queued.len(), 1);

    // Sent copy exists on A immediately.
    let sent = sender
        .service
        .storage
        .list_mailbox(sender.account_id, "sent", 10)
        .await
        .expect("sent list");
    assert_eq!(sent.len(), 1, "sent copy stored");

    // Wait for the worker to deliver.
    let mut received = Vec::new();
    for _ in 0..100 {
        received = receiver
            .storage
            .list_mailbox(receiver.account_id, "inbox", 10)
            .await
            .expect("list");
        if !received.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(received.len(), 1, "message arrived at B");
    assert_eq!(received[0].subject.as_deref(), Some("loopback"));

    // Queue row records success.
    let status = sender
        .service
        .storage
        .queue_status(queued[0])
        .await
        .expect("status");
    assert_eq!(status.expect("row").0, "delivered");

    // Verify A's DKIM signature on the bytes B received, with A's published
    // DNS record injected into B's resolver cache.
    let raw = receiver
        .storage
        .email_raw(received[0].id)
        .await
        .expect("raw")
        .expect("present");
    let (record_name, record_value) = sender.service.dkim.dns_record();
    let caches = DnsCaches::new();
    caches.add_txt(
        format!("{record_name}."),
        mail_auth::common::verify::DomainKey::parse(record_value.as_bytes()).expect("domain key"),
        300,
    );
    let authenticator = Authenticator::with_caches("mx.b.test".into(), caches);
    let verdict = authenticator
        .verify(AuthInput {
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            helo: "mx.a.test",
            mail_from: "alice@a.test",
            raw: &raw,
        })
        .await;
    assert_eq!(verdict.dkim.len(), 1, "{verdict:?}");
    assert_eq!(verdict.dkim[0].result, "pass", "{verdict:?}");
    assert_eq!(verdict.dkim[0].domain, "a.test");
}

#[tokio::test]
async fn unreachable_relay_defers_with_backoff() {
    // TCP port 9 on localhost: nothing listens; connection refused.
    let sender = start_sender(Relay {
        host: "127.0.0.1".into(),
        port: 9,
    })
    .await;

    let queued = sender
        .service
        .submit(
            sender.account_id,
            "alice@a.test",
            &["bob@b.test".to_owned()],
            test_message(),
        )
        .await
        .expect("submit");

    let mut status = None;
    for _ in 0..100 {
        status = sender
            .service
            .storage
            .queue_status(queued[0])
            .await
            .expect("status");
        if let Some((_, attempts, _)) = &status
            && *attempts >= 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (state, attempts, last_error) = status.expect("row");
    assert_eq!(state, "queued", "still retrying, not failed");
    assert!(attempts >= 1);
    assert!(last_error.is_some());
}

#[tokio::test]
async fn chat_mode_flag_stored_and_retrieved() {
    // Verify that chat_mode is correctly stored and retrieved from emails.
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(8)).expect("open"));
    let account = storage
        .create_account("alice@example.com", None)
        .await
        .expect("account");

    let raw = test_message();

    // Ingest with chat_mode=true
    let chat_ingested = storage
        .ingest_email_with_chat(account.id, raw.clone(), "inbox", None, true)
        .await
        .expect("ingest chat");

    // Ingest with chat_mode=false
    let normal_ingested = storage
        .ingest_email_with_chat(account.id, raw.clone(), "inbox", None, false)
        .await
        .expect("ingest normal");

    // Retrieve and verify chat_mode is set correctly
    let rows = storage
        .emails_by_ids(account.id, vec![chat_ingested.id, normal_ingested.id])
        .await
        .expect("fetch");

    assert_eq!(rows.len(), 2);

    let chat_row = rows
        .iter()
        .find(|r| r.id == chat_ingested.id.to_string())
        .expect("find chat email");
    assert_eq!(
        chat_row.chat_mode, true,
        "chat-mode email should have chat_mode=true"
    );

    let normal_row = rows
        .iter()
        .find(|r| r.id == normal_ingested.id.to_string())
        .expect("find normal email");
    assert_eq!(
        normal_row.chat_mode, false,
        "normal email should have chat_mode=false"
    );
}

#[tokio::test]
async fn chat_preference_storage_operations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(8)).expect("open"));
    let account = storage
        .create_account("alice@example.com", None)
        .await
        .expect("account");

    // Set auto_chat for bob
    storage
        .set_chat_preference(
            account.id,
            "bob@example.com",
            owney_storage::ChatMode::AutoChat,
        )
        .await
        .expect("set");

    // Verify retrieval
    let pref = storage
        .get_chat_preference(account.id, "bob@example.com")
        .await
        .expect("get");
    assert_eq!(pref, owney_storage::ChatMode::AutoChat);

    // Set never_chat for spam
    storage
        .set_chat_preference(
            account.id,
            "spam@bot.com",
            owney_storage::ChatMode::NeverChat,
        )
        .await
        .expect("set");

    // List should show both
    let prefs = storage
        .list_chat_preferences(account.id)
        .await
        .expect("list");
    assert_eq!(prefs.len(), 2);

    // Delete one
    storage
        .delete_chat_preference(account.id, "bob@example.com")
        .await
        .expect("delete");

    let prefs = storage
        .list_chat_preferences(account.id)
        .await
        .expect("list");
    assert_eq!(prefs.len(), 1);
    assert_eq!(prefs[0].contact_email, "spam@bot.com");

    // Default when not set is RespectSender
    let default_pref = storage
        .get_chat_preference(account.id, "unknown@example.com")
        .await
        .expect("default");
    assert_eq!(default_pref, owney_storage::ChatMode::RespectSender);
}
