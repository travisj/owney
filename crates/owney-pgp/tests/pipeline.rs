//! The M4 story, end to end: two servers exchange mail; after one round trip
//! of Autocrypt harvesting, messages encrypt automatically — and the
//! recipient's server transparently decrypts, so its mailbox still reads
//! plaintext. Zero manual key handling anywhere.

use owney_core::AccountId;
use owney_events::EventBus;
use owney_pgp::pipeline;
use owney_storage::Storage;

struct Server {
    storage: Storage,
    account_id: AccountId,
    email: &'static str,
    _dir: tempfile::TempDir,
}

async fn server(email: &'static str) -> Server {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(dir.path(), EventBus::new(8)).expect("open");
    let account = storage.create_account(email, None).await.expect("account");
    Server {
        storage,
        account_id: account.id,
        email,
        _dir: dir,
    }
}

fn message(from: &str, to: &str, subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: <{from}>\r\nTo: <{to}>\r\nSubject: {subject}\r\n\
         Message-ID: <{subject}@{from}>\r\n\r\n{body}\r\n"
    )
    .into_bytes()
}

/// One hop: sender's outbound pipeline, then recipient's inbound pipeline.
async fn send(
    from: &Server,
    to: &Server,
    subject: &str,
    body: &str,
) -> (Vec<u8>, pipeline::InboundOutcome) {
    let raw = message(from.email, to.email, subject, body);
    let wire = pipeline::outbound(
        &from.storage,
        from.account_id,
        from.email,
        &[to.email.to_owned()],
        raw,
    )
    .await
    .expect("outbound");
    let outcome = pipeline::inbound(&to.storage, to.account_id, wire.clone())
        .await
        .expect("inbound");
    (wire, outcome)
}

#[tokio::test]
async fn autocrypt_bootstrap_then_automatic_encryption() {
    let alice = server("alice@a.test").await;
    let bob = server("bob@b.test").await;

    // 1. First contact: cleartext, but Alice's key rides along.
    let (wire, outcome) = send(&alice, &bob, "hello", "first contact").await;
    let wire_text = String::from_utf8_lossy(&wire);
    assert!(
        wire_text.starts_with("Autocrypt: addr=alice@a.test;"),
        "header injected"
    );
    assert!(
        !wire_text.contains("BEGIN PGP MESSAGE"),
        "not yet encrypted"
    );
    assert!(outcome.pgp_status.is_none(), "plain message");
    assert!(outcome.key_changes.is_empty());
    // Bob's server now knows Alice's key.
    assert!(
        bob.storage
            .pgp_peer(bob.account_id, "alice@a.test")
            .await
            .expect("peer")
            .is_some()
    );

    // 2. Bob replies: cleartext (Bob doesn't know if Alice can decrypt yet is
    //    false — he has her key now, so this already encrypts!).
    let (wire, outcome) = send(&bob, &alice, "re: hello", "reply").await;
    assert!(
        String::from_utf8_lossy(&wire).contains("BEGIN PGP MESSAGE"),
        "reply encrypts immediately — Bob harvested Alice's key"
    );
    let status = outcome.pgp_status.expect("pgp status");
    assert!(status.contains(r#""encrypted":true"#), "{status}");
    assert!(
        status.contains(r#""signature":"valid""#),
        "signed by Bob, verified: {status}"
    );
    // Alice's copy is readable plaintext.
    let stored = String::from_utf8_lossy(&outcome.raw);
    assert!(stored.contains("reply"), "decrypted for storage: {stored}");
    assert!(
        stored.contains("Subject: re: hello"),
        "inner headers survive: {stored}"
    );

    // 3. Alice → Bob again: now encrypted in both directions.
    let (wire, outcome) = send(&alice, &bob, "secret plans", "meet at dawn").await;
    let wire_text = String::from_utf8_lossy(&wire);
    assert!(
        wire_text.contains("multipart/encrypted"),
        "PGP/MIME envelope"
    );
    assert!(
        wire_text.contains("Subject: secret plans"),
        "routing headers on envelope"
    );
    assert!(
        !wire_text.contains("meet at dawn"),
        "body is NOT in the clear on the wire"
    );
    let stored = String::from_utf8_lossy(&outcome.raw);
    assert!(
        stored.contains("meet at dawn"),
        "but Bob's server stores plaintext"
    );
    assert!(
        outcome
            .pgp_status
            .expect("status")
            .contains(r#""signature":"valid""#),
        "Alice's signature verifies against her harvested key"
    );
}

#[tokio::test]
async fn key_change_is_flagged() {
    let alice = server("alice@a.test").await;
    let bob = server("bob@b.test").await;

    // Bob learns Alice's key.
    send(&alice, &bob, "hi", "x").await;

    // "Alice" shows up with a different key (rotation — or an impostor).
    let mallory_cert = owney_pgp::generate_cert("alice@a.test", None).expect("cert");
    let header = owney_pgp::autocrypt::header("alice@a.test", &mallory_cert, true).expect("header");
    let mut raw = format!("Autocrypt: {header}\r\n").into_bytes();
    raw.extend_from_slice(&message("alice@a.test", bob.email, "urgent", "trust me"));

    let outcome = pipeline::inbound(&bob.storage, bob.account_id, raw)
        .await
        .expect("inbound");
    assert_eq!(
        outcome.key_changes,
        vec!["alice@a.test".to_owned()],
        "change detected"
    );
}

#[tokio::test]
async fn undecryptable_message_is_kept_and_marked() {
    let alice = server("alice@a.test").await;
    let bob = server("bob@b.test").await;
    let eve = server("eve@e.test").await;

    // Alice encrypts to Eve, but the message lands at Bob (mis-delivery).
    send(&alice, &eve, "bootstrap", "x").await;
    send(&eve, &alice, "re: bootstrap", "y").await;
    let raw = message(alice.email, eve.email, "for eve", "not for bob");
    let wire = pipeline::outbound(
        &alice.storage,
        alice.account_id,
        alice.email,
        &["eve@e.test".to_owned()],
        raw,
    )
    .await
    .expect("outbound");
    assert!(String::from_utf8_lossy(&wire).contains("BEGIN PGP MESSAGE"));

    let outcome = pipeline::inbound(&bob.storage, bob.account_id, wire)
        .await
        .expect("inbound");
    assert!(
        outcome
            .pgp_status
            .expect("status")
            .contains("undecryptable"),
        "kept as ciphertext, marked undecryptable"
    );
}
