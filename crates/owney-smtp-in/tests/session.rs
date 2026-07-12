//! Session state-machine tests over in-memory duplex streams — the same
//! byte-level dialogue a real client would have, no TCP involved.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use owney_smtp_in::session::serve_connection;
use owney_smtp_in::{DeliverError, InboundMail, MailHandler, RcptVerdict, SmtpParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct MockHandler {
    delivered: Mutex<Vec<InboundMail>>,
    fail_delivery: bool,
}

impl MailHandler for MockHandler {
    async fn rcpt(&self, address: &str) -> RcptVerdict {
        if !address.ends_with("@example.com") {
            RcptVerdict::NotLocal
        } else if address.starts_with("alice") || address.starts_with("bob") {
            RcptVerdict::Accept
        } else {
            RcptVerdict::UnknownUser
        }
    }

    async fn deliver(&self, mail: InboundMail) -> Result<(), DeliverError> {
        if self.fail_delivery {
            return Err(DeliverError("mock failure".into()));
        }
        self.delivered.lock().expect("lock").push(mail);
        Ok(())
    }
}

fn params() -> Arc<SmtpParams> {
    Arc::new(SmtpParams {
        hostname: "mail.example.com".into(),
        max_message_size: 1024,
        max_recipients: 3,
        max_errors: 5,
        read_timeout: Duration::from_secs(5),
        tls: None,
    })
}

/// Run a scripted dialogue: write everything the client would send, collect
/// everything the server replies until it closes or the script completes.
async fn dialogue(handler: Arc<MockHandler>, client_writes: &[&[u8]]) -> String {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let session = tokio::spawn(serve_connection(
        server,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        params(),
        handler,
    ));

    let (mut read_half, mut write_half) = tokio::io::split(client);
    let reader = tokio::spawn(async move {
        let mut all = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), read_half.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => all.extend_from_slice(&buf[..n]),
                Ok(Err(_)) => break,
            }
        }
        String::from_utf8_lossy(&all).into_owned()
    });

    for chunk in client_writes {
        write_half.write_all(chunk).await.expect("client write");
        // Give the server a beat so multi-step dialogues stay ordered.
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    drop(write_half); // EOF → server session ends

    let output = reader.await.expect("reader");
    session.await.expect("session");
    output
}

#[tokio::test]
async fn happy_path_delivers_with_received_header() {
    let handler = Arc::new(MockHandler::default());
    let output = dialogue(
        handler.clone(),
        &[
            b"EHLO client.test\r\n",
            b"MAIL FROM:<sender@remote.test>\r\n",
            b"RCPT TO:<alice@example.com>\r\n",
            b"DATA\r\n",
            b"Subject: hi\r\n\r\nhello\r\n.\r\n",
            b"QUIT\r\n",
        ],
    )
    .await;

    assert!(
        output.starts_with("220 mail.example.com"),
        "banner: {output}"
    );
    assert!(
        output.contains("250-PIPELINING"),
        "ehlo extensions: {output}"
    );
    assert!(
        output.contains("250-SIZE 1024"),
        "size advertised: {output}"
    );
    assert!(output.contains("354 "), "data go-ahead: {output}");
    assert!(output.contains("250 2.0.0 accepted"), "accepted: {output}");
    assert!(output.contains("221 "), "quit: {output}");

    let delivered = handler.delivered.lock().expect("lock");
    assert_eq!(delivered.len(), 1);
    let mail = &delivered[0];
    assert_eq!(mail.mail_from, "sender@remote.test");
    assert_eq!(mail.recipients, vec!["alice@example.com".to_owned()]);
    assert_eq!(mail.helo, "client.test");
    let raw = String::from_utf8_lossy(&mail.raw);
    assert!(
        raw.starts_with("Received: from client.test ([192.0.2.7])"),
        "raw: {raw}"
    );
    assert!(raw.contains("Subject: hi"), "raw: {raw}");
    assert!(raw.ends_with("hello\r\n"), "final CRLF restored: {raw:?}");
}

#[tokio::test]
async fn unknown_user_rejected_at_rcpt_known_user_accepted() {
    let handler = Arc::new(MockHandler::default());
    let output = dialogue(
        handler.clone(),
        &[
            b"EHLO client.test\r\n",
            b"MAIL FROM:<s@remote.test>\r\n",
            b"RCPT TO:<nobody@example.com>\r\n",
            b"RCPT TO:<stranger@other.test>\r\n",
            b"RCPT TO:<bob@example.com>\r\n",
            b"QUIT\r\n",
        ],
    )
    .await;

    assert!(output.contains("550 5.1.1"), "unknown user: {output}");
    assert!(output.contains("550 5.7.1"), "relay denied: {output}");
    assert!(
        output.contains("250 2.1.5"),
        "valid rcpt accepted: {output}"
    );
    assert!(handler.delivered.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn command_ordering_is_enforced() {
    let handler = Arc::new(MockHandler::default());
    let output = dialogue(
        handler,
        &[
            b"EHLO client.test\r\n",
            b"DATA\r\n",
            b"RCPT TO:<alice@example.com>\r\n",
            b"QUIT\r\n",
        ],
    )
    .await;

    // DATA without RCPT and RCPT without MAIL both refused.
    let count_503 = output.matches("503 5.5.1").count();
    assert_eq!(count_503, 2, "both out-of-order commands refused: {output}");
}

#[tokio::test]
async fn pipelined_transaction_in_one_write() {
    let handler = Arc::new(MockHandler::default());
    let output = dialogue(
        handler.clone(),
        &[
            b"EHLO c.test\r\nMAIL FROM:<s@r.test>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\nfull pipeline\r\n.\r\nQUIT\r\n",
        ],
    )
    .await;

    assert!(
        output.contains("250 2.0.0 accepted"),
        "pipelined delivery: {output}"
    );
    assert_eq!(handler.delivered.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn dot_unstuffing() {
    let handler = Arc::new(MockHandler::default());
    dialogue(
        handler.clone(),
        &[
            b"EHLO c.test\r\n",
            b"MAIL FROM:<s@r.test>\r\n",
            b"RCPT TO:<alice@example.com>\r\n",
            b"DATA\r\n",
            b"line one\r\n..starts with dot\r\n.\r\n",
            b"QUIT\r\n",
        ],
    )
    .await;

    let delivered = handler.delivered.lock().expect("lock");
    let raw = String::from_utf8_lossy(&delivered[0].raw);
    assert!(
        raw.contains("\r\n.starts with dot\r\n"),
        "unstuffed: {raw:?}"
    );
}

#[tokio::test]
async fn oversized_message_rejected_but_connection_survives() {
    let handler = Arc::new(MockHandler::default());
    let big_body = vec![b'x'; 4096]; // params cap is 1024
    let mut data =
        b"EHLO c.test\r\nMAIL FROM:<s@r.test>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\n".to_vec();
    let mut script: Vec<&[u8]> = vec![&data];
    let terminator = b"\r\n.\r\nNOOP\r\nQUIT\r\n";
    script.push(&big_body);
    script.push(terminator);

    let output = dialogue(handler.clone(), &script).await;
    assert!(output.contains("552 5.3.4"), "oversize rejected: {output}");
    assert!(
        output.contains("250 2.0.0 OK"),
        "NOOP still works after: {output}"
    );
    assert!(handler.delivered.lock().expect("lock").is_empty());
    data.clear();
}

#[tokio::test]
async fn delivery_failure_is_a_tempfail() {
    let handler = Arc::new(MockHandler {
        fail_delivery: true,
        ..Default::default()
    });
    let output = dialogue(
        handler,
        &[
            b"EHLO c.test\r\n",
            b"MAIL FROM:<s@r.test>\r\n",
            b"RCPT TO:<alice@example.com>\r\n",
            b"DATA\r\n",
            b"x\r\n.\r\n",
            b"QUIT\r\n",
        ],
    )
    .await;
    assert!(
        output.contains("451 4.3.0"),
        "tempfail, not bounce-later: {output}"
    );
}

#[tokio::test]
async fn too_many_errors_drops_connection() {
    let handler = Arc::new(MockHandler::default());
    let output = dialogue(
        handler,
        &[b"BOGUS1\r\nBOGUS2\r\nBOGUS3\r\nBOGUS4\r\nBOGUS5\r\nBOGUS6\r\n"],
    )
    .await;
    assert!(
        output.contains("421 4.7.0 too many errors"),
        "dropped: {output}"
    );
}

#[tokio::test]
async fn null_reverse_path_accepted_for_bounces() {
    let handler = Arc::new(MockHandler::default());
    let output = dialogue(
        handler.clone(),
        &[
            b"EHLO c.test\r\n",
            b"MAIL FROM:<>\r\n",
            b"RCPT TO:<alice@example.com>\r\n",
            b"DATA\r\nbounce\r\n.\r\n",
            b"QUIT\r\n",
        ],
    )
    .await;
    assert!(
        output.contains("250 2.0.0 accepted"),
        "bounce accepted: {output}"
    );
    assert_eq!(handler.delivered.lock().expect("lock")[0].mail_from, "");
}
