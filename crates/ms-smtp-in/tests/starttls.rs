//! STARTTLS upgrade test: a real rustls handshake over an in-memory stream,
//! then a full mail transaction inside the TLS channel.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ms_smtp_in::session::serve_connection;
use ms_smtp_in::{DeliverError, InboundMail, MailHandler, RcptVerdict, SmtpParams};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct MockHandler {
    delivered: Mutex<Vec<InboundMail>>,
}

impl MailHandler for MockHandler {
    async fn rcpt(&self, _address: &str) -> RcptVerdict {
        RcptVerdict::Accept
    }

    async fn deliver(&self, mail: InboundMail) -> Result<(), DeliverError> {
        self.delivered.lock().expect("lock").push(mail);
        Ok(())
    }
}

/// Test-only verifier: accepts the self-signed server certificate.
#[derive(Debug)]
struct AcceptAnyCert(rustls::crypto::CryptoProvider);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_configs() -> (tokio_rustls::TlsAcceptor, tokio_rustls::TlsConnector) {
    let provider = rustls::crypto::ring::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider.clone());

    let certified = rcgen::generate_simple_self_signed(vec!["mail.example.com".to_owned()])
        .expect("self-signed cert");
    let cert = CertificateDer::from(certified.cert);
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("server config");

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();

    (
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        tokio_rustls::TlsConnector::from(Arc::new(client_config)),
    )
}

async fn read_reply<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn starttls_upgrade_then_full_transaction() {
    let (acceptor, connector) = tls_configs();
    let params = Arc::new(
        SmtpParams {
            hostname: "mail.example.com".into(),
            max_message_size: 1024 * 1024,
            max_recipients: 10,
            max_errors: 5,
            read_timeout: Duration::from_secs(5),
            tls: None,
        }
        .with_tls(acceptor),
    );

    let handler = Arc::new(MockHandler::default());
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let session = tokio::spawn(serve_connection(
        server,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        params,
        handler.clone(),
    ));

    // Plaintext phase.
    let banner = read_reply(&mut client).await;
    assert!(banner.starts_with("220 "), "banner: {banner}");

    client
        .write_all(b"EHLO client.test\r\n")
        .await
        .expect("write");
    let ehlo = read_reply(&mut client).await;
    assert!(ehlo.contains("250-STARTTLS"), "advertised: {ehlo}");

    client.write_all(b"STARTTLS\r\n").await.expect("write");
    let go_ahead = read_reply(&mut client).await;
    assert!(go_ahead.starts_with("220 "), "go ahead: {go_ahead}");

    // Handshake and encrypted phase.
    let server_name = ServerName::try_from("mail.example.com").expect("name");
    let mut tls = connector
        .connect(server_name, client)
        .await
        .expect("handshake");

    tls.write_all(b"EHLO client.test\r\n").await.expect("write");
    let ehlo2 = read_reply(&mut tls).await;
    assert!(
        !ehlo2.contains("STARTTLS"),
        "no STARTTLS once encrypted: {ehlo2}"
    );

    tls.write_all(b"MAIL FROM:<s@remote.test>\r\nRCPT TO:<alice@example.com>\r\nDATA\r\n")
        .await
        .expect("write");
    let responses = read_reply(&mut tls).await;
    assert!(responses.contains("354 "), "data go-ahead: {responses}");

    tls.write_all(b"Subject: tls\r\n\r\nencrypted body\r\n.\r\nQUIT\r\n")
        .await
        .expect("write");
    let fin = read_reply(&mut tls).await;
    assert!(fin.contains("250 2.0.0 accepted"), "delivered: {fin}");

    drop(tls);
    session.await.expect("session task");

    let delivered = handler.delivered.lock().expect("lock");
    assert_eq!(delivered.len(), 1);
    let raw = String::from_utf8_lossy(&delivered[0].raw);
    assert!(
        raw.contains("with ESMTPS"),
        "received header notes TLS: {raw}"
    );
    assert!(raw.contains("encrypted body"), "{raw}");
}

#[tokio::test]
async fn starttls_refused_when_not_configured() {
    let params = Arc::new(SmtpParams {
        hostname: "mail.example.com".into(),
        max_message_size: 1024,
        max_recipients: 3,
        max_errors: 5,
        read_timeout: Duration::from_secs(5),
        tls: None,
    });
    let handler = Arc::new(MockHandler::default());
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let session = tokio::spawn(serve_connection(
        server,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        params,
        handler,
    ));

    let _banner = read_reply(&mut client).await;
    client.write_all(b"EHLO c.test\r\n").await.expect("write");
    let ehlo = read_reply(&mut client).await;
    assert!(!ehlo.contains("STARTTLS"), "not advertised: {ehlo}");

    client.write_all(b"STARTTLS\r\n").await.expect("write");
    let refused = read_reply(&mut client).await;
    assert!(refused.starts_with("502 "), "refused: {refused}");

    client.write_all(b"QUIT\r\n").await.expect("write");
    let _ = read_reply(&mut client).await;
    session.await.expect("session");
}
