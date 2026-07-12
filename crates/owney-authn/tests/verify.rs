//! Full-stack verification with injected DNS records — zero network access.

use std::net::{IpAddr, Ipv4Addr};

use mail_auth::common::parse::TxtRecordParser;
use mail_auth::{dmarc::Dmarc, spf::Spf};
use owney_authn::cache::DnsCaches;
use owney_authn::{AuthInput, Authenticator};

const REMOTE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

fn message() -> Vec<u8> {
    b"From: Bob <bob@remote.test>\r\nTo: alice@example.com\r\n\
      Message-ID: <m1@remote.test>\r\nSubject: authn test\r\n\r\nhello\r\n"
        .to_vec()
}

fn caches() -> DnsCaches {
    let caches = DnsCaches::new();
    // FCrDNS: 192.0.2.7 → mx.remote.test → 192.0.2.7
    caches.add_ptr(REMOTE_IP, "mx.remote.test.", 300);
    caches.add_ipv4("mx.remote.test.", vec![Ipv4Addr::new(192, 0, 2, 7)], 300);
    caches
}

#[tokio::test]
async fn aligned_spf_pass_gives_dmarc_pass() {
    let caches = caches();
    caches.add_txt(
        "remote.test.",
        Spf::parse(b"v=spf1 ip4:192.0.2.7 -all").expect("spf record"),
        300,
    );
    caches.add_txt(
        "_dmarc.remote.test.",
        Dmarc::parse(b"v=DMARC1; p=reject").expect("dmarc record"),
        300,
    );

    let authenticator = Authenticator::with_caches("mail.example.com".into(), caches);
    let raw = message();
    let verdict = authenticator
        .verify(AuthInput {
            remote_ip: REMOTE_IP,
            helo: "mx.remote.test",
            mail_from: "bob@remote.test",
            raw: &raw,
        })
        .await;

    assert_eq!(verdict.iprev, "pass", "fcrdns: {verdict:?}");
    assert_eq!(verdict.spf, "pass", "{verdict:?}");
    assert_eq!(
        verdict.dmarc, "pass",
        "aligned spf ⇒ dmarc pass: {verdict:?}"
    );
    assert_eq!(verdict.dmarc_policy, "reject");
    assert!(verdict.dkim.is_empty(), "no signatures present");
    assert!(verdict.summary().contains("spf=pass"));
    let header = verdict.authentication_results("mail.example.com");
    assert!(header.contains("spf=pass"), "{header}");
}

#[tokio::test]
async fn spoofed_sender_fails_spf_and_dmarc() {
    let caches = caches();
    // remote.test only authorizes 198.51.100.1 — not our connecting IP.
    caches.add_txt(
        "remote.test.",
        Spf::parse(b"v=spf1 ip4:198.51.100.1 -all").expect("spf record"),
        300,
    );
    caches.add_txt(
        "_dmarc.remote.test.",
        Dmarc::parse(b"v=DMARC1; p=quarantine").expect("dmarc record"),
        300,
    );

    let authenticator = Authenticator::with_caches("mail.example.com".into(), caches);
    let raw = message();
    let verdict = authenticator
        .verify(AuthInput {
            remote_ip: REMOTE_IP,
            helo: "mx.remote.test",
            mail_from: "bob@remote.test",
            raw: &raw,
        })
        .await;

    assert_eq!(verdict.spf, "fail", "{verdict:?}");
    assert_ne!(verdict.dmarc, "pass", "{verdict:?}");
    assert_eq!(verdict.dmarc_policy, "quarantine");
}

#[tokio::test]
async fn null_reverse_path_checks_helo_identity() {
    let caches = caches();
    caches.add_txt(
        "mx.remote.test.",
        Spf::parse(b"v=spf1 ip4:192.0.2.7 -all").expect("spf record"),
        300,
    );

    let authenticator = Authenticator::with_caches("mail.example.com".into(), caches);
    let raw = message();
    let verdict = authenticator
        .verify(AuthInput {
            remote_ip: REMOTE_IP,
            helo: "mx.remote.test",
            mail_from: "",
            raw: &raw,
        })
        .await;

    assert_eq!(
        verdict.spf, "pass",
        "bounce checked against EHLO: {verdict:?}"
    );
}
