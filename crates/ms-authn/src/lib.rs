//! Inbound message authentication.
//!
//! One call ([`Authenticator::verify`]) runs the full 2026 receiving stack —
//! FCrDNS (iprev), SPF, DKIM, ARC, DMARC (RFC 9989 tree walk via `mail-auth`)
//! — and returns a serializable [`AuthVerdict`] that is stored on the message
//! and later feeds screening policy (M5) and the JMAP vendor properties.
//!
//! Verdicts never block delivery in M1; they are recorded evidence.

pub mod cache;

use std::net::IpAddr;

use mail_auth::{
    AuthenticatedMessage, DkimResult, DmarcResult, IprevResult, MessageAuthenticator, Parameters,
    SpfResult,
    dmarc::{Policy, verify::DmarcParameters},
    spf::verify::SpfParameters,
};
use serde::{Deserialize, Serialize};

use crate::cache::DnsCaches;

/// Everything known about a message at the end of DATA.
#[derive(Debug, Clone, Copy)]
pub struct AuthInput<'a> {
    pub remote_ip: IpAddr,
    /// EHLO/HELO hostname as claimed by the client.
    pub helo: &'a str,
    /// Envelope sender (empty = null reverse-path).
    pub mail_from: &'a str,
    /// Raw message as received (before our Received header).
    pub raw: &'a [u8],
}

/// Stored per message; keep every variant lowercase-stable — these strings
/// are persisted and later surfaced through JMAP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerdict {
    /// FCrDNS / iprev: does the connecting IP's PTR round-trip?
    pub iprev: String,
    pub spf: String,
    /// One entry per DKIM signature found.
    pub dkim: Vec<DkimSummary>,
    pub arc: String,
    pub dmarc: String,
    /// The sender domain's requested DMARC policy (none/quarantine/reject).
    pub dmarc_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimSummary {
    pub domain: String,
    pub selector: String,
    pub result: String,
}

/// Typed accessor for [`AuthVerdict::spf`] (Phase 2.1).
///
/// The wire form stays `String` (the lowercase token), but consumers that
/// want exhaustiveness should call [`AuthVerdict::spf_status`] rather than
/// pattern-matching on strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfStatus {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
    None,
}

impl SpfStatus {
    /// Parse a lowercase wire token. Unknown tokens collapse to `None`.
    pub fn parse(token: &str) -> Self {
        match token {
            "pass" => Self::Pass,
            "fail" => Self::Fail,
            "softfail" => Self::SoftFail,
            "neutral" => Self::Neutral,
            "temperror" => Self::TempError,
            "permerror" => Self::PermError,
            "none" => Self::None,
            _ => Self::None,
        }
    }

    /// Lowercase wire token, stable across releases.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
            Self::None => "none",
        }
    }
}

/// Typed accessor for [`AuthVerdict::dkim[].result`] and [`AuthVerdict::arc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimStatus {
    Pass,
    Neutral,
    Fail,
    TempError,
    PermError,
    None,
}

impl DkimStatus {
    pub fn parse(token: &str) -> Self {
        match token {
            "pass" => Self::Pass,
            "neutral" => Self::Neutral,
            "fail" => Self::Fail,
            "temperror" => Self::TempError,
            "permerror" => Self::PermError,
            _ => Self::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Neutral => "neutral",
            Self::Fail => "fail",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
            Self::None => "none",
        }
    }
}

/// Typed accessor for [`AuthVerdict::dmarc`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcStatus {
    Pass,
    Fail { reason: DmarcFailReason },
    TempError,
    PermError,
    None,
}

/// Why a DMARC check failed — propagated from `mail-auth` so consumers can
/// distinguish alignment failure from missing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcFailReason {
    /// Identifier was misaligned (relaxed or strict).
    Unaligned,
    /// Policy was published but did not permit the failing result.
    NotPermitted,
    /// Mismatched identifiers (no shared domain).
    MismatchedIdentifiers,
    /// `mail-auth` returned a different `DmarcResult::Fail(_)` reason — the
    /// `_` matters because the upstream set is wider than we want to enumerate.
    Other,
}

impl DmarcStatus {
    /// Parse a DMARC wire token. `auth-verdict.dmarc="fail"` does not carry
    /// the *reason* over the wire (that's a JMAP vendor-property or
    /// internal-log concern); the parser falls back to `Other` for `fail`
    /// unless the original `DmarcOutput` is available.
    pub fn parse(token: &str) -> Self {
        match token {
            "pass" => Self::Pass,
            "fail" => Self::Fail { reason: DmarcFailReason::Other },
            "temperror" => Self::TempError,
            "permerror" => Self::PermError,
            _ => Self::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail { .. } => "fail",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
            Self::None => "none",
        }
    }
}

impl AuthVerdict {
    /// Typed view of `self.spf`.
    pub fn spf_status(&self) -> SpfStatus {
        SpfStatus::parse(&self.spf)
    }

    /// Typed view of `self.dmarc`.
    pub fn dmarc_status(&self) -> DmarcStatus {
        DmarcStatus::parse(&self.dmarc)
    }

    /// Typed view of `self.arc`.
    pub fn arc_status(&self) -> DkimStatus {
        DkimStatus::parse(&self.arc)
    }

    /// Typed view of each DKIM signature's `result`.
    pub fn dkim_statuses(&self) -> Vec<DkimStatus> {
        self.dkim.iter().map(|d| DkimStatus::parse(&d.result)).collect()
    }
}

impl AuthVerdict {
    /// A compact `Authentication-Results`-style single line for logs and the
    /// stored header.
    pub fn summary(&self) -> String {
        let dkim = if self.dkim.is_empty() {
            "none".to_owned()
        } else {
            self.dkim
                .iter()
                .map(|d| format!("{} ({})", d.result, d.domain))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "iprev={} spf={} dkim={} arc={} dmarc={} (policy={})",
            self.iprev, self.spf, dkim, self.arc, self.dmarc, self.dmarc_policy
        )
    }

    /// RFC 8601 Authentication-Results header value.
    pub fn authentication_results(&self, authserv_id: &str) -> String {
        let mut parts = vec![authserv_id.to_owned()];
        parts.push(format!("iprev={}", self.iprev));
        parts.push(format!("spf={}", self.spf));
        if self.dkim.is_empty() {
            parts.push("dkim=none".to_owned());
        }
        for dkim in &self.dkim {
            parts.push(format!(
                "dkim={} header.d={} header.s={}",
                dkim.result, dkim.domain, dkim.selector
            ));
        }
        parts.push(format!("arc={}", self.arc));
        parts.push(format!(
            "dmarc={} policy.dmarc={}",
            self.dmarc, self.dmarc_policy
        ));
        parts.join(";\r\n\t")
    }
}

pub struct Authenticator {
    inner: MessageAuthenticator,
    caches: DnsCaches,
    /// Our hostname, used as the SPF host domain and authserv-id.
    hostname: String,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// System resolver from /etc/resolv.conf, falling back to Cloudflare.
    pub fn new(hostname: String) -> Self {
        let inner = MessageAuthenticator::new_system_conf()
            .or_else(|_| MessageAuthenticator::new_cloudflare())
            .expect("constructing a DNS resolver cannot fail");
        Self {
            inner,
            caches: DnsCaches::new(),
            hostname,
        }
    }

    /// Test constructor: same resolver, but records come from `caches`.
    pub fn with_caches(hostname: String, caches: DnsCaches) -> Self {
        let mut authenticator = Self::new(hostname);
        authenticator.caches = caches;
        authenticator
    }

    /// Run the full verification stack. Never fails: DNS trouble shows up as
    /// temperror verdicts, evidence rather than errors.
    pub async fn verify(&self, input: AuthInput<'_>) -> AuthVerdict {
        let iprev = self.inner.verify_iprev(self.params(input.remote_ip)).await;

        // SPF: MAIL FROM when present, EHLO identity for bounces (RFC 7208 §2.4).
        let spf = if input.mail_from.is_empty() {
            self.inner
                .verify_spf(self.params(SpfParameters::verify_ehlo(
                    input.remote_ip,
                    input.helo,
                    &self.hostname,
                )))
                .await
        } else {
            self.inner
                .verify_spf(self.params(SpfParameters::verify_mail_from(
                    input.remote_ip,
                    input.helo,
                    &self.hostname,
                    input.mail_from,
                )))
                .await
        };

        let message = AuthenticatedMessage::parse(input.raw);
        let (dkim_summaries, arc, dmarc, dmarc_policy) = match &message {
            Some(message) => {
                let dkim = self.inner.verify_dkim(self.params(message)).await;
                let arc = self.inner.verify_arc(self.params(message)).await;

                let mail_from_domain = input
                    .mail_from
                    .rsplit_once('@')
                    .map(|(_, domain)| domain)
                    .unwrap_or(input.helo);
                let dmarc = self
                    .inner
                    .verify_dmarc(self.params(DmarcParameters {
                        message,
                        dkim_output: &dkim,
                        dkim2_output: None,
                        rfc5321_mail_from_domain: mail_from_domain,
                        spf_output: &spf,
                    }))
                    .await;

                let dkim_summaries = dkim
                    .iter()
                    .map(|output| DkimSummary {
                        domain: output.signature().map(|s| s.d.clone()).unwrap_or_default(),
                        selector: output.signature().map(|s| s.s.clone()).unwrap_or_default(),
                        result: dkim_result_str(output.result()).to_owned(),
                    })
                    .collect();

                let dmarc_result = strongest_dmarc(&dmarc);
                (
                    dkim_summaries,
                    dkim_result_str(arc.result()).to_owned(),
                    dmarc_result,
                    policy_str(dmarc.policy()).to_owned(),
                )
            }
            None => (
                Vec::new(),
                "none".to_owned(),
                "none".to_owned(),
                "none".to_owned(),
            ),
        };

        let verdict = AuthVerdict {
            iprev: iprev_result_str(&iprev.result).to_owned(),
            spf: spf_result_str(spf.result()).to_owned(),
            dkim: dkim_summaries,
            arc,
            dmarc,
            dmarc_policy,
        };
        tracing::debug!(verdict = %verdict.summary(), "authentication complete");
        verdict
    }

    /// Attach our caches to any mail-auth parameter set.
    fn params<'x, P>(&'x self, params: P) -> CachedParameters<'x, P> {
        Parameters {
            params,
            cache_txt: Some(&self.caches.txt),
            cache_mx: Some(&self.caches.mx),
            cache_ipv4: Some(&self.caches.ipv4),
            cache_ipv6: Some(&self.caches.ipv6),
            cache_ptr: Some(&self.caches.ptr),
        }
    }
}

/// A mail-auth parameter set wired to our [`DnsCaches`].
type CachedParameters<'x, P> = Parameters<
    'x,
    P,
    cache::MemoryCache<Box<str>, mail_auth::Txt>,
    cache::MemoryCache<Box<str>, mail_auth::RecordSet<mail_auth::MX>>,
    cache::MemoryCache<Box<str>, mail_auth::RecordSet<std::net::Ipv4Addr>>,
    cache::MemoryCache<Box<str>, mail_auth::RecordSet<std::net::Ipv6Addr>>,
    cache::MemoryCache<IpAddr, mail_auth::RecordSet<Box<str>>>,
>;

fn spf_result_str(result: SpfResult) -> &'static str {
    match result {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
        SpfResult::None => "none",
    }
}

fn dkim_result_str(result: &DkimResult) -> &'static str {
    match result {
        DkimResult::Pass => "pass",
        DkimResult::Neutral(_) => "neutral",
        DkimResult::Fail(_) => "fail",
        DkimResult::PermError(_) => "permerror",
        DkimResult::TempError(_) => "temperror",
        DkimResult::None => "none",
    }
}

fn iprev_result_str(result: &IprevResult) -> &'static str {
    match result {
        IprevResult::Pass => "pass",
        IprevResult::Fail(_) => "fail",
        IprevResult::TempError(_) => "temperror",
        IprevResult::PermError(_) => "permerror",
        IprevResult::None => "none",
    }
}

fn dmarc_result_str(result: &DmarcResult) -> &'static str {
    match result {
        DmarcResult::Pass => "pass",
        DmarcResult::Fail(_) => "fail",
        DmarcResult::TempError(_) => "temperror",
        DmarcResult::PermError(_) => "permerror",
        DmarcResult::None => "none",
    }
}

/// DMARC passes if either aligned identifier passes (RFC 7489 §4.2).
fn strongest_dmarc(output: &mail_auth::DmarcOutput) -> String {
    let spf = output.spf_result();
    let dkim = output.dkim_result();
    if matches!(spf, &DmarcResult::Pass) || matches!(dkim, &DmarcResult::Pass) {
        "pass".to_owned()
    } else if matches!(spf, &DmarcResult::None) && matches!(dkim, &DmarcResult::None) {
        "none".to_owned()
    } else {
        // Prefer the more specific failure.
        let candidate = if matches!(dkim, &DmarcResult::None) {
            spf
        } else {
            dkim
        };
        dmarc_result_str(candidate).to_owned()
    }
}

fn policy_str(policy: Policy) -> &'static str {
    match policy {
        Policy::None => "none",
        Policy::Quarantine => "quarantine",
        Policy::Reject => "reject",
        Policy::Unspecified => "unspecified",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_status_round_trip() {
        for token in ["pass", "fail", "softfail", "neutral", "temperror", "permerror", "none"] {
            let s = SpfStatus::parse(token);
            assert_eq!(s.as_str(), token, "round-trip {token}");
        }
        assert_eq!(SpfStatus::parse("unknown"), SpfStatus::None);
    }

    #[test]
    fn dkim_status_round_trip() {
        for token in ["pass", "neutral", "fail", "temperror", "permerror"] {
            let s = DkimStatus::parse(token);
            assert_eq!(s.as_str(), token, "round-trip {token}");
        }
        assert_eq!(DkimStatus::parse("garbage"), DkimStatus::None);
    }

    #[test]
    fn dmarc_status_round_trip() {
        for token in ["pass", "fail", "temperror", "permerror"] {
            let s = DmarcStatus::parse(token);
            assert_eq!(s.as_str(), token, "round-trip {token}");
        }
        assert_eq!(DmarcStatus::parse("none"), DmarcStatus::None);
        // Fail tokens always carry `reason: Other` since the wire form doesn't carry the reason.
        assert!(matches!(DmarcStatus::parse("fail"), DmarcStatus::Fail { .. }));
    }

    #[test]
    fn verdict_accessors_return_typed_views() {
        let verdict = AuthVerdict {
            iprev: "pass".to_owned(),
            spf: "softfail".to_owned(),
            dkim: vec![DkimSummary {
                domain: "example.com".to_owned(),
                selector: "s1".to_owned(),
                result: "pass".to_owned(),
            }],
            arc: "none".to_owned(),
            dmarc: "fail".to_owned(),
            dmarc_policy: "quarantine".to_owned(),
        };
        assert_eq!(verdict.spf_status(), SpfStatus::SoftFail);
        assert_eq!(verdict.arc_status(), DkimStatus::None);
        assert!(matches!(verdict.dmarc_status(), DmarcStatus::Fail { .. }));
        assert_eq!(verdict.dkim_statuses(), vec![DkimStatus::Pass]);
    }

    #[test]
    fn auth_verdict_serde_round_trip_preserves_strings() {
        let v = AuthVerdict {
            iprev: "pass".to_owned(),
            spf: "fail".to_owned(),
            dkim: vec![],
            arc: "none".to_owned(),
            dmarc: "temperror".to_owned(),
            dmarc_policy: "reject".to_owned(),
        };
        let json = serde_json::to_string(&v).expect("serialize");
        let back: AuthVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, v);
        // Wire form is unchanged.
        assert!(json.contains("\"spf\":\"fail\""));
        assert!(json.contains("\"dmarc\":\"temperror\""));
    }
}
