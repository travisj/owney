//! Live DNS verification of the expected record set, plus operational
//! preflight checks (FCrDNS, outbound port 25). Used by `setup --verify`
//! and `doctor`.

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;

use crate::{DnsRecord, RecordKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    /// Nothing published at the name.
    Missing,
    /// Something is published, but not what we expect.
    Mismatch {
        found: String,
    },
    /// Recommended record absent — warn, don't fail.
    Skipped,
}

#[derive(Debug)]
pub struct CheckOutcome {
    pub record: DnsRecord,
    pub status: CheckStatus,
}

impl CheckOutcome {
    pub fn is_ok(&self) -> bool {
        matches!(self.status, CheckStatus::Ok)
            || (!self.record.required && matches!(self.status, CheckStatus::Skipped))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("dns: {0}")]
pub struct CheckError(pub String);

pub struct Checker {
    resolver: TokioResolver,
}

impl std::fmt::Debug for Checker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checker").finish_non_exhaustive()
    }
}

impl Checker {
    pub fn new() -> Result<Self, CheckError> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|err| CheckError(err.to_string()))?
            .build()
            .map_err(|err| CheckError(err.to_string()))?;
        Ok(Self { resolver })
    }

    /// Check every record, returning one outcome per record.
    pub async fn check_all(&self, records: &[DnsRecord]) -> Vec<CheckOutcome> {
        let mut outcomes = Vec::with_capacity(records.len());
        for record in records {
            let status = self.check(record).await;
            outcomes.push(CheckOutcome {
                record: record.clone(),
                status,
            });
        }
        outcomes
    }

    pub async fn check(&self, record: &DnsRecord) -> CheckStatus {
        match record.rtype {
            RecordKind::A => match self.resolver.lookup_ip(record.name.as_str()).await {
                Ok(lookup) => {
                    let ips: Vec<IpAddr> = lookup.iter().collect();
                    if ips.is_empty() {
                        CheckStatus::Missing
                    } else {
                        CheckStatus::Ok
                    }
                }
                Err(_) => CheckStatus::Missing,
            },
            RecordKind::Mx => match self.resolver.mx_lookup(record.name.as_str()).await {
                Ok(lookup) => {
                    let found: Vec<String> = lookup
                        .answers()
                        .iter()
                        .filter_map(|r| match &r.data {
                            RData::MX(mx) => {
                                Some(format!("{} {}", mx.preference, mx.exchange.to_utf8()))
                            }
                            _ => None,
                        })
                        .collect();
                    if found.is_empty() {
                        CheckStatus::Missing
                    } else if found
                        .iter()
                        .any(|v| normalize(v) == normalize(&record.value))
                    {
                        CheckStatus::Ok
                    } else {
                        CheckStatus::Mismatch {
                            found: found.join(", "),
                        }
                    }
                }
                Err(_) => CheckStatus::Missing,
            },
            RecordKind::Txt => match self.resolver.txt_lookup(record.name.as_str()).await {
                Ok(lookup) => {
                    let found: Vec<String> = lookup
                        .answers()
                        .iter()
                        .filter_map(|r| match &r.data {
                            RData::TXT(txt) => Some(
                                txt.txt_data
                                    .iter()
                                    .map(|part| String::from_utf8_lossy(part).into_owned())
                                    .collect::<String>(),
                            ),
                            _ => None,
                        })
                        .collect();
                    // MTA-STS ids are operator-chosen; match on the prefix.
                    let expected_prefix = if record.value.starts_with("v=STSv1") {
                        "v=STSv1"
                    } else {
                        record.value.as_str()
                    };
                    if found.is_empty() {
                        missing_or_skipped(record)
                    } else if found
                        .iter()
                        .any(|v| normalize(v).starts_with(&normalize(expected_prefix)))
                    {
                        CheckStatus::Ok
                    } else if found.iter().any(|v| relevant_txt(record, v)) {
                        CheckStatus::Mismatch {
                            found: found.join(" | "),
                        }
                    } else {
                        missing_or_skipped(record)
                    }
                }
                Err(_) => missing_or_skipped(record),
            },
        }
    }

    /// FCrDNS as the world sees it: hostname → IPs → PTR → hostname.
    pub async fn check_fcrdns(&self, hostname: &str) -> (bool, String) {
        let Ok(lookup) = self.resolver.lookup_ip(hostname).await else {
            return (false, format!("{hostname} does not resolve"));
        };
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return (false, format!("{hostname} has no A/AAAA records"));
        }
        // Pass if ANY of the host's addresses round-trips; report the first
        // problem otherwise.
        let mut first_problem = None;
        for ip in &ips {
            match self.resolver.reverse_lookup(*ip).await {
                Ok(ptr) => {
                    let names: Vec<String> = ptr
                        .answers()
                        .iter()
                        .filter_map(|r| match &r.data {
                            RData::PTR(name) => {
                                Some(name.to_utf8().trim_end_matches('.').to_owned())
                            }
                            _ => None,
                        })
                        .collect();
                    if names.iter().any(|name| name.eq_ignore_ascii_case(hostname)) {
                        return (true, format!("{ip} ↔ {hostname}"));
                    }
                    first_problem.get_or_insert(format!(
                        "PTR for {ip} is {names:?}, expected {hostname} — set it at your VPS provider"
                    ));
                }
                Err(_) => {
                    first_problem.get_or_insert(format!(
                        "no PTR record for {ip} — set it at your VPS provider"
                    ));
                }
            }
        }
        (
            false,
            first_problem.unwrap_or_else(|| "unreachable".to_owned()),
        )
    }

    /// Can this machine open outbound port 25 at all? Many providers block it.
    pub async fn check_outbound_25(&self) -> (bool, String) {
        // Any well-known MX works; we never send a message, just connect.
        let probe = "gmail-smtp-in.l.google.com:25";
        match tokio::time::timeout(
            Duration::from_secs(8),
            tokio::net::TcpStream::connect(probe),
        )
        .await
        {
            Ok(Ok(_)) => (true, "outbound port 25 reachable".to_owned()),
            Ok(Err(err)) => (
                false,
                format!(
                    "cannot reach {probe}: {err} — your provider may block port 25; configure [delivery] smarthost"
                ),
            ),
            Err(_) => (
                false,
                format!(
                    "timeout connecting to {probe} — your provider likely blocks port 25; configure [delivery] smarthost"
                ),
            ),
        }
    }
}

fn missing_or_skipped(record: &DnsRecord) -> CheckStatus {
    if record.required {
        CheckStatus::Missing
    } else {
        CheckStatus::Skipped
    }
}

/// Is this TXT value the kind this record is about? (A domain's TXT set mixes
/// SPF with site-verification tokens etc.)
fn relevant_txt(record: &DnsRecord, value: &str) -> bool {
    let value = normalize(value);
    for prefix in ["v=spf1", "v=dkim1", "v=dmarc1", "v=tlsrptv1", "v=stsv1"] {
        if normalize(&record.value).starts_with(prefix) {
            return value.starts_with(prefix);
        }
    }
    true
}

fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches('.')
        .to_lowercase()
}
