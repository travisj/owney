//! Self-hosting onboarding: the DNS records a domain needs, and checks that
//! they are actually published. Mail-in-a-Box's lesson: self-hosted mail fails
//! at the operational layer, so the server itself must know what correct DNS
//! looks like and say exactly what is missing.

pub mod check;

use std::fmt;

/// One DNS record the operator must publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: RecordKind,
    pub value: String,
    /// Why this record matters, shown in `setup` output.
    pub purpose: &'static str,
    /// Required for correct operation, or recommended hardening.
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Mx,
    Txt,
    A,
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RecordKind::Mx => "MX",
            RecordKind::Txt => "TXT",
            RecordKind::A => "A/AAAA",
        })
    }
}

impl DnsRecord {
    /// Zone-file style line for display.
    pub fn zone_line(&self) -> String {
        match self.rtype {
            RecordKind::Mx => format!("{}. IN MX {}", self.name, self.value),
            RecordKind::Txt => format!("{}. IN TXT \"{}\"", self.name, self.value),
            RecordKind::A => format!("{}. IN A <this server's public IP>", self.name),
        }
    }
}

/// Everything a fresh domain must publish. `dkim_record` comes from
/// `DkimKeys::dns_record()` (ms-delivery owns key material).
pub fn expected_records(
    domain: &str,
    hostname: &str,
    dkim_record: (String, String),
) -> Vec<DnsRecord> {
    let (dkim_name, dkim_value) = dkim_record;
    vec![
        DnsRecord {
            name: hostname.to_owned(),
            rtype: RecordKind::A,
            value: String::new(),
            purpose: "points your mail host at this server",
            required: true,
        },
        DnsRecord {
            name: domain.to_owned(),
            rtype: RecordKind::Mx,
            value: format!("10 {hostname}."),
            purpose: "tells the world where mail for your domain goes",
            required: true,
        },
        DnsRecord {
            name: domain.to_owned(),
            rtype: RecordKind::Txt,
            value: "v=spf1 mx -all".to_owned(),
            purpose: "SPF: authorizes your MX to send for the domain",
            required: true,
        },
        DnsRecord {
            name: dkim_name,
            rtype: RecordKind::Txt,
            value: dkim_value,
            purpose: "DKIM: lets receivers verify your signatures",
            required: true,
        },
        DnsRecord {
            name: format!("_dmarc.{domain}"),
            rtype: RecordKind::Txt,
            value: format!("v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"),
            purpose: "DMARC: policy + aggregate reports (required by Gmail/Outlook)",
            required: true,
        },
        DnsRecord {
            name: format!("_smtp._tls.{domain}"),
            rtype: RecordKind::Txt,
            value: format!("v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"),
            purpose: "TLS-RPT: providers report TLS delivery problems to you",
            required: false,
        },
        DnsRecord {
            name: format!("_mta-sts.{domain}"),
            rtype: RecordKind::Txt,
            value: format!("v=STSv1; id={domain}1"),
            purpose: "MTA-STS: senders must use TLS (policy file served from M3)",
            required: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<DnsRecord> {
        expected_records(
            "example.com",
            "mail.example.com",
            (
                "ms1._domainkey.example.com".to_owned(),
                "v=DKIM1; k=rsa; p=AAAA".to_owned(),
            ),
        )
    }

    #[test]
    fn full_record_set() {
        let records = records();
        assert_eq!(records.len(), 7);
        assert!(
            records
                .iter()
                .any(|r| r.rtype == RecordKind::Mx && r.value == "10 mail.example.com.")
        );
        assert!(records.iter().any(|r| r.value == "v=spf1 mx -all"));
        assert!(
            records
                .iter()
                .any(|r| r.name == "_dmarc.example.com" && r.value.contains("p=quarantine"))
        );
        assert!(
            records
                .iter()
                .any(|r| r.name == "ms1._domainkey.example.com")
        );
        assert_eq!(records.iter().filter(|r| r.required).count(), 5);
    }

    #[test]
    fn zone_lines_render() {
        let records = records();
        let mx = records
            .iter()
            .find(|r| r.rtype == RecordKind::Mx)
            .expect("mx");
        assert_eq!(mx.zone_line(), "example.com. IN MX 10 mail.example.com.");
        let spf = records
            .iter()
            .find(|r| r.value.starts_with("v=spf1"))
            .expect("spf");
        assert_eq!(spf.zone_line(), "example.com. IN TXT \"v=spf1 mx -all\"");
    }
}
