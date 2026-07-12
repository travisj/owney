//! Autocrypt (Level 1): in-band key distribution. Every outbound message
//! carries the sender's public key; every inbound message's header is
//! harvested into the peer table. This is what makes encryption happen with
//! zero user key management.

use base64::Engine;
use sequoia_openpgp as openpgp;

use openpgp::Cert;
use openpgp::parse::Parse;

use crate::{PgpError, public_der};

/// The `Autocrypt:` header value for an outbound message.
pub fn header(email: &str, cert: &Cert, prefer_encrypt_mutual: bool) -> Result<String, PgpError> {
    let keydata = base64::engine::general_purpose::STANDARD.encode(public_der(cert)?);
    let prefer = if prefer_encrypt_mutual {
        "prefer-encrypt=mutual; "
    } else {
        ""
    };
    Ok(format!("addr={email}; {prefer}keydata={keydata}"))
}

/// A parsed inbound Autocrypt header.
#[derive(Debug)]
pub struct ParsedHeader {
    pub addr: String,
    pub prefer_encrypt: Option<String>,
    pub cert: Cert,
}

/// Parse an `Autocrypt:` header value (whitespace-tolerant, per spec).
pub fn parse_header(value: &str) -> Result<ParsedHeader, PgpError> {
    let mut addr = None;
    let mut prefer_encrypt = None;
    let mut keydata = None;

    for attribute in value.split(';') {
        let Some((key, val)) = attribute.split_once('=') else {
            continue;
        };
        match key.trim() {
            "addr" => addr = Some(val.trim().to_lowercase()),
            "prefer-encrypt" => prefer_encrypt = Some(val.trim().to_owned()),
            "keydata" => {
                let compact: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                keydata = Some(compact);
            }
            // Unknown non-critical attributes are ignored; critical unknown
            // attributes (no leading underscore) invalidate the header.
            other if !other.starts_with('_') && !other.is_empty() => {
                return Err(PgpError::OpenPgp(format!(
                    "unknown critical autocrypt attribute {other}"
                )));
            }
            _ => {}
        }
    }

    let addr = addr.ok_or_else(|| PgpError::OpenPgp("autocrypt: no addr".into()))?;
    let keydata = keydata.ok_or_else(|| PgpError::OpenPgp("autocrypt: no keydata".into()))?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&keydata)
        .map_err(|err| PgpError::OpenPgp(format!("autocrypt keydata: {err}")))?;
    let cert = Cert::from_bytes(&der).map_err(PgpError::from)?;
    Ok(ParsedHeader {
        addr,
        prefer_encrypt,
        cert,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_cert;

    #[test]
    fn header_round_trips() {
        let cert = generate_cert("alice@example.com", Some("Alice")).expect("cert");
        let value = header("alice@example.com", &cert, true).expect("header");
        assert!(value.starts_with("addr=alice@example.com; prefer-encrypt=mutual; keydata="));

        let parsed = parse_header(&value).expect("parse");
        assert_eq!(parsed.addr, "alice@example.com");
        assert_eq!(parsed.prefer_encrypt.as_deref(), Some("mutual"));
        assert_eq!(parsed.cert.fingerprint(), cert.fingerprint());
        assert!(!parsed.cert.is_tsk(), "public material only");
    }

    #[test]
    fn folded_keydata_parses() {
        let cert = generate_cert("bob@example.com", None).expect("cert");
        let value = header("bob@example.com", &cert, false).expect("header");
        // Simulate header folding: whitespace inside keydata.
        let folded = value
            .replace("keydata=", "keydata= ")
            .replace("AAA", "AA\r\n\tA");
        let parsed = parse_header(&folded).expect("parse folded");
        assert_eq!(parsed.cert.fingerprint(), cert.fingerprint());
    }
}
