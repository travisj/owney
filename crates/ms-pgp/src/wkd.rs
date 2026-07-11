//! Web Key Directory (draft-koch-openpgp-webkey-service): the `hu` hash that
//! maps a local part to its well-known URL, so `gpg --locate-keys` and
//! Thunderbird can find our users' keys.

use sequoia_openpgp::types::HashAlgorithm;

use crate::PgpError;

/// z-base-32 alphabet (RFC 6189 / Tahoe).
const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// The WKD "hashed user" component: zbase32(SHA1(lowercase(local_part))).
pub fn hu(local_part: &str) -> Result<String, PgpError> {
    let mut context = HashAlgorithm::SHA1
        .context()
        .map_err(PgpError::from)?
        .for_digest();
    context.update(local_part.to_lowercase().as_bytes());
    let digest = context.into_digest().map_err(PgpError::from)?;
    Ok(zbase32(&digest))
}

/// The direct-method WKD path for an address, rooted at the mail domain:
/// `/.well-known/openpgpkey/hu/<hash>?l=<local>`.
pub fn direct_path(email: &str) -> Result<(String, String), PgpError> {
    let (local, _domain) = email
        .rsplit_once('@')
        .ok_or_else(|| PgpError::OpenPgp(format!("{email} has no domain")))?;
    Ok((
        format!("/.well-known/openpgpkey/hu/{}", hu(local)?),
        local.to_owned(),
    ))
}

fn zbase32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ZBASE32[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_from_the_wkd_draft() {
        // draft-koch-openpgp-webkey-service: "Joe.Doe@Example.ORG" maps to
        // hu of "iy9q119eutrkn8s1mk4r39qejnbu3n5q".
        assert_eq!(
            hu("Joe.Doe").expect("hash"),
            "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
        );
    }

    #[test]
    fn direct_path_shape() {
        let (path, local) = direct_path("Alice@example.com").expect("path");
        assert!(path.starts_with("/.well-known/openpgpkey/hu/"), "{path}");
        assert_eq!(local, "Alice");
    }
}
