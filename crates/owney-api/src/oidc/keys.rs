//! OIDC signing key: an RSA-2048 key used to sign ID tokens with RS256.
//!
//! Generated on first use and persisted under `<data_dir>/oidc/`, mirroring
//! the DKIM key lifecycle (see `owney-delivery`). The private half is stored as
//! PKCS#1 DER — the form `jsonwebtoken`'s `EncodingKey::from_rsa_der` expects
//! under the `rust_crypto` backend. The `kid` is derived from the public key,
//! so a rotated key automatically gets a distinct JWKS entry.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::EncodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};

/// A loaded RSA signing key, ready to mint and publish RS256 ID tokens.
pub struct OidcSigningKey {
    kid: String,
    encoding_key: EncodingKey,
    /// Base64url (no pad) modulus and exponent, for the JWKS document.
    jwk_n: String,
    jwk_e: String,
}

impl std::fmt::Debug for OidcSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcSigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl OidcSigningKey {
    /// Load the instance's RS256 signing key from `<data_dir>/oidc/`, generating
    /// and persisting one on first use.
    pub fn load_or_generate(data_dir: &Path) -> anyhow::Result<Self> {
        let dir = data_dir.join("oidc");
        std::fs::create_dir_all(&dir)?;

        // A key file is named `rs256-<kid>.pkcs1.der`. At most one should exist;
        // load the first we find, otherwise generate.
        let existing = std::fs::read_dir(&dir)?.filter_map(|e| e.ok()).find(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("rs256-") && name.ends_with(".pkcs1.der")
        });

        let private_der = if let Some(entry) = existing {
            std::fs::read(entry.path())?
        } else {
            let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
                .map_err(|err| anyhow::anyhow!("generate RSA key: {err}"))?;
            let der = key
                .to_pkcs1_der()
                .map_err(|err| anyhow::anyhow!("encode RSA key: {err}"))?
                .as_bytes()
                .to_vec();
            let kid = derive_kid(&key)?;
            let path = dir.join(format!("rs256-{kid}.pkcs1.der"));
            write_restricted(&path, &der)?;
            tracing::info!(kid, "generated OIDC RS256 signing key");
            der
        };

        Self::from_pkcs1_der(&private_der)
    }

    /// Build a signing key from raw PKCS#1 DER (also the reload path).
    pub fn from_pkcs1_der(private_der: &[u8]) -> anyhow::Result<Self> {
        let key = RsaPrivateKey::from_pkcs1_der(private_der)
            .map_err(|err| anyhow::anyhow!("decode RSA key: {err}"))?;
        let kid = derive_kid(&key)?;
        let public = key.to_public_key();
        let jwk_n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let jwk_e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());

        Ok(Self {
            kid,
            encoding_key: EncodingKey::from_rsa_der(private_der),
            jwk_n,
            jwk_e,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public JWKS document served at the discovery `jwks_uri`.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.kid,
                "n": self.jwk_n,
                "e": self.jwk_e,
            }]
        })
    }

    /// Sign a set of claims into a compact JWS, stamping our `kid` in the header
    /// so verifiers can select the matching JWKS entry.
    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding_key)
    }
}

/// `kid` = first 16 hex chars of BLAKE3 over the SubjectPublicKeyInfo DER.
/// Stable for a given key, distinct across rotations.
fn derive_kid(key: &RsaPrivateKey) -> anyhow::Result<String> {
    let spki = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|err| anyhow::anyhow!("encode SPKI: {err}"))?;
    let hash = blake3::hash(spki.as_bytes());
    Ok(hash.to_hex()[..16].to_string())
}

fn write_restricted(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)
}

/// Standard OpenID Connect ID token claims (RFC 7519 + OIDC Core §2). Fields
/// that are absent for a given grant are skipped rather than serialized null.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};

    #[test]
    fn generate_persist_reload_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = OidcSigningKey::load_or_generate(dir.path()).expect("generate");
        let second = OidcSigningKey::load_or_generate(dir.path()).expect("reload");
        // Reload must not mint a new key: same kid, same published modulus.
        assert_eq!(first.kid(), second.kid());
        assert_eq!(first.jwks(), second.jwks());
    }

    #[test]
    fn minted_id_token_verifies_against_published_jwks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = OidcSigningKey::load_or_generate(dir.path()).expect("generate");

        let claims = IdTokenClaims {
            iss: "https://mail.example.com".to_string(),
            sub: "11111111-1111-1111-1111-111111111111".to_string(),
            aud: "client-abc".to_string(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            auth_time: Some(1_000_000_000),
            nonce: Some("n-0S6_WzA2Mj".to_string()),
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            name: None,
        };
        let token = key.sign(&claims).expect("sign");

        // A relying party would fetch the JWKS and verify with n/e alone.
        let jwks = key.jwks();
        let jwk = &jwks["keys"][0];
        let n = jwk["n"].as_str().expect("n");
        let e = jwk["e"].as_str().expect("e");
        let decoding = DecodingKey::from_rsa_components(n, e).expect("decoding key");

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["client-abc"]);
        validation.set_issuer(&["https://mail.example.com"]);
        let decoded =
            jsonwebtoken::decode::<IdTokenClaims>(&token, &decoding, &validation).expect("verify");

        assert_eq!(decoded.claims.sub, claims.sub);
        assert_eq!(decoded.claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(decoded.header.kid.as_deref(), Some(key.kid()));

        // Wrong audience must be rejected — proves validation is real.
        let mut bad = Validation::new(Algorithm::RS256);
        bad.set_audience(&["someone-else"]);
        assert!(jsonwebtoken::decode::<IdTokenClaims>(&token, &decoding, &bad).is_err());
    }
}
