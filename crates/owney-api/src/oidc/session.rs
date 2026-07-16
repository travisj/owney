//! Shared state for the authorization-code flow: the parked authorization
//! request, the minted-code payload, and helpers to build redirects.
//!
//! Both live in the in-memory OIDC challenge store. The authorization request is
//! peeked across several requests (login, consent) and consumed only when a code
//! is minted or the flow is abandoned; the code payload is consumed once at the
//! token endpoint.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::oidc::OidcState;

/// Authorization codes are prefixed so the token endpoint can reject anything
/// that plainly is not one of ours before touching the store.
pub(super) const CODE_PREFIX: &str = "moc_";

/// How long a parked `/authorize` request survives (login + consent must finish
/// within this window).
pub(super) const AUTH_REQUEST_TTL: Duration = Duration::from_secs(600);
/// How long the post-login "this browser authenticated as X" marker lives.
pub(super) const AUTHOK_TTL: Duration = Duration::from_secs(300);
/// Authorization-code lifetime (single use; kept short per RFC 6749 §4.1.2).
pub(super) const CODE_TTL: Duration = Duration::from_secs(60);

/// A validated `/authorize` request, parked while the user logs in and consents.
/// `redirect_uri` has already been checked against the client's registered set,
/// so it is safe to redirect to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    /// PKCE S256 challenge (raw base64url string as sent by the client).
    pub code_challenge: String,
}

/// The payload an authorization code stands for, verified and exchanged for
/// tokens at `/oidc/token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CodeGrant {
    pub account_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub scopes: Vec<String>,
}

/// Mint a single-use authorization code for `grant`, storing it under itself in
/// the challenge store. Returns the opaque code string.
pub(super) async fn mint_code(oidc: &OidcState, grant: &CodeGrant) -> Result<String, ()> {
    let bytes = serde_json::to_vec(grant).map_err(|_| ())?;
    let raw: [u8; 32] = {
        use rand::Rng;
        rand::thread_rng().r#gen()
    };
    let code = format!("{CODE_PREFIX}{}", hex_lower(&raw));
    oidc.challenges
        .store_keyed(code.clone(), bytes, CODE_TTL)
        .await;
    Ok(code)
}

/// Consume an authorization code, returning its grant if the code is live.
pub(super) async fn take_code(oidc: &OidcState, code: &str) -> Option<CodeGrant> {
    if !code.starts_with(CODE_PREFIX) {
        return None;
    }
    let bytes = oidc.challenges.retrieve_challenge(code).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Append query parameters to a redirect URI, honoring any it already carries.
pub(super) fn redirect_with(base: &str, params: &[(&str, &str)]) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}{sep}{query}")
}

/// Redirect back to the client with an OAuth error, echoing `state` if present.
pub(super) fn error_redirect(redirect_uri: &str, error: &str, state: Option<&str>) -> String {
    let mut params = vec![("error", error)];
    if let Some(state) = state {
        params.push(("state", state));
    }
    redirect_with(redirect_uri, &params)
}

/// Verify a PKCE code verifier against a stored S256 challenge (RFC 7636 §4.6):
/// `challenge == base64url(sha256(verifier))`.
pub(super) fn verify_pkce_s256(challenge: &str, verifier: &str) -> bool {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    computed == challenge
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_appends_query_correctly() {
        assert_eq!(
            redirect_with(
                "https://app.example/cb",
                &[("code", "abc"), ("state", "x y")]
            ),
            "https://app.example/cb?code=abc&state=x%20y"
        );
        assert_eq!(
            redirect_with("https://app.example/cb?foo=1", &[("code", "abc")]),
            "https://app.example/cb?foo=1&code=abc"
        );
    }

    #[test]
    fn error_redirect_echoes_state() {
        assert_eq!(
            error_redirect("https://app/cb", "access_denied", Some("s1")),
            "https://app/cb?error=access_denied&state=s1"
        );
        assert_eq!(
            error_redirect("https://app/cb", "invalid_scope", None),
            "https://app/cb?error=invalid_scope"
        );
    }

    #[test]
    fn pkce_s256_matches_rfc7636_example() {
        // RFC 7636 Appendix B vectors.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce_s256(challenge, verifier));
        assert!(!verify_pkce_s256(challenge, "wrong-verifier"));
    }
}
