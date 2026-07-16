//! OpenID Connect provider: discovery, JWKS, authorization-code + PKCE flow,
//! token/refresh/revoke/userinfo, and the RS256 ID-token signing key.
//!
//! The entire surface is gated behind [`owney_core::config::OidcConfig::enabled`]
//! (default off). It is only constructed — and its routes only merged — when a
//! signing key and [`OidcState`] exist, so a server with OIDC disabled exposes
//! none of these endpoints at all.

pub mod authorize;
pub mod consent;
pub mod discovery;
pub mod enroll;
pub mod keys;
mod session;
pub mod token;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod flow_tests;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use owney_authn_v2::{PasskeyManager, PasswordlessAuthConfig};
use owney_core::config::OidcConfig;

use crate::ApiState;
use crate::challenge_store::ChallengeStore;
pub use keys::{IdTokenClaims, OidcSigningKey};

/// OIDC standard scope: required; asserts an authentication.
pub const SCOPE_OPENID: &str = "openid";
/// OIDC standard scope: releases the `email`/`email_verified` claims.
pub const SCOPE_EMAIL: &str = "email";
/// OIDC standard scope: releases the `name` claim.
pub const SCOPE_PROFILE: &str = "profile";
/// OIDC standard scope: mints a rotating refresh token.
pub const SCOPE_OFFLINE: &str = "offline_access";
/// Owney API scope: the access token may call the JMAP mail/data endpoints.
pub const SCOPE_MAIL: &str = "owney:mail";
/// Owney API scope: the access token may call the MCP endpoint.
pub const SCOPE_MCP: &str = "owney:mcp";

/// Every scope this provider recognises. A client may only request from this set
/// (unknown scopes are rejected at `/authorize`), and consent is shown per scope.
pub const SUPPORTED_SCOPES: &[&str] = &[
    SCOPE_OPENID,
    SCOPE_EMAIL,
    SCOPE_PROFILE,
    SCOPE_OFFLINE,
    SCOPE_MAIL,
    SCOPE_MCP,
];

/// Everything the OIDC endpoints need beyond [`ApiState`]'s storage: the signing
/// key, the WebAuthn relying-party manager (shared by enrollment and login), a
/// short-lived challenge store for ceremony state and authorization codes, and
/// the issuer identity / TTL policy.
pub struct OidcState {
    pub config: OidcConfig,
    /// Issuer URL — our public base URL, e.g. `https://mail.example.com`.
    pub issuer: String,
    pub signing_key: OidcSigningKey,
    pub passkey_manager: PasskeyManager,
    pub challenges: ChallengeStore,
}

impl std::fmt::Debug for OidcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcState")
            .field("issuer", &self.issuer)
            .field("kid", &self.signing_key.kid())
            .finish_non_exhaustive()
    }
}

impl OidcState {
    /// Build OIDC state for `issuer` (our public base URL). The WebAuthn
    /// relying-party id is the issuer host; the sole allowed origin is the
    /// issuer itself, so passkeys are bound to the login page's origin.
    pub fn new(
        config: OidcConfig,
        issuer: String,
        signing_key: OidcSigningKey,
    ) -> anyhow::Result<Self> {
        let rp_id = issuer_host(&issuer)
            .ok_or_else(|| anyhow::anyhow!("OIDC issuer is not a valid URL: {issuer}"))?;
        let auth_config = PasswordlessAuthConfig::new(rp_id, vec![issuer.clone()]);
        let passkey_manager = PasskeyManager::new(auth_config)
            .map_err(|err| anyhow::anyhow!("build passkey manager: {err}"))?;
        Ok(Self {
            config,
            issuer,
            signing_key,
            passkey_manager,
            challenges: ChallengeStore::new(),
        })
    }

    /// Spawn a background task that evicts expired ceremony state and codes.
    /// Runs on the current Tokio runtime; returns the join handle.
    pub fn spawn_sweeper(state: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                state.challenges.cleanup_expired().await;
            }
        })
    }
}

/// The registrable host of the issuer URL, used as the WebAuthn RP id.
fn issuer_host(issuer: &str) -> Option<String> {
    let rest = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))?;
    let host = rest.split('/').next()?.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// OIDC routes, merged into the main router only when `enabled`. Every handler
/// additionally re-checks `state.oidc` and 404s if OIDC is off, so a stale
/// mount can never expose the provider.
pub fn routes(enabled: bool) -> Router<Arc<ApiState>> {
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/oidc/jwks.json", get(discovery::jwks))
        .route("/oidc/enroll", get(enroll::enroll_page))
        .route("/oidc/enroll/start", post(enroll::enroll_start))
        .route("/oidc/enroll/finish", post(enroll::enroll_finish))
        .route("/oidc/authorize", get(authorize::authorize))
        .route("/oidc/authorize/login/start", post(authorize::login_start))
        .route(
            "/oidc/authorize/login/finish",
            post(authorize::login_finish),
        )
        .route(
            "/oidc/consent",
            get(consent::consent_page).post(consent::consent_submit),
        )
        .route("/oidc/token", post(token::token))
        .route("/oidc/revoke", post(token::revoke))
        .route("/oidc/userinfo", get(token::userinfo).post(token::userinfo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_host_extraction() {
        assert_eq!(
            issuer_host("https://mail.example.com"),
            Some("mail.example.com".to_string())
        );
        assert_eq!(
            issuer_host("https://mail.example.com:8443/"),
            Some("mail.example.com".to_string())
        );
        assert_eq!(
            issuer_host("http://alice.local:8381"),
            Some("alice.local".to_string())
        );
        assert_eq!(issuer_host("not-a-url"), None);
    }
}
