//! OIDC discovery document and JWKS endpoint. Both are public (no auth): they
//! publish only the issuer metadata and the RS256 public key relying parties
//! need to verify ID tokens.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::ApiState;
use crate::oidc::SUPPORTED_SCOPES;

/// `GET /.well-known/openid-configuration` — the provider metadata document
/// (OpenID Connect Discovery 1.0 §3).
pub async fn openid_configuration(State(state): State<Arc<ApiState>>) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let issuer = &oidc.issuer;
    let doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oidc/authorize"),
        "token_endpoint": format!("{issuer}/oidc/token"),
        "userinfo_endpoint": format!("{issuer}/oidc/userinfo"),
        "revocation_endpoint": format!("{issuer}/oidc/revoke"),
        "jwks_uri": format!("{issuer}/oidc/jwks.json"),
        "scopes_supported": SUPPORTED_SCOPES,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post", "client_secret_basic", "none"
        ],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
            "email", "email_verified", "name"
        ],
    });
    Json(doc).into_response()
}

/// `GET /oidc/jwks.json` — the signing key set. Relying parties fetch this to
/// verify ID token signatures; it contains only public key material.
pub async fn jwks(State(state): State<Arc<ApiState>>) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let jwks: Value = oidc.signing_key.jwks();
    Json(jwks).into_response()
}
