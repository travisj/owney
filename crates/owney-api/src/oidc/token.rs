//! The token, revocation, and userinfo endpoints.
//!
//! `POST /oidc/token` handles both `authorization_code` (with PKCE) and
//! `refresh_token` grants. Refresh tokens rotate on every use; presenting an
//! already-used refresh token is treated as theft and revokes the whole family
//! (RFC 6819 §5.2.2.3). `POST /oidc/revoke` implements RFC 7009. `GET/POST
//! /oidc/userinfo` returns claims for the bearer's granted scopes.

use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, response::Json as JsonResponse};
use base64::Engine;
use owney_core::{AccountId, OAuthClientId};
use owney_storage::{OAuthClient, TokenAccess};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiState;
use crate::oidc::session::{take_code, verify_pkce_s256};
use crate::oidc::{IdTokenClaims, OidcState};

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: Option<String>,
    // authorization_code
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    // refresh_token
    refresh_token: Option<String>,
    scope: Option<String>,
    // client authentication (client_secret_post); Basic is also accepted.
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// An OAuth 2.0 error response (RFC 6749 §5.2). `invalid_client` is 401 with a
/// `WWW-Authenticate` challenge; everything else is 400.
fn oauth_error(code: &str) -> Response {
    let status = if code == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
    let mut response = (status, Json(json!({ "error": code }))).into_response();
    if code == "invalid_client" {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Basic"),
        );
    }
    response
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = raw.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// Resolve and authenticate the client from the Basic header or the form body.
/// Public clients need no secret (PKCE is the proof); confidential clients must
/// present the correct secret.
async fn authenticate_client(
    state: &ApiState,
    headers: &HeaderMap,
    form: &TokenForm,
) -> Result<OAuthClient, Response> {
    let (client_id_raw, secret) = match parse_basic_auth(headers) {
        Some((id, secret)) => (id, Some(secret)),
        None => match form.client_id.clone() {
            Some(id) => (id, form.client_secret.clone()),
            None => return Err(oauth_error("invalid_client")),
        },
    };
    let client_id =
        OAuthClientId::from_str(&client_id_raw).map_err(|_| oauth_error("invalid_client"))?;
    let client = match state.storage.oauth_client(client_id).await {
        Ok(Some(client)) if !client.disabled => client,
        Ok(_) => return Err(oauth_error("invalid_client")),
        Err(err) => {
            tracing::error!(%err, "token: client lookup failed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };
    if client.public {
        return Ok(client);
    }
    let Some(secret) = secret else {
        return Err(oauth_error("invalid_client"));
    };
    match state
        .storage
        .verify_oauth_client_secret(client_id, &secret)
        .await
    {
        Ok(true) => Ok(client),
        Ok(false) => Err(oauth_error("invalid_client")),
        Err(err) => {
            tracing::error!(%err, "token: secret verify failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// `POST /oidc/token`
pub async fn token(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    if state.oidc.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let client = match authenticate_client(&state, &headers, &form).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    match form.grant_type.as_deref() {
        Some("authorization_code") => code_grant(&state, &client, &form).await,
        Some("refresh_token") => refresh_grant(&state, &client, &form).await,
        _ => oauth_error("unsupported_grant_type"),
    }
}

async fn code_grant(state: &ApiState, client: &OAuthClient, form: &TokenForm) -> Response {
    let oidc = state.oidc.as_ref().expect("oidc present");
    let Some(code) = form.code.as_deref() else {
        return oauth_error("invalid_request");
    };
    let Some(verifier) = form.code_verifier.as_deref() else {
        return oauth_error("invalid_request");
    };
    let Some(grant) = take_code(oidc, code).await else {
        return oauth_error("invalid_grant");
    };

    // The code is bound to the client, redirect_uri, and PKCE challenge.
    if grant.client_id != client.id.to_string() {
        return oauth_error("invalid_grant");
    }
    if form.redirect_uri.as_deref() != Some(grant.redirect_uri.as_str()) {
        return oauth_error("invalid_grant");
    }
    if !verify_pkce_s256(&grant.code_challenge, verifier) {
        return oauth_error("invalid_grant");
    }

    let Ok(account_id) = AccountId::from_str(&grant.account_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    issue_tokens(
        state,
        oidc,
        account_id,
        client.id,
        &grant.scopes,
        grant.nonce.as_deref(),
        None,
    )
    .await
}

async fn refresh_grant(state: &ApiState, client: &OAuthClient, form: &TokenForm) -> Response {
    let oidc = state.oidc.as_ref().expect("oidc present");
    let Some(token) = form.refresh_token.as_deref() else {
        return oauth_error("invalid_request");
    };
    let row = match state.storage.refresh_token_by_plaintext(token).await {
        Ok(Some(row)) => row,
        Ok(None) => return oauth_error("invalid_grant"),
        Err(err) => {
            tracing::error!(%err, "token: refresh lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if row.client_id != client.id {
        return oauth_error("invalid_grant");
    }

    // Reuse detection: a token already rotated is a theft signal — burn the
    // family so neither the thief's nor the victim's line survives.
    if row.used_at.is_some() {
        tracing::warn!(family = %row.family_id, "refresh token reuse — revoking family");
        let _ = state.storage.revoke_refresh_family(&row.family_id).await;
        return oauth_error("invalid_grant");
    }
    if row.revoked_at.is_some() || row.expires_at <= now() {
        return oauth_error("invalid_grant");
    }

    // Optional down-scoping; the request may only narrow, never widen.
    let scopes = match form.scope.as_deref() {
        Some(requested) => {
            let requested: Vec<String> = requested.split_whitespace().map(str::to_owned).collect();
            if !requested.iter().all(|s| row.scopes.contains(s)) {
                return oauth_error("invalid_scope");
            }
            requested
        }
        None => row.scopes.clone(),
    };

    issue_tokens(
        state,
        oidc,
        row.account_id,
        client.id,
        &scopes,
        None,
        Some(row.token_hash.clone()),
    )
    .await
}

/// Mint an access token (+ optional ID and refresh tokens) for a granted scope
/// set. `rotate_from` is the old refresh-token hash when this is a refresh.
async fn issue_tokens(
    state: &ApiState,
    oidc: &OidcState,
    account_id: AccountId,
    client_id: OAuthClientId,
    scopes: &[String],
    nonce: Option<&str>,
    rotate_from: Option<String>,
) -> Response {
    let account = match state.storage.account(account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => return oauth_error("invalid_grant"),
        Err(err) => {
            tracing::error!(%err, "token: account lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let access_ttl = oidc.config.access_token_ttl_secs as i64;
    let access_expires = now() + access_ttl;
    let (access_token, access_hash) = match state
        .storage
        .create_scoped_token(account_id, "oidc access", scopes, access_expires, client_id)
        .await
    {
        Ok(pair) => pair,
        Err(err) => {
            tracing::error!(%err, "token: access mint failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": access_ttl,
        "scope": scopes.join(" "),
    });

    // ID token when the `openid` scope is present.
    if scopes.iter().any(|s| s == super::SCOPE_OPENID) {
        let issued = now();
        let claims = IdTokenClaims {
            iss: oidc.issuer.clone(),
            sub: account_id.to_string(),
            aud: client_id.to_string(),
            exp: issued + oidc.config.id_token_ttl_secs as i64,
            iat: issued,
            auth_time: Some(issued),
            nonce: nonce.map(str::to_owned),
            email: scopes
                .iter()
                .any(|s| s == super::SCOPE_EMAIL)
                .then(|| account.email.clone()),
            email_verified: scopes
                .iter()
                .any(|s| s == super::SCOPE_EMAIL)
                .then_some(true),
            name: scopes
                .iter()
                .any(|s| s == super::SCOPE_PROFILE)
                .then(|| account.display_name.clone())
                .flatten(),
        };
        match oidc.signing_key.sign(&claims) {
            Ok(id_token) => {
                body["id_token"] = json!(id_token);
            }
            Err(err) => {
                tracing::error!(%err, "token: id_token sign failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    // Refresh token when `offline_access` is present.
    if scopes.iter().any(|s| s == super::SCOPE_OFFLINE) {
        let refresh_expires = now() + oidc.config.refresh_token_ttl_secs as i64;
        let refresh = match rotate_from {
            Some(old_hash) => {
                state
                    .storage
                    .rotate_refresh_token(&old_hash, Some(access_hash.clone()), refresh_expires)
                    .await
            }
            None => {
                state
                    .storage
                    .create_refresh_token(
                        account_id,
                        client_id,
                        scopes,
                        None,
                        Some(access_hash.clone()),
                        refresh_expires,
                    )
                    .await
            }
        };
        match refresh {
            Ok(refresh_token) => {
                body["refresh_token"] = json!(refresh_token);
            }
            Err(err) => {
                tracing::error!(%err, "token: refresh mint failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else if let Some(old_hash) = rotate_from {
        // A refresh grant whose new scope set dropped offline_access: retire the
        // presented token without a successor rather than leaving it live.
        let _ = state.storage.revoke_token_by_hash(&old_hash).await;
    }

    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        JsonResponse(body),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    token: Option<String>,
    #[allow(dead_code)]
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// `POST /oidc/revoke` (RFC 7009). Always returns 200 for a well-formed request,
/// even if the token is unknown, so callers cannot probe token validity.
pub async fn revoke(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    if state.oidc.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Reuse the token-endpoint client authentication.
    let token_form = TokenForm {
        grant_type: None,
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
        client_id: form.client_id.clone(),
        client_secret: form.client_secret.clone(),
    };
    let client = match authenticate_client(&state, &headers, &token_form).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    let Some(token) = form.token.as_deref() else {
        return StatusCode::OK.into_response();
    };

    if token.starts_with("mrt_") {
        // Only revoke a refresh family the caller actually owns.
        if let Ok(Some(row)) = state.storage.refresh_token_by_plaintext(token).await
            && row.client_id == client.id
        {
            let _ = state.storage.revoke_refresh_family(&row.family_id).await;
        }
    } else if token.starts_with("msk_") {
        let hash = blake3::hash(token.as_bytes()).to_hex().to_string();
        let _ = state.storage.revoke_token_by_hash(&hash).await;
    }
    StatusCode::OK.into_response()
}

/// `GET`/`POST /oidc/userinfo` — claims for the presented access token. Requires
/// the `openid` scope; releases `email`/`name` per the token's granted scopes.
pub async fn userinfo(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    if state.oidc.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response()
    };
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return unauthorized();
    };

    let (account, access) = match state.storage.account_and_access_by_token(token).await {
        Ok(Some(pair)) => pair,
        Ok(None) => return unauthorized(),
        Err(err) => {
            tracing::error!(%err, "userinfo: token lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let has = |scope: &str| match &access {
        TokenAccess::Full => true,
        TokenAccess::Scoped(scopes) => scopes.iter().any(|s| s == scope),
    };
    if !has(super::SCOPE_OPENID) {
        return (
            StatusCode::FORBIDDEN,
            [(
                header::WWW_AUTHENTICATE,
                "Bearer error=\"insufficient_scope\", scope=\"openid\"",
            )],
        )
            .into_response();
    }

    let mut claims: Value = json!({ "sub": account.id.to_string() });
    if has(super::SCOPE_EMAIL) {
        claims["email"] = json!(account.email);
        claims["email_verified"] = json!(true);
    }
    if has(super::SCOPE_PROFILE)
        && let Some(name) = account.display_name.as_ref()
    {
        claims["name"] = json!(name);
    }
    Json(claims).into_response()
}
