//! The authorization endpoint and passkey login ceremony.
//!
//! `GET /oidc/authorize` validates the request. Two failures are handled by
//! rendering an error *page* and never redirecting — an unknown `client_id` or a
//! `redirect_uri` that does not exactly match the client's registered set —
//! because redirecting to an unvalidated URI is an open-redirect / token-leak
//! vector. Every other failure (bad `response_type`, missing PKCE, unknown
//! scope) redirects back to the now-trusted `redirect_uri` with an OAuth error.
//!
//! On success the request is parked and a login page is served. The page drives
//! `POST /oidc/authorize/login/start` + `/finish` (a WebAuthn assertion). A
//! successful login either mints a code straight away (if prior consent already
//! covers the requested scopes) or forwards the browser to the consent page.

use std::str::FromStr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use owney_authn_v2::{PasskeyAuthentication, PublicKeyCredential};
use owney_core::{AccountId, OAuthClientId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiState;
use crate::oidc::SUPPORTED_SCOPES;
use crate::oidc::session::{
    AUTH_REQUEST_TTL, AUTHOK_TTL, AuthRequest, CodeGrant, error_redirect, mint_code, redirect_with,
};

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

fn error_page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorization error</title>\
         <style>body{{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}}\
         .err{{background:#fce8e6;color:#c5221f;padding:1rem;border-radius:4px}}</style></head>\
         <body><h1>Authorization error</h1><p class=\"err\">{}</p></body></html>",
        html_escape(message)
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(body),
    )
        .into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `GET /oidc/authorize`
pub async fn authorize(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    // 1) client_id must name a real, enabled client. Never redirect on failure.
    let Some(client_id_raw) = params.client_id.as_deref() else {
        return error_page(StatusCode::BAD_REQUEST, "missing client_id");
    };
    let Ok(client_id) = OAuthClientId::from_str(client_id_raw) else {
        return error_page(StatusCode::BAD_REQUEST, "invalid client_id");
    };
    let client = match state.storage.oauth_client(client_id).await {
        Ok(Some(client)) if !client.disabled => client,
        Ok(_) => return error_page(StatusCode::BAD_REQUEST, "unknown or disabled client"),
        Err(err) => {
            tracing::error!(%err, "authorize: client lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 2) redirect_uri must exactly match a registered URI. Never redirect.
    let Some(redirect_uri) = params.redirect_uri.as_deref() else {
        return error_page(StatusCode::BAD_REQUEST, "missing redirect_uri");
    };
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return error_page(
            StatusCode::BAD_REQUEST,
            "redirect_uri not registered for this client",
        );
    }
    // From here `redirect_uri` is trusted: failures redirect with an error.
    let state_param = params.state.as_deref();

    // 3) response_type
    if params.response_type.as_deref() != Some("code") {
        return redirect_response(&error_redirect(
            redirect_uri,
            "unsupported_response_type",
            state_param,
        ));
    }

    // 4) PKCE: S256 required.
    let Some(code_challenge) = params.code_challenge.as_deref().filter(|c| !c.is_empty()) else {
        return redirect_response(&error_redirect(
            redirect_uri,
            "invalid_request",
            state_param,
        ));
    };
    if params.code_challenge_method.as_deref() != Some("S256") {
        return redirect_response(&error_redirect(
            redirect_uri,
            "invalid_request",
            state_param,
        ));
    }

    // 5) scopes: subset of supported, must include openid.
    let scopes: Vec<String> = params
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if scopes.is_empty()
        || !scopes
            .iter()
            .all(|s| SUPPORTED_SCOPES.contains(&s.as_str()))
        || !scopes.iter().any(|s| s == super::SCOPE_OPENID)
    {
        return redirect_response(&error_redirect(redirect_uri, "invalid_scope", state_param));
    }

    // Park the validated request; hand its id to the login page.
    let request = AuthRequest {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scopes,
        state: params.state.clone(),
        nonce: params.nonce.clone(),
        code_challenge: code_challenge.to_string(),
    };
    let bytes = match serde_json::to_vec(&request) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(%err, "authorize: request serialization failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let req_id = oidc
        .challenges
        .store_with_ttl(bytes, AUTH_REQUEST_TTL)
        .await;

    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(login_page(&req_id, &client.name)),
    )
        .into_response()
}

fn redirect_response(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// Ceremony state parked between login start and finish, bound to the parked
/// authorization request and the account that the challenge was built for.
#[derive(Debug, Serialize, Deserialize)]
struct LoginCeremony {
    req_id: String,
    account_id: String,
    auth: PasskeyAuthentication,
}

#[derive(Debug, Deserialize)]
pub struct LoginStartRequest {
    req: String,
    email: String,
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// `POST /oidc/authorize/login/start` — build a WebAuthn assertion challenge for
/// the account identified by `email`, scoped to the parked request `req`.
pub async fn login_start(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<LoginStartRequest>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The parked request must still be alive.
    if oidc.challenges.peek(&req.req).await.is_none() {
        return json_error(StatusCode::BAD_REQUEST, "authorization request expired");
    }

    let email = req.email.trim().to_lowercase();
    let account = match state.storage.account_by_email(&email).await {
        Ok(Some(account)) => account,
        _ => return json_error(StatusCode::BAD_REQUEST, "no passkey for that account"),
    };
    let account_key = account.id.to_string();
    let stored = match state
        .storage
        .list_passkeys_for_account(account_key.clone())
        .await
    {
        Ok(creds) if !creds.is_empty() => creds,
        _ => return json_error(StatusCode::BAD_REQUEST, "no passkey for that account"),
    };
    let credentials = match stored
        .iter()
        .map(convert_cred)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(credentials) => credentials,
        Err(response) => return response,
    };

    let auth_opts = match oidc.passkey_manager.start_authentication(&credentials) {
        Ok(opts) => opts,
        Err(err) => {
            tracing::warn!(%err, "login: start_authentication failed");
            return json_error(StatusCode::BAD_REQUEST, "no passkey for that account");
        }
    };
    let ceremony = LoginCeremony {
        req_id: req.req.clone(),
        account_id: account_key,
        auth: auth_opts.state,
    };
    let bytes = match serde_json::to_vec(&ceremony) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(%err, "login: ceremony serialization failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let ceremony_id = oidc
        .challenges
        .store_with_ttl(bytes, AUTH_REQUEST_TTL)
        .await;

    match serde_json::to_value(auth_opts.options) {
        Ok(options) => Json(json!({ "ceremony": ceremony_id, "options": options })).into_response(),
        Err(err) => {
            tracing::error!(%err, "login: options serialization failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginFinishRequest {
    req: String,
    ceremony: String,
    credential: Value,
}

/// `POST /oidc/authorize/login/finish` — verify the assertion, then either mint
/// a code (consent already on file) or forward to consent.
pub async fn login_finish(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<LoginFinishRequest>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    // Consume the ceremony; it is single use.
    let ceremony_bytes = match oidc.challenges.retrieve_challenge(&body.ceremony).await {
        Ok(bytes) => bytes,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "login session expired"),
    };
    let ceremony: LoginCeremony = match serde_json::from_slice(&ceremony_bytes) {
        Ok(ceremony) => ceremony,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "corrupt login session"),
    };
    if ceremony.req_id != body.req {
        return json_error(StatusCode::BAD_REQUEST, "login session mismatch");
    }

    // The parked authorization request must still be alive.
    let request: AuthRequest = match oidc.challenges.peek(&body.req).await {
        Some(bytes) => match serde_json::from_slice(&bytes) {
            Ok(request) => request,
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "corrupt authorization request"),
        },
        None => return json_error(StatusCode::BAD_REQUEST, "authorization request expired"),
    };

    let response: PublicKeyCredential = match serde_json::from_value(body.credential) {
        Ok(response) => response,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid assertion"),
    };

    // Resolve the credential and *verify it belongs to the ceremony's account* —
    // a credential registered to another account must never satisfy this login.
    let cred_id = response.raw_id.as_ref().to_vec();
    let stored = match state.storage.get_passkey_credential(&cred_id).await {
        Ok(Some(cred)) => cred,
        _ => return json_error(StatusCode::BAD_REQUEST, "credential not recognized"),
    };
    if stored.account_id != ceremony.account_id {
        return json_error(
            StatusCode::FORBIDDEN,
            "credential does not belong to this account",
        );
    }

    let mut auth_cred = match convert_cred(&stored) {
        Ok(cred) => cred,
        Err(response) => return response,
    };
    if oidc
        .passkey_manager
        .finish_authentication(&response, &ceremony.auth, &mut auth_cred)
        .is_err()
    {
        return json_error(StatusCode::UNAUTHORIZED, "assertion verification failed");
    }
    if let Err(err) = state
        .storage
        .update_passkey_counter(&cred_id, auth_cred.counter)
        .await
    {
        tracing::error!(%err, "login: counter update failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let account_id = match AccountId::from_str(&ceremony.account_id) {
        Ok(id) => id,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let client_id = match OAuthClientId::from_str(&request.client_id) {
        Ok(id) => id,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Prior consent that already covers every requested scope skips the prompt.
    let already_granted = match state.storage.oauth_grant(account_id, client_id).await {
        Ok(Some(grant)) => request.scopes.iter().all(|s| grant.scopes.contains(s)),
        Ok(None) => false,
        Err(err) => {
            tracing::error!(%err, "login: grant lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if already_granted {
        let grant = CodeGrant {
            account_id: ceremony.account_id,
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            code_challenge: request.code_challenge.clone(),
            nonce: request.nonce.clone(),
            scopes: request.scopes.clone(),
        };
        // Consume the parked request now that we are committing to a code.
        let _ = oidc.challenges.retrieve_challenge(&body.req).await;
        let Ok(code) = mint_code(oidc, &grant).await else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let mut redirect_params = vec![("code", code.as_str())];
        if let Some(state_param) = request.state.as_deref() {
            redirect_params.push(("state", state_param));
        }
        let location = redirect_with(&request.redirect_uri, &redirect_params);
        return Json(json!({ "redirect": location })).into_response();
    }

    // Otherwise record that this browser authenticated, and send it to consent.
    let authok = oidc
        .challenges
        .store_with_ttl(ceremony.account_id.into_bytes(), AUTHOK_TTL)
        .await;
    let location = redirect_with(
        &format!("{}/oidc/consent", oidc.issuer),
        &[("req", body.req.as_str()), ("auth", authok.as_str())],
    );
    Json(json!({ "redirect": location })).into_response()
}

/// Convert a stored passkey row into the authn-v2 domain credential, mapping any
/// deserialization failure to a 500 response.
#[allow(clippy::result_large_err)]
fn convert_cred(
    stored: &owney_storage::PasskeyCredential,
) -> Result<owney_authn_v2::PasskeyCredential, Response> {
    let passkey = owney_authn_v2::PasskeyCredential::passkey_from_bytes(&stored.public_key)
        .map_err(|err| {
            tracing::error!(%err, "login: passkey deserialization failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
    Ok(owney_authn_v2::PasskeyCredential {
        id: owney_authn_v2::CredentialId(stored.id.clone()),
        account_id: stored.account_id.clone(),
        device_name: stored.device_name.clone(),
        passkey,
        counter: stored.counter,
        backup_eligible: stored.backup_eligible,
        backup_state: stored.backup_state,
        created_at: stored.created_at,
        last_used_at: stored.last_used_at,
        disabled: stored.disabled,
    })
}

fn login_page(req_id: &str, client_name: &str) -> String {
    LOGIN_HTML
        .replace("{{REQ_ID}}", &html_escape(req_id))
        .replace("{{CLIENT}}", &html_escape(client_name))
}

const LOGIN_HTML: &str = include_str!("login.html");
