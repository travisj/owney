//! The consent screen. Shown after a successful login when prior consent does
//! not already cover the requested scopes. Approving records a grant (scopes are
//! unioned, never narrowed) and mints an authorization code; denying redirects
//! back to the client with `error=access_denied`.

use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use owney_core::{AccountId, OAuthClientId};
use serde::Deserialize;

use crate::ApiState;
use crate::oidc::session::{AuthRequest, CodeGrant, error_redirect, mint_code, redirect_with};

/// Human-readable description for each scope shown on the consent screen.
fn scope_label(scope: &str) -> &'static str {
    match scope {
        super::SCOPE_OPENID => "Confirm your identity",
        super::SCOPE_EMAIL => "See your email address",
        super::SCOPE_PROFILE => "See your display name",
        super::SCOPE_OFFLINE => "Stay signed in (refresh access without re-login)",
        super::SCOPE_MAIL => "Access your mail and calendar data",
        super::SCOPE_MCP => "Use AI tools on your behalf",
        _ => "Unknown permission",
    }
}

#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    req: String,
    auth: String,
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn parked_request(state: &ApiState, req_id: &str) -> Option<AuthRequest> {
    let oidc = state.oidc.as_ref()?;
    let bytes = oidc.challenges.peek(req_id).await?;
    serde_json::from_slice(&bytes).ok()
}

/// `GET /oidc/consent` — render the approval screen.
pub async fn consent_page(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<ConsentQuery>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The auth marker (proof of login) must still be alive; peek, don't consume.
    if oidc.challenges.peek(&query.auth).await.is_none() {
        return (StatusCode::BAD_REQUEST, "login expired; start over").into_response();
    }
    let Some(request) = parked_request(&state, &query.req).await else {
        return (StatusCode::BAD_REQUEST, "authorization request expired").into_response();
    };

    let client_name = match OAuthClientId::from_str(&request.client_id) {
        Ok(id) => match state.storage.oauth_client(id).await {
            Ok(Some(client)) => client.name,
            _ => request.client_id.clone(),
        },
        Err(_) => request.client_id.clone(),
    };

    let scope_items = request
        .scopes
        .iter()
        .map(|s| format!("<li>{}</li>", html_escape(scope_label(s))))
        .collect::<String>();

    let body = CONSENT_HTML
        .replace("{{CLIENT}}", &html_escape(&client_name))
        .replace("{{SCOPES}}", &scope_items)
        .replace("{{REQ}}", &html_escape(&query.req))
        .replace("{{AUTH}}", &html_escape(&query.auth));

    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(body),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    req: String,
    auth: String,
    decision: String,
}

/// `POST /oidc/consent` — apply the user's approve/deny decision.
pub async fn consent_submit(
    State(state): State<Arc<ApiState>>,
    Form(form): Form<ConsentForm>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    // Consume the login proof: consent is single-use per authentication.
    let account_bytes = match oidc.challenges.retrieve_challenge(&form.auth).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "login expired; start over").into_response(),
    };
    let Ok(account_str) = String::from_utf8(account_bytes) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let Some(request) = parked_request(&state, &form.req).await else {
        return (StatusCode::BAD_REQUEST, "authorization request expired").into_response();
    };
    // The parked request is now being resolved either way; consume it.
    let _ = oidc.challenges.retrieve_challenge(&form.req).await;

    if form.decision != "approve" {
        let location = error_redirect(
            &request.redirect_uri,
            "access_denied",
            request.state.as_deref(),
        );
        return redirect(&location);
    }

    let (Ok(account_id), Ok(client_id)) = (
        AccountId::from_str(&account_str),
        OAuthClientId::from_str(&request.client_id),
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    if let Err(err) = state
        .storage
        .upsert_oauth_grant(account_id, client_id, &request.scopes)
        .await
    {
        tracing::error!(%err, "consent: grant upsert failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let grant = CodeGrant {
        account_id: account_str,
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        code_challenge: request.code_challenge.clone(),
        nonce: request.nonce.clone(),
        scopes: request.scopes.clone(),
    };
    let Ok(code) = mint_code(oidc, &grant).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut params = vec![("code", code.as_str())];
    if let Some(state_param) = request.state.as_deref() {
        params.push(("state", state_param));
    }
    tracing::info!(account_id = %account_id, client_id = %client_id, "oidc consent approved");
    redirect(&redirect_with(&request.redirect_uri, &params))
}

fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

const CONSENT_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  ul { padding-left: 1.2rem; }
  li { margin: 0.4rem 0; }
  .actions { margin-top: 1.5rem; display: flex; gap: 0.75rem; }
  button { padding: 0.6rem 1.2rem; font-size: 1rem; cursor: pointer; }
  .approve { background: #1a73e8; color: white; border: none; border-radius: 4px; }
  .deny { background: #f1f3f4; color: #202124; border: 1px solid #dadce0; border-radius: 4px; }
</style>
</head>
<body>
<h1>Authorize <em>{{CLIENT}}</em></h1>
<p>This application is requesting permission to:</p>
<ul>{{SCOPES}}</ul>
<form method="post" action="/oidc/consent">
  <input type="hidden" name="req" value="{{REQ}}">
  <input type="hidden" name="auth" value="{{AUTH}}">
  <div class="actions">
    <button class="approve" type="submit" name="decision" value="approve">Allow</button>
    <button class="deny" type="submit" name="decision" value="deny">Deny</button>
  </div>
</form>
</body>
</html>
"#;
