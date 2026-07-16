//! Passkey enrollment for OIDC login. A user who already holds a valid bearer
//! token (an app password) enrols a passkey so they can later authenticate at
//! `/oidc/authorize` without pasting a token into a browser.
//!
//! Every credential is keyed by the authenticated [`AccountId`] — never by an
//! email or a client-supplied identity — so one account can never enrol a
//! passkey against another. The start/finish ceremony state is parked in the
//! OIDC challenge store under a random id with a 5-minute TTL.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use owney_authn_v2::{CredentialId, PasskeyRegistration, RegisterPublicKeyCredential};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiState;
use crate::authenticate;

/// Ceremony state stored between `start` and `finish`. Binds the WebAuthn
/// registration state to the account that began it, so `finish` can reject a
/// session replayed under a different token.
#[derive(Serialize, Deserialize)]
struct EnrollState {
    account_id: String,
    reg: PasskeyRegistration,
}

#[derive(Debug, Deserialize)]
pub struct EnrollFinishRequest {
    session_id: String,
    #[serde(default)]
    device_name: Option<String>,
    credential: Value,
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// `POST /oidc/enroll/start` — begin a passkey registration for the
/// authenticated account. Existing credentials are excluded so the same
/// authenticator cannot be enrolled twice.
pub async fn enroll_start(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let account_key = account.id.to_string();
    let existing = match state
        .storage
        .list_passkeys_for_account(account_key.clone())
        .await
    {
        Ok(creds) => creds,
        Err(err) => {
            tracing::error!(%err, "enroll: listing passkeys failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let exclude: Vec<_> = existing
        .iter()
        .map(|c| CredentialId(c.id.clone()).0.into())
        .collect();
    let exclude = if exclude.is_empty() {
        None
    } else {
        Some(exclude)
    };

    // The WebAuthn user name/display comes from the account, not client input.
    let reg_opts = match oidc.passkey_manager.start_registration(
        &account.email,
        account.display_name.as_deref().unwrap_or(&account.email),
        exclude,
    ) {
        Ok(opts) => opts,
        Err(err) => {
            tracing::error!(%err, "enroll: start_registration failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let stored = EnrollState {
        account_id: account_key,
        reg: reg_opts.state,
    };
    let bytes = match serde_json::to_vec(&stored) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(%err, "enroll: state serialization failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let session_id = oidc
        .challenges
        .store_with_ttl(bytes, Duration::from_secs(300))
        .await;

    match serde_json::to_value(reg_opts.options) {
        Ok(options) => {
            Json(json!({ "session_id": session_id, "options": options })).into_response()
        }
        Err(err) => {
            tracing::error!(%err, "enroll: options serialization failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `POST /oidc/enroll/finish` — verify the authenticator's response and persist
/// the credential under the authenticated account.
pub async fn enroll_finish(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(req): Json<EnrollFinishRequest>,
) -> Response {
    let account = match authenticate(&state, &headers).await {
        Ok(account) => account,
        Err(response) => return response,
    };
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let bytes = match oidc.challenges.retrieve_challenge(&req.session_id).await {
        Ok(bytes) => bytes,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "unknown or expired session"),
    };
    let stored: EnrollState = match serde_json::from_slice(&bytes) {
        Ok(stored) => stored,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "corrupt session state"),
    };

    // Defense in depth: the token finishing the ceremony must be the same
    // account that started it. A consumed challenge cannot be reused anyway.
    let account_key = account.id.to_string();
    if stored.account_id != account_key {
        return json_error(StatusCode::FORBIDDEN, "session belongs to another account");
    }

    let response: RegisterPublicKeyCredential = match serde_json::from_value(req.credential) {
        Ok(response) => response,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid credential"),
    };
    let device_name = req
        .device_name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Passkey".to_string());

    let credential = match oidc.passkey_manager.finish_registration(
        account_key.clone(),
        device_name,
        &response,
        &stored.reg,
    ) {
        Ok(credential) => credential,
        Err(err) => {
            tracing::warn!(%err, "enroll: finish_registration rejected");
            return json_error(StatusCode::BAD_REQUEST, "registration verification failed");
        }
    };

    let passkey_bytes = match credential.passkey_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(%err, "enroll: passkey serialization failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let storage_cred = owney_storage::PasskeyCredential {
        id: credential.id.0.clone(),
        account_id: account_key,
        device_name: credential.device_name.clone(),
        public_key: passkey_bytes,
        counter: credential.counter,
        backup_eligible: credential.backup_eligible,
        backup_state: credential.backup_state,
        aaguid: None,
        created_at: credential.created_at,
        last_used_at: credential.last_used_at,
        disabled: credential.disabled,
    };
    if let Err(err) = state.storage.save_passkey_credential(&storage_cred).await {
        tracing::error!(%err, "enroll: saving credential failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    tracing::info!(account_id = %account.id, device = %credential.device_name, "oidc passkey enrolled");
    Json(json!({ "enrolled": true, "device_name": credential.device_name })).into_response()
}

/// `GET /oidc/enroll` — a minimal self-contained page that runs the WebAuthn
/// registration ceremony. The user pastes an app-password token; the page uses
/// it as the bearer credential for the start/finish calls. Unauthenticated by
/// design — the security boundary is on the two POST handlers.
pub async fn enroll_page(State(state): State<Arc<ApiState>>) -> Response {
    if state.oidc.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(ENROLL_HTML),
    )
        .into_response()
}

const ENROLL_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enroll a passkey</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  label { display: block; margin: 1rem 0 0.25rem; font-weight: 600; }
  input { width: 100%; padding: 0.5rem; font-size: 1rem; box-sizing: border-box; }
  button { margin-top: 1.5rem; padding: 0.6rem 1.2rem; font-size: 1rem; cursor: pointer; }
  #status { margin-top: 1rem; padding: 0.75rem; border-radius: 4px; white-space: pre-wrap; }
  .ok { background: #e6f4ea; color: #137333; }
  .err { background: #fce8e6; color: #c5221f; }
</style>
</head>
<body>
<h1>Enroll a passkey</h1>
<p>Register a passkey for this account so you can sign in to connected apps.</p>
<label for="token">Access token</label>
<input id="token" type="password" placeholder="msk_..." autocomplete="off">
<label for="device">Device name (optional)</label>
<input id="device" type="text" placeholder="MacBook Pro">
<button id="go">Enroll passkey</button>
<div id="status"></div>
<script>
const b64uToBuf = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
};
const bufToB64u = (buf) => {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const show = (msg, ok) => {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = ok ? 'ok' : 'err';
};
document.getElementById('go').onclick = async () => {
  const token = document.getElementById('token').value.trim();
  const device = document.getElementById('device').value.trim();
  if (!token) { show('Enter an access token first.', false); return; }
  const auth = { 'Authorization': 'Bearer ' + token };
  try {
    show('Starting…', true);
    let r = await fetch('/oidc/enroll/start', { method: 'POST', headers: auth });
    if (!r.ok) { show('Start failed: ' + r.status + ' ' + (await r.text()), false); return; }
    const { session_id, options } = await r.json();
    const pk = options.publicKey;
    pk.challenge = b64uToBuf(pk.challenge);
    pk.user.id = b64uToBuf(pk.user.id);
    if (pk.excludeCredentials) pk.excludeCredentials.forEach(c => c.id = b64uToBuf(c.id));
    show('Waiting for your authenticator…', true);
    const cred = await navigator.credentials.create({ publicKey: pk });
    const payload = {
      session_id,
      device_name: device || null,
      credential: {
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: bufToB64u(cred.response.clientDataJSON),
          attestationObject: bufToB64u(cred.response.attestationObject),
        },
      },
    };
    r = await fetch('/oidc/enroll/finish', {
      method: 'POST',
      headers: { ...auth, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) { show('Finish failed: ' + r.status + ' ' + (await r.text()), false); return; }
    const done = await r.json();
    show('Passkey enrolled: ' + (done.device_name || 'Passkey'), true);
  } catch (e) {
    show('Error: ' + e, false);
  }
};
</script>
</body>
</html>
"#;
