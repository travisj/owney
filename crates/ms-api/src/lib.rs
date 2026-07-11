//! The HTTP layer: axum router exposing the JMAP session object and API
//! endpoint, authenticated with bearer tokens (`admin token`). JMAP data
//! methods are registered on the dispatcher by ms-jmap-mail; this crate is
//! transport only.

pub mod push;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use jmap_core::{Dispatcher, Session};
use ms_storage::{Account, Storage};

/// Per-request context handed to every JMAP method handler.
pub struct JmapCtx {
    pub account: Account,
    pub storage: Arc<Storage>,
    /// Outbound pipeline; None in read-only deployments and some tests.
    pub submitter: Option<Arc<dyn ms_delivery::Submitter>>,
}

impl std::fmt::Debug for JmapCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JmapCtx")
            .field("account", &self.account.email)
            .finish_non_exhaustive()
    }
}

pub struct ApiState {
    pub dispatcher: Dispatcher<JmapCtx>,
    pub storage: Arc<Storage>,
    pub events: ms_events::EventBus,
    pub submitter: Option<Arc<dyn ms_delivery::Submitter>>,
    /// Base URL clients reach us at, e.g. `https://mail.example.com`.
    pub public_url: String,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiState")
            .field("public_url", &self.public_url)
            .finish_non_exhaustive()
    }
}

pub fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/jmap", get(session))
        .route("/jmap/api", post(api))
        .route("/jmap/eventsource", get(push::eventsource))
        .route("/jmap/ws", get(push::websocket))
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(download),
        )
        .route("/jmap/upload/{account_id}", post(upload))
        .route("/.well-known/openpgpkey/hu/{hash}", get(wkd_key))
        .route("/.well-known/openpgpkey/policy", get(|| async { "" }))
        .route("/mcp", post(mcp))
        .with_state(state)
}

/// MCP over streamable HTTP: one JSON-RPC request per POST, bearer-authed.
/// The token's send scope gates the `send_email` tool.
async fn mcp(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    let account = authenticate(&state, &headers).await?;
    let request: serde_json::Value = serde_json::from_str(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": "parse error"},
            })),
        )
            .into_response()
    })?;

    let ctx = ms_mcp::McpCtx {
        account_id: account.id,
        account_email: account.email,
        storage: state.storage.clone(),
        submitter: state.submitter.clone(),
        may_send: state.submitter.is_some(),
    };
    match ms_mcp::handle(&ctx, &request).await {
        Some(response) => Ok(axum::Json(response).into_response()),
        // Notification: acknowledge with 202, no body (per MCP HTTP transport).
        None => Ok(StatusCode::ACCEPTED.into_response()),
    }
}

/// WKD direct method: serve the public key for the local part whose hash
/// matches. Unauthenticated by design — this is key publication.
async fn wkd_key(
    State(state): State<Arc<ApiState>>,
    Path(hash): Path<String>,
) -> Result<Response, Response> {
    let accounts = state.storage.accounts().await.map_err(|err| {
        tracing::error!(%err, "wkd account listing failed");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    for account in accounts {
        let Some((local, _domain)) = account.email.rsplit_once('@') else {
            continue;
        };
        let matches = ms_pgp::wkd::hu(local).map(|h| h == hash).unwrap_or(false);
        if !matches {
            continue;
        }
        let cert = ms_pgp::own_cert(&state.storage, account.id)
            .await
            .map_err(|err| {
                tracing::error!(%err, "wkd key load failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
        let der = ms_pgp::public_der(&cert)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        return Ok(([(header::CONTENT_TYPE, "application/octet-stream")], der).into_response());
    }
    Err(StatusCode::NOT_FOUND.into_response())
}

async fn healthz() -> &'static str {
    "ok"
}

/// Resolve the bearer token to an account, or produce the 401.
pub(crate) async fn authenticate(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<Account, Response> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "authentication required",
        )
            .into_response()
    };

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;

    match state.storage.account_by_token(token).await {
        Ok(Some(account)) => Ok(account),
        Ok(None) => Err(unauthorized()),
        Err(err) => {
            tracing::error!(%err, "token lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

async fn session(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let account = authenticate(&state, &headers).await?;
    let session = Session::for_account(
        &state.public_url,
        &account.email,
        &account.id.to_string(),
        state.dispatcher.capabilities().clone(),
        "0",
    );
    Ok(axum::Json(session).into_response())
}

async fn api(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    let account = authenticate(&state, &headers).await?;

    if body.len() as u64 > state.dispatcher.limits().max_size_request {
        let problem = jmap_core::RequestError::Limit("maxSizeRequest").problem_details();
        return Err((StatusCode::BAD_REQUEST, axum::Json(problem)).into_response());
    }

    let request: jmap_core::Request = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(_) => {
            let problem = jmap_core::RequestError::NotRequest.problem_details();
            return Err((StatusCode::BAD_REQUEST, axum::Json(problem)).into_response());
        }
    };

    let ctx = Arc::new(JmapCtx {
        account,
        storage: state.storage.clone(),
        submitter: state.submitter.clone(),
    });
    match state.dispatcher.process(request, ctx).await {
        Ok(response) => Ok(axum::Json(response).into_response()),
        Err(err) => {
            Err((StatusCode::BAD_REQUEST, axum::Json(err.problem_details())).into_response())
        }
    }
}

/// Blob upload (RFC 8620 §6.1).
async fn upload(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, Response> {
    let account = authenticate(&state, &headers).await?;
    if account_id != account.id.to_string() {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    if body.len() as u64 > state.dispatcher.limits().max_size_upload {
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let size = body.len();
    match state.storage.put_blob(body.to_vec()).await {
        Ok(blob_id) => Ok(axum::Json(serde_json::json!({
            "accountId": account_id,
            "blobId": blob_id.to_hex(),
            "type": content_type,
            "size": size,
        }))
        .into_response()),
        Err(err) => {
            tracing::error!(%err, "upload failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Raw blob download (RFC 8620 §6.2): the stored, decrypted message bytes.
async fn download(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Path((account_id, blob_id, _name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let account = authenticate(&state, &headers).await?;
    if account_id != account.id.to_string() {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    let blob_id: ms_core::BlobId = blob_id
        .parse()
        .map_err(|_| StatusCode::NOT_FOUND.into_response())?;
    match state.storage.get_blob(blob_id).await {
        Ok(bytes) => {
            Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
        }
        Err(ms_storage::StorageError::BlobNotFound(_)) => {
            Err(StatusCode::NOT_FOUND.into_response())
        }
        Err(err) => {
            tracing::error!(%err, "blob download failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}
