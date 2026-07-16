//! HTTP-level tests for the OIDC provider: discovery/JWKS shape, gating when
//! disabled, and the enrollment auth boundary.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use jmap_core::Dispatcher;
use owney_api::oidc::{OidcSigningKey, OidcState};
use owney_api::{ApiState, JmapCtx, router};
use owney_core::config::OidcConfig;
use owney_events::EventBus;
use owney_storage::Storage;
use tower::util::ServiceExt;

const ISSUER: &str = "https://mail.example.com";

/// Build state with OIDC enabled, returning (state, bearer token, tempdir).
async fn oidc_state() -> (Arc<ApiState>, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(8)).expect("open"));
    let account = storage
        .create_account("alice@example.com", None)
        .await
        .expect("account");
    let token = storage
        .create_token(account.id, "test")
        .await
        .expect("token");

    let signing_key = OidcSigningKey::load_or_generate(dir.path()).expect("signing key");
    let oidc = Arc::new(
        OidcState::new(OidcConfig::default(), ISSUER.to_string(), signing_key).expect("oidc state"),
    );

    let dispatcher: Dispatcher<JmapCtx> = Dispatcher::new("s0");
    let state = Arc::new(ApiState {
        dispatcher,
        storage,
        events: EventBus::new(8),
        submitter: None,
        public_url: ISSUER.into(),
        federation: Default::default(),
        oidc: Some(oidc),
    });
    (state, token, dir)
}

/// Build state with OIDC disabled.
async fn disabled_state() -> (Arc<ApiState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(8)).expect("open"));
    let dispatcher: Dispatcher<JmapCtx> = Dispatcher::new("s0");
    let state = Arc::new(ApiState {
        dispatcher,
        storage,
        events: EventBus::new(8),
        submitter: None,
        public_url: ISSUER.into(),
        federation: Default::default(),
        oidc: None,
    });
    (state, dir)
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn discovery_document_is_public_and_well_formed() {
    let (state, _token, _dir) = oidc_state().await;
    let response = router(state)
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let doc = body_json(response).await;
    assert_eq!(doc["issuer"], ISSUER);
    assert_eq!(
        doc["authorization_endpoint"],
        format!("{ISSUER}/oidc/authorize")
    );
    assert_eq!(doc["token_endpoint"], format!("{ISSUER}/oidc/token"));
    assert_eq!(doc["jwks_uri"], format!("{ISSUER}/oidc/jwks.json"));
    assert_eq!(doc["id_token_signing_alg_values_supported"][0], "RS256");
    assert_eq!(doc["code_challenge_methods_supported"][0], "S256");
    let scopes = doc["scopes_supported"].as_array().expect("scopes");
    assert!(scopes.iter().any(|s| s == "openid"));
    assert!(scopes.iter().any(|s| s == "owney:mail"));
}

#[tokio::test]
async fn jwks_publishes_one_rs256_key() {
    let (state, _token, _dir) = oidc_state().await;
    let response = router(state)
        .oneshot(Request::get("/oidc/jwks.json").body(Body::empty()).unwrap())
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let jwks = body_json(response).await;
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["use"], "sig");
    assert!(key["kid"].as_str().is_some_and(|k| !k.is_empty()));
    assert!(key["n"].as_str().is_some_and(|n| !n.is_empty()));
    assert!(key["e"].as_str().is_some_and(|e| !e.is_empty()));
}

#[tokio::test]
async fn routes_absent_when_oidc_disabled() {
    let (state, _dir) = disabled_state().await;
    // Disabled: discovery is not mounted, so it falls through to the SPA
    // fallback — anything but a 200 JSON document. We assert it is not the
    // provider metadata.
    let response = router(state)
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    assert_ne!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn enroll_start_requires_bearer() {
    let (state, _token, _dir) = oidc_state().await;
    let response = router(state)
        .oneshot(
            Request::post("/oidc/enroll/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_start_with_bearer_returns_creation_options() {
    let (state, token, _dir) = oidc_state().await;
    let response = router(state)
        .oneshot(
            Request::post("/oidc/enroll/start")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body["session_id"].as_str().is_some_and(|s| !s.is_empty()));
    // WebAuthn creation options must carry a challenge and our RP id.
    let pk = &body["options"]["publicKey"];
    assert!(pk["challenge"].as_str().is_some_and(|c| !c.is_empty()));
    assert_eq!(pk["rp"]["id"], "mail.example.com");
}

/// Build an OIDC harness that also has a registered public client.
/// Returns (state, client_id, redirect_uri, tempdir).
async fn oidc_state_with_client() -> (Arc<ApiState>, String, String, tempfile::TempDir) {
    let (state, _token, dir) = oidc_state().await;
    let redirect_uri = "https://app.example.com/callback".to_string();
    let (client, _secret) = state
        .storage
        .create_oauth_client("Test App", std::slice::from_ref(&redirect_uri), true)
        .await
        .expect("client");
    (state, client.id.to_string(), redirect_uri, dir)
}

fn authorize_url(client_id: &str, redirect_uri: &str, extra: &str) -> String {
    format!(
        "/oidc/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid%20email&state=xyz\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256{extra}",
        urlencoding_encode(redirect_uri),
    )
}

fn urlencoding_encode(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

async fn get(state: Arc<ApiState>, uri: &str) -> axum::response::Response {
    router(state)
        .oneshot(Request::get(uri).body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

#[tokio::test]
async fn authorize_unknown_client_shows_error_never_redirects() {
    let (state, _c, _u, _dir) = oidc_state_with_client().await;
    let bad = "00000000-0000-0000-0000-000000000000";
    let resp = get(
        state,
        &authorize_url(bad, "https://app.example.com/callback", ""),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Must not be a redirect (no Location header) — open-redirect guard.
    assert!(resp.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn authorize_bad_redirect_uri_shows_error_never_redirects() {
    let (state, client_id, _u, _dir) = oidc_state_with_client().await;
    let resp = get(
        state,
        &authorize_url(&client_id, "https://evil.example.com/steal", ""),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get(header::LOCATION).is_none());
}

#[tokio::test]
async fn authorize_bad_response_type_redirects_with_error() {
    let (state, client_id, redirect_uri, _dir) = oidc_state_with_client().await;
    // Override response_type to a bad value by requesting token (not code).
    let uri = format!(
        "/oidc/authorize?response_type=token&client_id={client_id}\
         &redirect_uri={}&scope=openid&state=xyz\
         &code_challenge=abc&code_challenge_method=S256",
        urlencoding_encode(&redirect_uri),
    );
    let resp = get(state, &uri).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.starts_with(&redirect_uri),
        "redirect stays on client uri"
    );
    assert!(loc.contains("error=unsupported_response_type"));
    assert!(loc.contains("state=xyz"));
}

#[tokio::test]
async fn authorize_missing_pkce_redirects_with_error() {
    let (state, client_id, redirect_uri, _dir) = oidc_state_with_client().await;
    let uri = format!(
        "/oidc/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid&state=xyz",
        urlencoding_encode(&redirect_uri),
    );
    let resp = get(state, &uri).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(loc.contains("error=invalid_request"));
}

#[tokio::test]
async fn authorize_unknown_scope_redirects_with_error() {
    let (state, client_id, redirect_uri, _dir) = oidc_state_with_client().await;
    let uri = format!(
        "/oidc/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid%20wat&state=xyz\
         &code_challenge=abc&code_challenge_method=S256",
        urlencoding_encode(&redirect_uri),
    );
    let resp = get(state, &uri).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(loc.contains("error=invalid_scope"));
}

#[tokio::test]
async fn authorize_valid_serves_login_page() {
    let (state, client_id, redirect_uri, _dir) = oidc_state_with_client().await;
    let resp = get(state, &authorize_url(&client_id, &redirect_uri, "")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains("Test App"), "client name shown");
    assert!(html.contains("login/start"), "login ceremony wired");
}

#[tokio::test]
async fn login_start_unknown_account_is_rejected() {
    let (state, client_id, redirect_uri, _dir) = oidc_state_with_client().await;
    // Get a real req id from a valid authorize call.
    let page = get(state.clone(), &authorize_url(&client_id, &redirect_uri, "")).await;
    let html = String::from_utf8(
        page.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let req_id = html
        .split("const REQ = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("req id")
        .to_string();

    let body = serde_json::json!({ "req": req_id, "email": "nobody@example.com" });
    let resp = router(state)
        .oneshot(
            Request::post("/oidc/authorize/login/start")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_start_expired_request_is_rejected() {
    let (state, _c, _u, _dir) = oidc_state_with_client().await;
    let body = serde_json::json!({ "req": "no-such-req", "email": "alice@example.com" });
    let resp = router(state)
        .oneshot(
            Request::post("/oidc/authorize/login/start")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Mint an OIDC-style scoped token for alice with the given scopes.
async fn scoped_token(state: &ApiState, scopes: &[&str]) -> String {
    let account = state
        .storage
        .account_by_email("alice@example.com")
        .await
        .expect("lookup")
        .expect("account");
    let (client, _s) = state
        .storage
        .create_oauth_client("App", &["https://a/cb".to_string()], true)
        .await
        .expect("client");
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let far_future = 4_102_444_800; // year 2100
    let (token, _hash) = state
        .storage
        .create_scoped_token(account.id, "t", &scopes, far_future, client.id)
        .await
        .expect("scoped token");
    token
}

#[tokio::test]
async fn scoped_token_without_mail_scope_is_forbidden_on_jmap() {
    let (state, _token, _dir) = oidc_state().await;
    let token = scoped_token(&state, &["openid", "email"]).await;
    let resp = router(state)
        .oneshot(
            Request::post("/jmap/api")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn scoped_token_with_mail_scope_passes_auth_on_jmap() {
    let (state, _token, _dir) = oidc_state().await;
    let token = scoped_token(&state, &["openid", "owney:mail"]).await;
    let resp = router(state)
        .oneshot(
            Request::post("/jmap/api")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{\"using\":[],\"methodCalls\":[]}"))
                .unwrap(),
        )
        .await
        .expect("response");
    // Auth passed: not 401/403. (Dispatch may 200 or 400 on the body.)
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn scoped_token_is_invisible_to_imap_path() {
    // account_by_token is the IMAP LOGIN path; it must reject scoped tokens so
    // an OIDC-delegated token can never be used as an IMAP password.
    let (state, _token, _dir) = oidc_state().await;
    let token = scoped_token(&state, &["owney:mail"]).await;
    assert!(
        state
            .storage
            .account_by_token(&token)
            .await
            .unwrap()
            .is_none(),
        "scoped token must not resolve via account_by_token"
    );
    // But the scope-aware path does resolve it.
    assert!(
        state
            .storage
            .account_and_access_by_token(&token)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn enroll_finish_rejects_garbage_credential() {
    let (state, token, _dir) = oidc_state().await;

    // Start to obtain a real session id.
    let start = router(state.clone())
        .oneshot(
            Request::post("/oidc/enroll/start")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("start");
    let session_id = body_json(start).await["session_id"]
        .as_str()
        .expect("session id")
        .to_string();

    // A well-formed request body but a bogus credential must be rejected, not
    // persisted. (A full positive path needs a software authenticator; that
    // lives in the softtoken integration test.)
    let payload = serde_json::json!({
        "session_id": session_id,
        "credential": {"id": "AAAA", "rawId": "AAAA", "type": "public-key",
                       "response": {"clientDataJSON": "AAAA", "attestationObject": "AAAA"}},
    });
    let response = router(state)
        .oneshot(
            Request::post("/oidc/enroll/finish")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .expect("finish");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
