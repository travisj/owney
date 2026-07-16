//! In-crate tests for the token endpoint's happy paths. These need to mint an
//! authorization code, which is an internal (`pub(super)`) operation — doing it
//! here avoids adding any production test-seam. The passkey login/consent path
//! that normally produces a code is exercised separately by the softtoken
//! integration test.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use jmap_core::Dispatcher;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use owney_core::config::OidcConfig;
use owney_events::EventBus;
use owney_storage::Storage;
use tower::util::ServiceExt;

use crate::oidc::keys::{IdTokenClaims, OidcSigningKey};
use crate::oidc::session::{CodeGrant, mint_code};
use crate::oidc::{OidcState, SCOPE_EMAIL, SCOPE_MAIL, SCOPE_OFFLINE, SCOPE_OPENID};
use crate::{ApiState, JmapCtx, router};

const ISSUER: &str = "https://mail.example.com";
// RFC 7636 Appendix B vectors.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Harness {
    state: Arc<ApiState>,
    client_id: String,
    redirect_uri: String,
    account_id: String,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(8)).expect("open"));
    let account = storage
        .create_account("alice@example.com", Some("Alice"))
        .await
        .expect("account");
    let redirect_uri = "https://app.example.com/cb".to_string();
    let (client, _secret) = storage
        .create_oauth_client("Test App", std::slice::from_ref(&redirect_uri), true)
        .await
        .expect("client");

    let signing_key = OidcSigningKey::load_or_generate(dir.path()).expect("key");
    let oidc = Arc::new(
        OidcState::new(OidcConfig::default(), ISSUER.to_string(), signing_key).expect("oidc"),
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
    Harness {
        state,
        client_id: client.id.to_string(),
        redirect_uri,
        account_id: account.id.to_string(),
        _dir: dir,
    }
}

async fn code_for(h: &Harness, scopes: &[&str]) -> String {
    let oidc = h.state.oidc.as_ref().unwrap();
    let grant = CodeGrant {
        account_id: h.account_id.clone(),
        client_id: h.client_id.clone(),
        redirect_uri: h.redirect_uri.clone(),
        code_challenge: CHALLENGE.to_string(),
        nonce: Some("n1".to_string()),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
    };
    mint_code(oidc, &grant).await.expect("mint code")
}

async fn post_form(state: Arc<ApiState>, uri: &str, form: &str) -> axum::response::Response {
    router(state)
        .oneshot(
            Request::post(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
        .expect("response")
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn code_exchange_returns_verifiable_id_token_and_access_token() {
    let h = harness().await;
    let code = code_for(&h, &[SCOPE_OPENID, SCOPE_EMAIL, SCOPE_MAIL]).await;
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&code_verifier={VERIFIER}",
        urlencoding::encode(&h.redirect_uri),
        h.client_id,
    );
    let resp = post_form(h.state.clone(), "/oidc/token", &form).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;

    assert_eq!(body["token_type"], "Bearer");
    let access = body["access_token"].as_str().expect("access token");
    assert!(access.starts_with("msk_"));
    let id_token = body["id_token"].as_str().expect("id token");
    // No offline_access requested → no refresh token.
    assert!(body["refresh_token"].is_null());

    // Verify the ID token against the published JWKS.
    let oidc = h.state.oidc.as_ref().unwrap();
    let jwks = oidc.signing_key.jwks();
    let decoding = DecodingKey::from_rsa_components(
        jwks["keys"][0]["n"].as_str().unwrap(),
        jwks["keys"][0]["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[&h.client_id]);
    let decoded =
        jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding, &validation).expect("verify");
    assert_eq!(decoded.claims.sub, h.account_id);
    assert_eq!(decoded.claims.email.as_deref(), Some("alice@example.com"));
    assert_eq!(decoded.claims.email_verified, Some(true));
    assert_eq!(decoded.claims.nonce.as_deref(), Some("n1"));

    // The access token now works at userinfo and reveals email (email scope).
    let ui = router(h.state.clone())
        .oneshot(
            Request::get("/oidc/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("userinfo");
    assert_eq!(ui.status(), StatusCode::OK);
    let claims = json_body(ui).await;
    assert_eq!(claims["sub"], h.account_id);
    assert_eq!(claims["email"], "alice@example.com");
}

#[tokio::test]
async fn code_is_single_use() {
    let h = harness().await;
    let code = code_for(&h, &[SCOPE_OPENID]).await;
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&code_verifier={VERIFIER}",
        urlencoding::encode(&h.redirect_uri),
        h.client_id,
    );
    let first = post_form(h.state.clone(), "/oidc/token", &form).await;
    assert_eq!(first.status(), StatusCode::OK);
    // Replaying the same code fails.
    let second = post_form(h.state.clone(), "/oidc/token", &form).await;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(second).await["error"], "invalid_grant");
}

#[tokio::test]
async fn pkce_mismatch_is_rejected() {
    let h = harness().await;
    let code = code_for(&h, &[SCOPE_OPENID]).await;
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&code_verifier=wrong",
        urlencoding::encode(&h.redirect_uri),
        h.client_id,
    );
    let resp = post_form(h.state.clone(), "/oidc/token", &form).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_rotation_and_reuse_detection() {
    let h = harness().await;
    let code = code_for(&h, &[SCOPE_OPENID, SCOPE_MAIL, SCOPE_OFFLINE]).await;
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&code_verifier={VERIFIER}",
        urlencoding::encode(&h.redirect_uri),
        h.client_id,
    );
    let resp = post_form(h.state.clone(), "/oidc/token", &form).await;
    let body = json_body(resp).await;
    let refresh1 = body["refresh_token"].as_str().expect("refresh").to_string();
    let access1 = body["access_token"].as_str().unwrap().to_string();

    // Rotate: refresh1 -> access2 + refresh2.
    let rform = format!(
        "grant_type=refresh_token&refresh_token={refresh1}&client_id={}",
        h.client_id
    );
    let r2 = post_form(h.state.clone(), "/oidc/token", &rform).await;
    assert_eq!(r2.status(), StatusCode::OK);
    let b2 = json_body(r2).await;
    let refresh2 = b2["refresh_token"].as_str().expect("refresh2").to_string();
    assert_ne!(refresh1, refresh2, "refresh token rotates");

    // Reusing refresh1 (already rotated) is theft: rejected AND it burns the
    // family, so refresh2 must also stop working.
    let reuse = post_form(h.state.clone(), "/oidc/token", &rform).await;
    assert_eq!(reuse.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(reuse).await["error"], "invalid_grant");

    let r2form = format!(
        "grant_type=refresh_token&refresh_token={refresh2}&client_id={}",
        h.client_id
    );
    let after = post_form(h.state.clone(), "/oidc/token", &r2form).await;
    assert_eq!(after.status(), StatusCode::BAD_REQUEST, "family revoked");

    // The first access token was revoked with the family too.
    let ui = router(h.state.clone())
        .oneshot(
            Request::get("/oidc/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("userinfo");
    assert_eq!(ui.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_rejects_unknown_client_and_grant_type() {
    let h = harness().await;
    let bad_client = post_form(
        h.state.clone(),
        "/oidc/token",
        "grant_type=authorization_code&code=x&client_id=not-a-uuid",
    )
    .await;
    assert_eq!(bad_client.status(), StatusCode::UNAUTHORIZED);

    let code = code_for(&h, &[SCOPE_OPENID]).await;
    let _ = code; // ensure a client exists; now use a bad grant_type
    let bad_grant = post_form(
        h.state.clone(),
        "/oidc/token",
        &format!("grant_type=password&client_id={}", h.client_id),
    )
    .await;
    assert_eq!(bad_grant.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(bad_grant).await["error"],
        "unsupported_grant_type"
    );
}
