//! Full OIDC ceremony, end to end, driven by a software authenticator
//! (`webauthn-authenticator-rs` soft passkey): enroll a passkey, run the
//! authorization-code login + consent flow, and exchange the code for tokens.
//!
//! This is the one test that exercises the real WebAuthn register/authenticate
//! path — every other test stops at "garbage credential is rejected".

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use jmap_core::Dispatcher;
use owney_authn_v2::{CreationChallengeResponse, RequestChallengeResponse};
use owney_core::config::OidcConfig;
use owney_events::EventBus;
use owney_storage::Storage;
use tower::util::ServiceExt;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

use crate::oidc::OidcState;
use crate::oidc::keys::OidcSigningKey;
use crate::{ApiState, JmapCtx, router};

const ISSUER: &str = "https://mail.example.com";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Harness {
    state: Arc<ApiState>,
    admin_token: String,
    client_id: String,
    redirect_uri: String,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(Storage::open(dir.path(), EventBus::new(8)).expect("open"));
    let account = storage
        .create_account("alice@example.com", Some("Alice"))
        .await
        .expect("account");
    let admin_token = storage
        .create_token(account.id, "admin")
        .await
        .expect("token");
    let redirect_uri = "https://app.example.com/cb".to_string();
    let (client, _s) = storage
        .create_oauth_client("Test App", std::slice::from_ref(&redirect_uri), true)
        .await
        .expect("client");

    let key = OidcSigningKey::load_or_generate(dir.path()).expect("key");
    let oidc =
        Arc::new(OidcState::new(OidcConfig::default(), ISSUER.to_string(), key).expect("oidc"));
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
        admin_token,
        client_id: client.id.to_string(),
        redirect_uri,
        _dir: dir,
    }
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("json")
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn full_enroll_login_consent_token_flow() {
    let h = harness().await;
    let origin = url::Url::parse(ISSUER).unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // --- 1. Enroll a passkey (bearer-authed with the admin token) -----------
    let start = router(h.state.clone())
        .oneshot(
            Request::post("/oidc/enroll/start")
                .header(header::AUTHORIZATION, format!("Bearer {}", h.admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("enroll start");
    assert_eq!(start.status(), StatusCode::OK);
    let start = body_json(start).await;
    let session_id = start["session_id"].as_str().unwrap().to_string();
    let cco: CreationChallengeResponse =
        serde_json::from_value(start["options"].clone()).expect("creation options");
    let reg = authenticator
        .do_registration(origin.clone(), cco)
        .expect("soft register");

    let finish = router(h.state.clone())
        .oneshot(
            Request::post("/oidc/enroll/finish")
                .header(header::AUTHORIZATION, format!("Bearer {}", h.admin_token))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "session_id": session_id,
                        "device_name": "SoftKey",
                        "credential": reg,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("enroll finish");
    assert_eq!(finish.status(), StatusCode::OK, "enrollment must succeed");
    assert_eq!(body_json(finish).await["enrolled"], true);

    // --- 2. Authorize: obtain the login page and its req id -----------------
    let authorize_uri = format!(
        "/oidc/authorize?response_type=code&client_id={}\
         &redirect_uri={}&scope=openid%20email%20offline_access&state=st1\
         &code_challenge={CHALLENGE}&code_challenge_method=S256",
        h.client_id,
        h.redirect_uri.replace(':', "%3A").replace('/', "%2F"),
    );
    let page = router(h.state.clone())
        .oneshot(Request::get(&authorize_uri).body(Body::empty()).unwrap())
        .await
        .expect("authorize");
    assert_eq!(page.status(), StatusCode::OK);
    let html = body_string(page).await;
    let req_id = html
        .split("const REQ = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("req id")
        .to_string();

    // --- 3. Login: passkey assertion ---------------------------------------
    let login_start = router(h.state.clone())
        .oneshot(
            Request::post("/oidc/authorize/login/start")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "req": req_id, "email": "alice@example.com" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("login start");
    assert_eq!(login_start.status(), StatusCode::OK);
    let login_start = body_json(login_start).await;
    let ceremony = login_start["ceremony"].as_str().unwrap().to_string();
    let rcr: RequestChallengeResponse =
        serde_json::from_value(login_start["options"].clone()).expect("request options");
    let assertion = authenticator
        .do_authentication(origin.clone(), rcr)
        .expect("soft authenticate");

    let login_finish = router(h.state.clone())
        .oneshot(
            Request::post("/oidc/authorize/login/finish")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "req": req_id,
                        "ceremony": ceremony,
                        "credential": assertion,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("login finish");
    assert_eq!(login_finish.status(), StatusCode::OK);
    let redirect = body_json(login_finish).await["redirect"]
        .as_str()
        .unwrap()
        .to_string();
    // No prior grant → we are sent to consent, not straight to the client.
    assert!(
        redirect.contains("/oidc/consent"),
        "first login needs consent"
    );
    let auth_marker = redirect
        .split("auth=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("auth marker")
        .to_string();

    // --- 4. Consent: approve -----------------------------------------------
    let consent = router(h.state.clone())
        .oneshot(
            Request::post("/oidc/consent")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "req={req_id}&auth={auth_marker}&decision=approve"
                )))
                .unwrap(),
        )
        .await
        .expect("consent");
    assert_eq!(consent.status(), StatusCode::SEE_OTHER);
    let location = consent
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(&h.redirect_uri));
    assert!(location.contains("state=st1"));
    let code = location
        .split("code=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("code")
        .to_string();

    // --- 5. Token exchange --------------------------------------------------
    let token = router(h.state.clone())
        .oneshot(
            Request::post("/oidc/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}\
                     &redirect_uri={}&client_id={}&code_verifier={VERIFIER}",
                    h.redirect_uri.replace(':', "%3A").replace('/', "%2F"),
                    h.client_id,
                )))
                .unwrap(),
        )
        .await
        .expect("token");
    assert_eq!(token.status(), StatusCode::OK, "code exchange succeeds");
    let token = body_json(token).await;
    assert!(token["access_token"].as_str().unwrap().starts_with("msk_"));
    assert!(token["id_token"].as_str().is_some(), "openid → id_token");
    assert!(
        token["refresh_token"].as_str().is_some(),
        "offline_access → refresh_token"
    );

    // --- 6. A second login now skips consent (grant remembered) -------------
    let page2 = router(h.state.clone())
        .oneshot(Request::get(&authorize_uri).body(Body::empty()).unwrap())
        .await
        .expect("authorize 2");
    let html2 = body_string(page2).await;
    let req2 = html2
        .split("const REQ = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();
    let ls2 = body_json(
        router(h.state.clone())
            .oneshot(
                Request::post("/oidc/authorize/login/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "req": req2, "email": "alice@example.com" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let ceremony2 = ls2["ceremony"].as_str().unwrap().to_string();
    let rcr2: RequestChallengeResponse = serde_json::from_value(ls2["options"].clone()).unwrap();
    let assertion2 = authenticator
        .do_authentication(origin, rcr2)
        .expect("auth 2");
    let lf2 = body_json(
        router(h.state.clone())
            .oneshot(
                Request::post("/oidc/authorize/login/finish")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "req": req2, "ceremony": ceremony2, "credential": assertion2 })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let redirect2 = lf2["redirect"].as_str().unwrap();
    // Grant already covers the scopes → straight back to the client with a code.
    assert!(
        redirect2.starts_with(&h.redirect_uri),
        "consent skipped on 2nd login"
    );
    assert!(redirect2.contains("code="));
}
