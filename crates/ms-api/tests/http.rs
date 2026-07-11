//! HTTP-level tests: auth, session shape, JMAP echo over the wire.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use jmap_core::Dispatcher;
use ms_api::{ApiState, JmapCtx, router};
use ms_events::EventBus;
use ms_storage::Storage;
use tower::util::ServiceExt;

async fn test_state() -> (Arc<ApiState>, String, tempfile::TempDir) {
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

    let dispatcher: Dispatcher<JmapCtx> = Dispatcher::new("s0");
    let state = Arc::new(ApiState {
        dispatcher,
        storage,
        events: EventBus::new(8),
        submitter: None,
        public_url: "https://mail.example.com".into(),
    });
    (state, token, dir)
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
async fn health_needs_no_auth() {
    let (state, _token, _dir) = test_state().await;
    let response = router(state)
        .oneshot(
            Request::get("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn session_requires_and_accepts_token() {
    let (state, token, _dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::get("/.well-known/jmap")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router(state)
        .oneshot(
            Request::get("/.well-known/jmap")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let session = body_json(response).await;
    assert_eq!(session["apiUrl"], "https://mail.example.com/jmap/api");
    assert_eq!(session["username"], "alice@example.com");
    assert!(session["capabilities"]["urn:ietf:params:jmap:core"].is_object());
}

#[tokio::test]
async fn echo_over_http() {
    let (state, token, _dir) = test_state().await;
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core"],
        "methodCalls": [["Core/echo", {"ping": 1}, "c1"]],
    });

    let response = router(state)
        .oneshot(
            Request::post("/jmap/api")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(request_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["methodResponses"][0][1]["ping"], 1);
    assert_eq!(body["methodResponses"][0][2], "c1");
}

#[tokio::test]
async fn malformed_request_is_a_problem_details() {
    let (state, token, _dir) = test_state().await;
    let response = router(state)
        .oneshot(
            Request::post("/jmap/api")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("this is not json"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["type"], "urn:ietf:params:jmap:error:notRequest");
}
