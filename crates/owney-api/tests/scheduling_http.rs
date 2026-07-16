//! Public scheduling endpoints over the wire: unauthenticated page + slots,
//! the full booking flow in caller order, conflict/validation/rate-limit
//! boundaries.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use jmap_core::Dispatcher;
use owney_api::{ApiState, JmapCtx, router};
use owney_events::EventBus;
use owney_storage::{Availability, NewSchedulingPage, SchedulingPage, Storage};
use tower::util::ServiceExt;

struct Harness {
    state: Arc<ApiState>,
    /// Built once (like production) so the rate limiter's state persists
    /// across requests; cloned per call.
    app: axum::Router,
    page: SchedulingPage,
    owner: owney_storage::Account,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let events = EventBus::new(8);
    let storage = Arc::new(Storage::open(dir.path(), events.clone()).expect("open"));
    let owner = storage
        .create_account("alice@example.com", Some("Alice"))
        .await
        .expect("account");
    let calendar = storage
        .create_calendar(owner.id, "Personal".into(), None)
        .await
        .expect("calendar");
    let page = storage
        .create_scheduling_page(
            owner.id,
            NewSchedulingPage {
                slug: "meet-alice".into(),
                title: "Meet with <Alice>".into(),
                description: Some("30 minutes & counting".into()),
                calendar_id: calendar.id,
                // UTC keeps date math in tests trivial; DST is covered by
                // the slots unit tests.
                timezone: "UTC".into(),
                availability: Availability::default_business_hours(),
                durations_mins: vec![30],
                buffer_before_mins: 0,
                buffer_after_mins: 0,
                min_notice_mins: 0,
                max_per_day: None,
                valid_from: None,
                valid_until: None,
            },
        )
        .await
        .expect("page");

    let dispatcher: Dispatcher<JmapCtx> = Dispatcher::new("s0");
    let state = Arc::new(ApiState {
        dispatcher,
        storage,
        events,
        submitter: None,
        public_url: "http://alice.local:8381".into(),
        federation: Default::default(),
    });
    Harness {
        app: router(state.clone()),
        state,
        page,
        owner,
        _dir: dir,
    }
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn get(h: &Harness, uri: &str) -> axum::response::Response {
    h.app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

async fn post_json(h: &Harness, uri: &str, body: serde_json::Value) -> axum::response::Response {
    h.app
        .clone()
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
}

/// A weekday (Wednesday) at least a week out, as YYYY-MM-DD — availability
/// defaults are Mon-Fri so this date always has slots.
fn future_wednesday() -> (String, i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let days_since_epoch = now / 86_400;
    // 1970-01-01 was a Thursday: weekday index (days + 4) % 7, Sunday = 0.
    let weekday = (days_since_epoch + 4) % 7; // 3 = Wednesday
    let days_ahead = (3 - weekday + 7) % 7 + 7;
    let target_days = days_since_epoch + days_ahead;
    let date = chrono::DateTime::from_timestamp(target_days * 86_400, 0)
        .expect("date")
        .format("%Y-%m-%d")
        .to_string();
    (date, target_days * 86_400)
}

#[tokio::test]
async fn public_page_and_slots_need_no_auth() {
    let h = harness().await;

    let response = get(&h, "/schedule/meet-alice").await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_string(response).await;
    assert!(html.contains("Meet with &lt;Alice&gt;"), "title escaped");
    assert!(html.contains("30 minutes &amp; counting"));

    let (date, midnight) = future_wednesday();
    let response = get(
        &h,
        &format!("/schedule/meet-alice/slots?from={date}&to={date}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(response).await).expect("json");
    let slots = body["slots"].as_array().expect("slots");
    assert_eq!(slots.len(), 16, "8h / 30min");
    assert_eq!(slots[0]["start"], midnight + 9 * 3_600, "09:00 UTC");
}

#[tokio::test]
async fn unknown_and_paused_pages_are_uniform_404() {
    let h = harness().await;
    assert_eq!(
        get(&h, "/schedule/nope").await.status(),
        StatusCode::NOT_FOUND
    );

    h.state
        .storage
        .update_scheduling_page(
            h.owner.id,
            h.page.id,
            owney_storage::SchedulingPagePatch {
                status: Some(owney_storage::PageStatus::Paused),
                ..Default::default()
            },
        )
        .await
        .expect("pause");
    assert_eq!(
        get(&h, "/schedule/meet-alice").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&h, "/schedule/meet-alice/slots").await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn full_booking_flow_then_conflict() {
    let h = harness().await;
    let (date, _) = future_wednesday();

    // Caller order: page -> slots -> book.
    assert_eq!(
        get(&h, "/schedule/meet-alice").await.status(),
        StatusCode::OK
    );
    let response = get(
        &h,
        &format!("/schedule/meet-alice/slots?from={date}&to={date}"),
    )
    .await;
    let body: serde_json::Value = serde_json::from_str(&body_string(response).await).expect("json");
    let slot_start = body["slots"][0]["start"].as_i64().expect("slot");

    let book_body = serde_json::json!({
        "start": slot_start,
        "durationMins": 30,
        "name": "Bob",
        "email": "bob@remote.test",
        "note": "Looking forward!",
    });
    let response = post_json(&h, "/schedule/meet-alice/book", book_body.clone()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: serde_json::Value =
        serde_json::from_str(&body_string(response).await).expect("json");
    assert_eq!(created["start"], slot_start);

    // Storage state: booking + calendar event exist, owner got the
    // notification email in their inbox (submitter is None by design here,
    // so only the owner-side ingest happens).
    let bookings = h
        .state
        .storage
        .list_bookings(h.owner.id, None)
        .await
        .expect("bookings");
    assert_eq!(bookings.len(), 1);
    assert_eq!(bookings[0].visitor_email, "bob@remote.test");
    let events = h
        .state
        .storage
        .list_calendar_events(h.page.calendar_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].title, "Meeting: Bob & Alice");
    let inbox = h
        .state
        .storage
        .list_mailbox(h.owner.id, "inbox", 10)
        .await
        .expect("inbox");
    assert_eq!(inbox.len(), 1, "owner notification ingested");
    assert!(
        inbox[0]
            .subject
            .as_deref()
            .unwrap_or("")
            .contains("New booking: Bob")
    );

    // The slot is gone from /slots, and re-booking it conflicts.
    let response = get(
        &h,
        &format!("/schedule/meet-alice/slots?from={date}&to={date}"),
    )
    .await;
    let body: serde_json::Value = serde_json::from_str(&body_string(response).await).expect("json");
    assert!(
        !body["slots"]
            .as_array()
            .expect("slots")
            .iter()
            .any(|slot| slot["start"] == slot_start),
        "booked slot no longer offered"
    );
    let response = post_json(&h, "/schedule/meet-alice/book", book_body).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn validation_rejects_bad_input() {
    let h = harness().await;
    let (date, midnight) = future_wednesday();
    let _ = date;

    // Off-grid start (not a derived slot): 09:07 UTC.
    let response = post_json(
        &h,
        "/schedule/meet-alice/book",
        serde_json::json!({
            "start": midnight + 9 * 3_600 + 420,
            "durationMins": 30,
            "name": "Bob",
            "email": "bob@remote.test",
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Wrong duration.
    let response = post_json(
        &h,
        "/schedule/meet-alice/book",
        serde_json::json!({
            "start": midnight + 9 * 3_600,
            "durationMins": 45,
            "name": "Bob",
            "email": "bob@remote.test",
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Bad email.
    let response = post_json(
        &h,
        "/schedule/meet-alice/book",
        serde_json::json!({
            "start": midnight + 9 * 3_600,
            "durationMins": 30,
            "name": "Bob",
            "email": "not an email",
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn booking_rate_limit_trips() {
    let h = harness().await;
    // Every request shares the fallback IP key (no ConnectInfo under
    // oneshot), so 10 attempts exhaust the book budget regardless of body
    // validity.
    let mut last = StatusCode::OK;
    for _ in 0..11 {
        let response = post_json(
            &h,
            "/schedule/meet-alice/book",
            serde_json::json!({"start": 0, "durationMins": 30, "name": "x", "email": "x@y.z"}),
        )
        .await;
        last = response.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}
