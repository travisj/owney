//! Two-server end-to-end federation test.
//!
//! Stands up two full Owney API servers (A and B) on loopback, each with its
//! own storage and generated server identity, and drives a real cross-server
//! calendar share over signed HTTP: discover + pin, invite, accept, then a
//! realtime push (A notifies B, B pulls the sealed delta and applies it). Also
//! checks the authorization boundary over the wire (unsigned and wrong-capability
//! requests are rejected).
//!
//! Identity uses logical domains (a.test / b.test); a URL-override map points
//! those domains at the loopback ports, so no TLS or DNS is needed.

use std::collections::HashMap;
use std::sync::Arc;

use owney_api::fed_sig::FederationConfig;
use owney_api::{ApiState, fed_worker, federation};
use owney_events::EventBus;
use owney_storage::{SharingType, Storage};

fn make_state(
    storage: Arc<Storage>,
    events: EventBus,
    public_url: &str,
    federation: FederationConfig,
) -> Arc<ApiState> {
    Arc::new(ApiState {
        dispatcher: jmap_core::Dispatcher::new("0"),
        storage,
        events,
        submitter: None,
        public_url: public_url.to_string(),
        federation,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_server_federation_end_to_end() {
    // --- storages + servers -------------------------------------------------
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let events_a = EventBus::new(64);
    let events_b = EventBus::new(64);
    let storage_a = Arc::new(Storage::open(dir_a.path(), events_a.clone()).unwrap());
    let storage_b = Arc::new(Storage::open(dir_b.path(), events_b.clone()).unwrap());

    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let addr_b = listener_b.local_addr().unwrap();

    // Explicit per-instance config (no global env): both servers know how to
    // reach each domain on loopback, and permit http/private targets for the
    // test only.
    let mut overrides = HashMap::new();
    overrides.insert("a.test".to_string(), format!("http://{addr_a}"));
    overrides.insert("b.test".to_string(), format!("http://{addr_b}"));
    let fed_config = FederationConfig {
        enabled: true,
        allow_private_ips: true,
        url_overrides: overrides,
        allowlist: None,
    };

    let state_a = make_state(
        storage_a.clone(),
        events_a,
        "http://a.test",
        fed_config.clone(),
    );
    let state_b = make_state(
        storage_b.clone(),
        events_b,
        "http://b.test",
        fed_config.clone(),
    );

    tokio::spawn(async move {
        axum::serve(listener_a, owney_api::router(state_a))
            .await
            .unwrap();
    });
    tokio::spawn(async move {
        axum::serve(listener_b, owney_api::router(state_b))
            .await
            .unwrap();
    });
    // Give the servers a moment to start accepting.
    for _ in 0..50 {
        if reqwest::get(format!("http://{addr_b}/.well-known/owney/server"))
            .await
            .is_ok()
        {
            break;
        }
        tokio::task::yield_now().await;
    }

    // --- data on A ----------------------------------------------------------
    let alice = storage_a
        .create_account("alice@a.test", None)
        .await
        .unwrap();
    let calendar = storage_a
        .create_calendar(alice.id, "Team".to_string(), None)
        .await
        .unwrap();
    let event = storage_a
        .create_calendar_event(
            calendar.id,
            "Standup".to_string(),
            Some("Daily".to_string()),
            1_000,
            2_000,
            None,
        )
        .await
        .unwrap();

    // Bob exists on B.
    let bob = storage_b.create_account("bob@b.test", None).await.unwrap();

    // --- A initiates the federated share (what calendar_share does) ---------
    let client_a = federation::build_client(&storage_a, "http://a.test", &fed_config)
        .await
        .expect("client a");
    let peer_b = federation::discover_and_pin(&storage_a, &client_a, "b.test", &fed_config)
        .await
        .expect("discover b");
    assert_eq!(peer_b.server_url, "http://b.test");

    let (federation_id, capability) = storage_a
        .create_outbound_federation(
            calendar.id,
            "bob@b.test",
            &peer_b.server_url,
            SharingType::Sharing,
            "b.test",
            &peer_b.fingerprint,
        )
        .await
        .unwrap();

    let invitation = federation::FederationInvitation {
        federation_id: federation_id.clone(),
        capability_secret: capability,
        calendar_name: "Team".to_string(),
        inviter_email: "alice@a.test".to_string(),
        target_email: "bob@b.test".to_string(),
        sharing_type: "sharing".to_string(),
        created_at: 0,
    };
    let body = serde_json::to_vec(&invitation).unwrap();
    let resp = client_a
        .post_json(
            &format!("{}/.well-known/owney/calendar/invite", peer_b.server_url),
            "b.test",
            &body,
        )
        .await
        .expect("send invite");
    assert!(
        resp.status().is_success(),
        "invite rejected: {}",
        resp.status()
    );

    // --- Bob accepts --------------------------------------------------------
    let pending = storage_b
        .list_pending_inbound_federations(bob.id)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1, "bob should have one pending invite");
    assert_eq!(pending[0].id, federation_id);
    let mirror_calendar_id = pending[0].calendar_id;
    storage_b
        .accept_inbound_federation(&federation_id, bob.id)
        .await
        .expect("accept");

    // --- Realtime push: A notifies, B pulls + applies -----------------------
    let enqueued = fed_worker::notify_calendar_changed(&storage_a, calendar.id)
        .await
        .expect("enqueue notify");
    assert_eq!(enqueued, 1);

    let notify_worker = fed_worker::NotifyWorker::new(
        storage_a.clone(),
        "http://a.test".to_string(),
        fed_config.clone(),
    );
    let delivered = notify_worker.drain_once().await.expect("drain");
    assert_eq!(delivered, 1, "notification should be delivered");

    // B now has the event in the mirror calendar, read-only, mapped by uid.
    let mirrored = storage_b
        .list_calendar_events_page(mirror_calendar_id, 0, String::new(), 100, false)
        .await
        .unwrap();
    assert_eq!(mirrored.len(), 1, "event should have synced to B");
    assert_eq!(mirrored[0].title, "Standup");
    assert_eq!(mirrored[0].description.as_deref(), Some("Daily"));

    // The remote uid (A's event id) maps to a *local* B event id — the
    // cross-tenant-safety invariant.
    let mapped = storage_b
        .federation_local_event(&federation_id, &event.id.to_string())
        .await
        .unwrap();
    assert_eq!(mapped, Some(mirrored[0].id));

    // --- authorization boundary over the wire -------------------------------
    // Unsigned request to A's serve endpoint is rejected.
    let unsigned = reqwest::get(format!(
        "http://{addr_a}/.well-known/owney/calendar/sync/{federation_id}"
    ))
    .await
    .unwrap();
    assert_eq!(unsigned.status().as_u16(), 401, "unsigned sync must be 401");

    // Signed by B (a pinned peer) but with the wrong capability → 403.
    let client_b = federation::build_client(&storage_b, "http://b.test", &fed_config)
        .await
        .unwrap();
    let bad_cap = client_b
        .get_capable(
            &format!("http://a.test/.well-known/owney/calendar/sync/{federation_id}"),
            "a.test",
            "not-the-capability",
        )
        .await
        .unwrap();
    assert_eq!(
        bad_cap.status().as_u16(),
        403,
        "wrong capability must be 403"
    );
}
