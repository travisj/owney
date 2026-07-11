//! JMAP push: the EventSource stream (RFC 8620 §7.3) and the WebSocket
//! binding (RFC 8887). Both bridge the in-process event bus to clients; push
//! is a hint — clients recover the truth via `/changes`, which is why lagged
//! receivers are simply skipped.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use ms_core::AccountId;
use ms_events::Event;
use serde_json::{Value, json};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::{ApiState, JmapCtx, authenticate};

/// The `urn:ietf:params:jmap:websocket` capability object for the session.
pub fn websocket_capability(public_url: &str) -> Value {
    let ws_url = public_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    json!({
        "url": format!("{}/jmap/ws", ws_url.trim_end_matches('/')),
        "supportsPush": true,
    })
}

/// The push payload for one state change (RFC 8620 §7.1).
fn state_change_json(
    account_id: AccountId,
    changed: &[(ms_core::DataType, ms_core::ModSeq)],
) -> Value {
    let types: serde_json::Map<String, Value> = changed
        .iter()
        .map(|(data_type, modseq)| {
            (
                data_type.as_str().to_owned(),
                Value::String(modseq.to_string()),
            )
        })
        .collect();
    json!({
        "@type": "StateChange",
        "changed": { account_id.to_string(): types },
    })
}

pub async fn eventsource(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let account = authenticate(&state, &headers).await?;
    let account_id = account.id;

    let stream = BroadcastStream::new(state.events.subscribe()).filter_map(move |event| {
        let event = event.ok()?; // lagged: drop, clients resync via /changes
        match &*event {
            Event::StateChange {
                account_id: changed_account,
                changed,
            } if *changed_account == account_id => {
                let payload = state_change_json(account_id, changed);
                Some(Ok::<_, Infallible>(
                    SseEvent::default().event("state").data(payload.to_string()),
                ))
            }
            _ => None,
        }
    });

    Ok(Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(30))
                .event(SseEvent::default().event("ping").data("{}")),
        )
        .into_response())
}

pub async fn websocket(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, Response> {
    let account = authenticate(&state, &headers).await?;
    Ok(upgrade
        .protocols(["jmap"])
        .on_upgrade(move |socket| handle_socket(socket, state, account)))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<ApiState>, account: ms_storage::Account) {
    let account_id = account.id;
    let ctx = Arc::new(JmapCtx {
        account,
        storage: state.storage.clone(),
        submitter: state.submitter.clone(),
    });
    let mut bus = state.events.subscribe();
    let mut push_enabled = false;

    loop {
        tokio::select! {
            message = socket.recv() => {
                let Some(Ok(message)) = message else { break };
                match message {
                    Message::Text(text) => {
                        let reply = handle_frame(&state, &ctx, text.as_str(), &mut push_enabled).await;
                        if let Some(reply) = reply
                            && socket.send(Message::text(reply.to_string())).await.is_err()
                        {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            event = bus.recv() => {
                match event {
                    Ok(event) => {
                        if push_enabled
                            && let Event::StateChange { account_id: changed, changed: types } = &*event
                            && *changed == account_id
                        {
                            let payload = state_change_json(account_id, types);
                            if socket.send(Message::text(payload.to_string())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

/// One inbound WebSocket frame → optional reply frame (RFC 8887 §4).
async fn handle_frame(
    state: &ApiState,
    ctx: &Arc<JmapCtx>,
    text: &str,
    push_enabled: &mut bool,
) -> Option<Value> {
    let request_error = |detail: &str| {
        Some(json!({
            "@type": "RequestError",
            "type": "urn:ietf:params:jmap:error:notRequest",
            "status": 400,
            "detail": detail,
        }))
    };

    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return request_error("frame is not JSON");
    };
    match value.get("@type").and_then(Value::as_str) {
        Some("Request") => {
            let request_id = value.get("id").cloned();
            let Ok(request) = serde_json::from_value::<jmap_core::Request>(value) else {
                return request_error("not a JMAP request");
            };
            match state.dispatcher.process(request, ctx.clone()).await {
                Ok(response) => {
                    let mut reply = serde_json::to_value(&response).unwrap_or_else(|_| json!({}));
                    reply["@type"] = json!("Response");
                    if let Some(id) = request_id {
                        reply["requestId"] = id;
                    }
                    Some(reply)
                }
                Err(err) => {
                    let mut problem = err.problem_details();
                    problem["@type"] = json!("RequestError");
                    Some(problem)
                }
            }
        }
        Some("WebSocketPushEnable") => {
            *push_enabled = true;
            None
        }
        Some("WebSocketPushDisable") => {
            *push_enabled = false;
            None
        }
        _ => request_error("unknown @type"),
    }
}
