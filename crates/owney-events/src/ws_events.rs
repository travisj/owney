//! WebSocket real-time event broadcasting.
//!
//! Events flow: internal EventBus → WsEventBroadcaster → WebSocket clients
//! Non-blocking async with tokio::sync::broadcast for efficient fan-out.

use crate::Event;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::broadcast;

/// WebSocket event wrapper with metadata.
#[derive(Debug, Clone)]
pub struct WsEvent {
    /// Event type (for client routing: "email.created", "chat.delivered", "contact.updated", etc.)
    pub event_type: String,
    /// Account ID (for filtering)
    pub account_id: String,
    /// Event data as JSON
    pub payload: serde_json::Value,
}

impl WsEvent {
    /// Convert internal Event to WebSocket event.
    pub fn from_event(event: &Event) -> Vec<WsEvent> {
        match event {
            Event::StateChange { account_id, changed } => {
                let mut events = Vec::new();
                for (data_type, modseq) in changed {
                    events.push(WsEvent {
                        event_type: format!("{}.changed", data_type.as_str().to_lowercase()),
                        account_id: account_id.to_string(),
                        payload: json!({
                            "type": data_type.as_str(),
                            "modseq": modseq.0
                        }),
                    });
                }
                events
            }
            Event::Delivery {
                account_id,
                submission_id,
                status,
            } => {
                vec![WsEvent {
                    event_type: "delivery.status".to_string(),
                    account_id: account_id.to_string(),
                    payload: json!({
                        "submission_id": submission_id.to_string(),
                        "status": format!("{:?}", status)
                    }),
                }]
            }
            Event::Ai {
                account_id,
                skill,
                action_id,
                summary,
            } => {
                vec![WsEvent {
                    event_type: "ai.action".to_string(),
                    account_id: account_id.to_string(),
                    payload: json!({
                        "skill": skill,
                        "action_id": action_id.to_string(),
                        "summary": summary
                    }),
                }]
            }
            Event::Security {
                account_id,
                kind,
                detail,
            } => {
                vec![WsEvent {
                    event_type: "security.event".to_string(),
                    account_id: account_id.as_ref().map(|a| a.to_string()).unwrap_or_default(),
                    payload: json!({
                        "kind": format!("{:?}", kind),
                        "detail": detail
                    }),
                }]
            }
            Event::DoctorCheck(check) => {
                vec![WsEvent {
                    event_type: "doctor.check".to_string(),
                    account_id: String::new(), // Doctor checks are system-wide
                    payload: json!({
                        "check": check.check,
                        "status": check.status,
                        "message": check.message,
                        "checked_at": check.checked_at
                    }),
                }]
            }
        }
    }
}

/// Broadcast channel for WebSocket events. Each account has its own channel.
#[derive(Debug)]
pub struct WsEventBroadcaster {
    /// Broadcast sender (shared across all clients for this account)
    tx: broadcast::Sender<WsEvent>,
}

impl WsEventBroadcaster {
    /// Create a new broadcaster (typically one per account).
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel::<WsEvent>(1000); // 1000-event buffer
        Self { tx }
    }

    /// Broadcast an event to all connected clients.
    pub fn broadcast(&self, event: WsEvent) {
        // Fire-and-forget; dropped messages are OK (clients reconnect)
        let _ = self.tx.send(event);
    }

    /// Subscribe a new client to events for this account.
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.tx.subscribe()
    }

    /// Number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for WsEventBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

/// Global registry of broadcasters (one per account).
/// In production, this would be arc'd and managed by the server.
#[derive(Debug)]
pub struct WsRegistry {
    broadcasters: std::collections::HashMap<String, Arc<WsEventBroadcaster>>,
}

impl WsRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self {
            broadcasters: std::collections::HashMap::new(),
        }
    }

    /// Get or create a broadcaster for an account.
    pub fn get_or_create(&mut self, account_id: &str) -> Arc<WsEventBroadcaster> {
        self.broadcasters
            .entry(account_id.to_string())
            .or_insert_with(|| Arc::new(WsEventBroadcaster::new()))
            .clone()
    }
}

impl Default for WsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owney_core::DataType;

    #[test]
    fn ws_event_from_state_change() {
        use owney_core::AccountId;
        let account_id = AccountId::new();
        let event = Event::StateChange {
            account_id,
            changed: vec![(DataType::Email, owney_core::ModSeq(42))],
        };

        let ws_events = WsEvent::from_event(&event);
        assert_eq!(ws_events.len(), 1);
        assert_eq!(ws_events[0].event_type, "email.changed");
        assert_eq!(ws_events[0].account_id, account_id.to_string());
    }

    #[tokio::test]
    async fn broadcaster_subscribe_and_send() {
        let broadcaster = WsEventBroadcaster::new();
        let mut rx = broadcaster.subscribe();

        let event = WsEvent {
            event_type: "test.event".to_string(),
            account_id: "acc-1".to_string(),
            payload: json!({"data": "test"}),
        };

        broadcaster.broadcast(event.clone());

        let received = rx.recv().await.expect("should receive event");
        assert_eq!(received.event_type, "test.event");
        assert_eq!(received.account_id, "acc-1");
    }

    #[test]
    fn registry_multiple_accounts() {
        let mut registry = WsRegistry::new();

        let bc1 = registry.get_or_create("acc-1");
        let bc2 = registry.get_or_create("acc-2");
        let bc1_again = registry.get_or_create("acc-1");

        // Same account should return same broadcaster
        assert_eq!(Arc::as_ptr(&bc1), Arc::as_ptr(&bc1_again));
        // Different accounts should be different
        assert_ne!(Arc::as_ptr(&bc1), Arc::as_ptr(&bc2));
    }
}
