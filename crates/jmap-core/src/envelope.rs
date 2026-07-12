//! The JMAP request/response envelope (RFC 8620 §3).
//!
//! This module defines the wire-level types for JMAP requests and responses,
//! plus the error types that map to different HTTP and protocol responses.
//!
//! # Request & Response
//!
//! - [`Request`] is the wire-level request type (RFC 8620 §3.1).
//!   - `using`: A list of capability URNs the client intends to use.
//!   - `method_calls`: A parallel array of [`Invocation`]s (method name,
//!     arguments, call ID).
//!   - `created_ids`: (Optional) A map of call ID to server-generated IDs
//!     to be echoed back in the response (RFC 8620 §3.6.1).
//!
//! - [`Response`] is the wire-level response type (RFC 8620 §3.2).
//!   - `method_responses`: A parallel array of [`Invocation`]s, one per call.
//!     If a call failed, the invocation name is `"error"` (see [`MethodError`]).
//!   - `created_ids`: (Optional, if the request provided it) echoed unchanged.
//!   - `session_state`: An opaque token. If this changes between requests,
//!     clients should refetch the session via `GET /.well-known/jmap`.
//!
//! # Request vs. Method Errors
//!
//! - [`RequestError`]: Fails the entire request at the HTTP level (RFC 8620 §3.6.1).
//!   Returned as RFC 7807 problem-details with HTTP 400.
//!   - Unknown capability in `using`
//!   - Malformed request structure
//!   - Server limit exceeded (maxCallsInRequest, etc.)
//!
//! - [`MethodError`]: Fails a single method call (RFC 8620 §3.6.2).
//!   Appears inline in `methodResponses` as:
//!   ```json
//!   ["error", {
//!     "type": "unknownMethod",
//!     "description": "..."  // optional, only for some types
//!   }, "call-id"]
//!   ```
//!
//! # Invocation
//!
//! [`Invocation`] is a `[name, arguments, callId]` triple that appears
//! in both `methodCalls` (request) and `methodResponses` (response).
//! In responses, if the method call failed, `name` is `"error"` and
//! `arguments` is the error object.
//!
//! # Example Flow
//!
//! Client sends:
//! ```json
//! {
//!   "using": ["urn:ietf:params:jmap:core"],
//!   "methodCalls": [
//!     ["Ping/ping", {"clientData": 42}, "c1"],
//!     ["Core/echo", {"hello": "world"}, "c2"]
//!   ]
//! }
//! ```
//!
//! Server responds:
//! ```json
//! {
//!   "methodResponses": [
//!     ["Ping/ping", {"pong": true}, "c1"],
//!     ["Core/echo", {"hello": "world"}, "c2"]
//!   ],
//!   "sessionState": "s42"
//! }
//! ```
//!
//! If `Ping/ping` fails:
//! ```json
//! {
//!   "methodResponses": [
//!     ["error", {"type": "serverFail", "description": "..."}, "c1"],
//!     ["Core/echo", {"hello": "world"}, "c2"]
//!   ],
//!   "sessionState": "s42"
//! }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One method call or response: `[name, arguments, callId]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invocation(pub String, pub Value, pub String);

impl Invocation {
    pub fn name(&self) -> &str {
        &self.0
    }
    pub fn arguments(&self) -> &Value {
        &self.1
    }
    pub fn call_id(&self) -> &str {
        &self.2
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// Capability URNs the client intends to use.
    pub using: Vec<String>,
    pub method_calls: Vec<Invocation>,
    #[serde(default)]
    pub created_ids: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub method_responses: Vec<Invocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_ids: Option<BTreeMap<String, String>>,
    pub session_state: String,
}

/// Request-level errors (RFC 8620 §3.6.1), returned as RFC 7807 problem
/// details with HTTP status 400.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("unknown capability: {0}")]
    UnknownCapability(String),
    #[error("the request did not parse as a valid JMAP request")]
    NotRequest,
    #[error("request exceeds a server limit: {0}")]
    Limit(&'static str),
}

impl RequestError {
    pub fn urn(&self) -> &'static str {
        match self {
            RequestError::UnknownCapability(_) => "urn:ietf:params:jmap:error:unknownCapability",
            RequestError::NotRequest => "urn:ietf:params:jmap:error:notRequest",
            RequestError::Limit(_) => "urn:ietf:params:jmap:error:limit",
        }
    }

    /// RFC 7807 problem-details body.
    pub fn problem_details(&self) -> Value {
        let mut details = serde_json::json!({
            "type": self.urn(),
            "status": 400,
            "detail": self.to_string(),
        });
        if let RequestError::Limit(limit) = self {
            details["limit"] = Value::String((*limit).to_owned());
        }
        details
    }
}

/// Method-level errors (RFC 8620 §3.6.2): `["error", {type}, callId]`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MethodError {
    #[error("unknown method")]
    UnknownMethod,
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
    #[error("invalid result reference: {0}")]
    InvalidResultReference(String),
    #[error("forbidden")]
    Forbidden,
    #[error("account not found")]
    AccountNotFound,
    #[error("account does not support this method")]
    AccountNotSupportedByMethod,
    #[error("account is read-only")]
    AccountReadOnly,
    #[error("cannot calculate changes from the given state")]
    CannotCalculateChanges,
    #[error("requested state does not match current state")]
    StateMismatch,
    #[error("server failure: {0}")]
    ServerFail(String),
}

impl MethodError {
    pub fn type_name(&self) -> &'static str {
        match self {
            MethodError::UnknownMethod => "unknownMethod",
            MethodError::InvalidArguments(_) => "invalidArguments",
            MethodError::InvalidResultReference(_) => "invalidResultReference",
            MethodError::Forbidden => "forbidden",
            MethodError::AccountNotFound => "accountNotFound",
            MethodError::AccountNotSupportedByMethod => "accountNotSupportedByMethod",
            MethodError::AccountReadOnly => "accountReadOnly",
            MethodError::CannotCalculateChanges => "cannotCalculateChanges",
            MethodError::StateMismatch => "stateMismatch",
            MethodError::ServerFail(_) => "serverFail",
        }
    }

    /// The `["error", ...]` invocation for this failure.
    pub fn invocation(&self, call_id: &str) -> Invocation {
        let mut args = serde_json::json!({ "type": self.type_name() });
        let description = self.to_string();
        // Only include descriptions that add information beyond the type.
        if matches!(
            self,
            MethodError::InvalidArguments(_)
                | MethodError::InvalidResultReference(_)
                | MethodError::ServerFail(_)
        ) {
            args["description"] = Value::String(description);
        }
        Invocation("error".to_owned(), args, call_id.to_owned())
    }
}
