//! A clean-room, framework-agnostic JMAP server core (RFC 8620).
//!
//! This crate handles the protocol-generic machinery — the request envelope,
//! method dispatch, result references, capabilities, and the session object —
//! and nothing else. Embedders register async method handlers against a
//! context type of their choosing; data types (RFC 8621 mail, etc.) live in
//! the embedder.
//!
//! ```
//! # use jmap_core::{Dispatcher, envelope::MethodError};
//! # use serde_json::json;
//! # tokio_test();
//! # fn tokio_test() {
//! # let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
//! # rt.block_on(async {
//! let mut dispatcher: Dispatcher<()> = Dispatcher::new("myserver");
//! dispatcher.register("Ping/ping", jmap_core::CORE_CAPABILITY, |_args, _ctx| async {
//!     Ok(json!({"pong": true}))
//! });
//!
//! let request = serde_json::from_value(json!({
//!     "using": ["urn:ietf:params:jmap:core"],
//!     "methodCalls": [["Ping/ping", {}, "c1"]],
//! })).unwrap();
//! let response = dispatcher.process(request, std::sync::Arc::new(())).await.unwrap();
//! assert_eq!(response.method_responses[0].1["pong"], json!(true));
//! # });
//! # }
//! ```

pub mod envelope;
pub mod refs;
pub mod session;

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

pub use envelope::{Invocation, MethodError, Request, RequestError, Response};
pub use session::Session;

pub const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";

/// Server limits, advertised in the session capability object and enforced
/// during processing (RFC 8620 §2).
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_size_upload: u64,
    pub max_concurrent_upload: u64,
    pub max_size_request: u64,
    pub max_concurrent_requests: u64,
    pub max_calls_in_request: usize,
    pub max_objects_in_get: usize,
    pub max_objects_in_set: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_size_upload: 50_000_000,
            max_concurrent_upload: 4,
            max_size_request: 10_000_000,
            max_concurrent_requests: 4,
            max_calls_in_request: 16,
            max_objects_in_get: 500,
            max_objects_in_set: 500,
        }
    }
}

impl Limits {
    /// The `urn:ietf:params:jmap:core` capability object.
    pub fn core_capability(&self) -> Value {
        serde_json::json!({
            "maxSizeUpload": self.max_size_upload,
            "maxConcurrentUpload": self.max_concurrent_upload,
            "maxSizeRequest": self.max_size_request,
            "maxConcurrentRequests": self.max_concurrent_requests,
            "maxCallsInRequest": self.max_calls_in_request,
            "maxObjectsInGet": self.max_objects_in_get,
            "maxObjectsInSet": self.max_objects_in_set,
            "collationAlgorithms": ["i;ascii-numeric", "i;ascii-casemap", "i;unicode-casemap"],
        })
    }
}

type BoxedHandler<Ctx> = Box<
    dyn Fn(Value, Arc<Ctx>) -> Pin<Box<dyn Future<Output = Result<Value, MethodError>> + Send>>
        + Send
        + Sync,
>;

/// The method registry and request processor. `Ctx` is the embedder's
/// per-request context (authenticated account, storage handles, ...).
pub struct Dispatcher<Ctx> {
    limits: Limits,
    /// capability urn → capability object (session `capabilities`).
    capabilities: BTreeMap<String, Value>,
    /// method name → (required capability, handler).
    methods: HashMap<String, (String, BoxedHandler<Ctx>)>,
    /// Opaque token bumped when server-side session-affecting config changes.
    session_state: String,
}

impl<Ctx> std::fmt::Debug for Dispatcher<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("methods", &self.methods.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<Ctx: Send + Sync + 'static> Dispatcher<Ctx> {
    pub fn new(session_state: impl Into<String>) -> Self {
        let limits = Limits::default();
        let mut dispatcher = Self {
            capabilities: BTreeMap::new(),
            methods: HashMap::new(),
            session_state: session_state.into(),
            limits,
        };
        dispatcher.capabilities.insert(
            CORE_CAPABILITY.to_owned(),
            dispatcher.limits.core_capability(),
        );
        dispatcher.register("Core/echo", CORE_CAPABILITY, |args, _ctx| async move {
            Ok(args)
        });
        dispatcher
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.capabilities
            .insert(CORE_CAPABILITY.to_owned(), limits.core_capability());
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Declare a capability (e.g. `urn:ietf:params:jmap:mail`) and its
    /// session capability object.
    pub fn add_capability(&mut self, urn: impl Into<String>, object: Value) {
        self.capabilities.insert(urn.into(), object);
    }

    pub fn capabilities(&self) -> &BTreeMap<String, Value> {
        &self.capabilities
    }

    /// Register a method handler. The capability must be declared (or be the
    /// core capability) before processing requests that use it.
    pub fn register<F, Fut>(
        &mut self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: F,
    ) where
        F: Fn(Value, Arc<Ctx>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, MethodError>> + Send + 'static,
    {
        let boxed: BoxedHandler<Ctx> = Box::new(move |args, ctx| Box::pin(handler(args, ctx)));
        self.methods
            .insert(method.into(), (capability.into(), boxed));
    }

    /// Process one JMAP request to completion.
    pub async fn process(&self, request: Request, ctx: Arc<Ctx>) -> Result<Response, RequestError> {
        if request.using.is_empty() {
            return Err(RequestError::NotRequest);
        }
        let mut seen = std::collections::HashSet::with_capacity(request.using.len());
        for capability in &request.using {
            if !seen.insert(capability.as_str()) {
                return Err(RequestError::NotRequest);
            }
            if !self.capabilities.contains_key(capability) {
                return Err(RequestError::UnknownCapability(capability.clone()));
            }
        }
        if request.method_calls.len() > self.limits.max_calls_in_request {
            return Err(RequestError::Limit("maxCallsInRequest"));
        }

        let mut responses: Vec<Invocation> = Vec::with_capacity(request.method_calls.len());
        for Invocation(name, arguments, call_id) in request.method_calls {
            let outcome = self
                .call(&name, arguments, &call_id, &responses, &request.using, &ctx)
                .await;
            match outcome {
                Ok(result) => responses.push(Invocation(name, result, call_id)),
                Err(err) => responses.push(err.invocation(&call_id)),
            }
        }

        Ok(Response {
            method_responses: responses,
            created_ids: request.created_ids.clone(),
            session_state: self.session_state.clone(),
        })
    }

    async fn call(
        &self,
        name: &str,
        arguments: Value,
        _call_id: &str,
        prior: &[Invocation],
        using: &[String],
        ctx: &Arc<Ctx>,
    ) -> Result<Value, MethodError> {
        let (capability, handler) = self.methods.get(name).ok_or(MethodError::UnknownMethod)?;
        if capability != CORE_CAPABILITY && !using.iter().any(|u| u == capability) {
            // Spec: using must list the capability of every invoked method.
            return Err(MethodError::UnknownMethod);
        }
        let arguments = refs::resolve_references(arguments, prior)?;
        handler(arguments, ctx.clone()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(body: Value) -> Request {
        serde_json::from_value(body).expect("request parses")
    }

    #[tokio::test]
    async fn echo_round_trips() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Core/echo", {"hello": "world"}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(
            response.method_responses[0],
            Invocation("Core/echo".into(), json!({"hello": "world"}), "c1".into())
        );
        assert_eq!(response.session_state, "s0");
    }

    #[tokio::test]
    async fn duplicate_using_is_rejected() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        let err = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY, CORE_CAPABILITY],
                    "methodCalls": [["Core/echo", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect_err("dup using");
        assert!(matches!(err, RequestError::NotRequest));
    }

    #[tokio::test]
    async fn empty_using_rejects_request() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        let err = dispatcher
            .process(
                request(json!({
                    "using": [],
                    "methodCalls": [["Core/echo", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect_err("empty using is invalid");
        assert!(matches!(err, RequestError::NotRequest));
    }

    #[tokio::test]
    async fn unknown_method_is_a_method_error() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Nope/get", {}, "c1"], ["Core/echo", {"ok": 1}, "c2"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(response.method_responses[0].name(), "error");
        assert_eq!(
            response.method_responses[0].arguments()["type"],
            "unknownMethod"
        );
        // Later calls still run.
        assert_eq!(response.method_responses[1].arguments()["ok"], 1);
    }

    #[tokio::test]
    async fn unknown_capability_fails_the_request() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        let err = dispatcher
            .process(
                request(json!({
                    "using": ["urn:example:nope"],
                    "methodCalls": [],
                })),
                Arc::new(()),
            )
            .await
            .expect_err("must fail");
        assert!(matches!(err, RequestError::UnknownCapability(_)));
        assert_eq!(
            err.problem_details()["type"],
            "urn:ietf:params:jmap:error:unknownCapability"
        );
    }

    #[tokio::test]
    async fn method_capability_must_be_in_using() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.add_capability("urn:example:mail", json!({}));
        dispatcher.register("Mailbox/get", "urn:example:mail", |_args, _ctx| async {
            Ok(json!({"list": []}))
        });

        // using lists only core — mail method must be rejected.
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Mailbox/get", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(
            response.method_responses[0].arguments()["type"],
            "unknownMethod"
        );

        // With the capability, it works.
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY, "urn:example:mail"],
                    "methodCalls": [["Mailbox/get", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(response.method_responses[0].arguments()["list"], json!([]));
    }

    #[tokio::test]
    async fn result_references_chain_between_calls() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.register("Thing/query", CORE_CAPABILITY, |_args, _ctx| async {
            Ok(json!({"ids": ["a", "b"]}))
        });
        dispatcher.register("Thing/get", CORE_CAPABILITY, |args, _ctx| async move {
            Ok(json!({"requested": args["ids"]}))
        });

        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [
                        ["Thing/query", {}, "c1"],
                        ["Thing/get", {"#ids": {"resultOf": "c1", "name": "Thing/query", "path": "/ids"}}, "c2"],
                    ],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(
            response.method_responses[1].arguments()["requested"],
            json!(["a", "b"])
        );
    }

    #[tokio::test]
    async fn too_many_calls_hits_the_limit() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0").with_limits(Limits {
            max_calls_in_request: 2,
            ..Limits::default()
        });
        let err = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [
                        ["Core/echo", {}, "c1"],
                        ["Core/echo", {}, "c2"],
                        ["Core/echo", {}, "c3"],
                    ],
                })),
                Arc::new(()),
            )
            .await
            .expect_err("limit");
        assert!(matches!(err, RequestError::Limit("maxCallsInRequest")));
    }

    #[tokio::test]
    async fn non_panicking_handler_runs_normally() {
        // Today a registered handler that does not panic returns its value to
        // the caller unchanged. Phase 3 will layer panic containment on top of
        // this path; this test locks the current behavior so that change can
        // be evaluated against a known baseline.
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.register("Thing/crash", CORE_CAPABILITY, |_args, _ctx| async {
            Ok(json!({}))
        });
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Thing/crash", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(response.method_responses[0].name(), "Thing/crash");
        // (A separate test in Phase 3 will replace this with a
        // MethodError::ServerFail expectation.)
    }

    #[tokio::test]
    async fn client_provided_created_ids_are_echoed() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Core/echo", {}, "c1"]],
                    "createdIds": {"c1": "u1"},
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        let echo = response.created_ids.expect("created_ids echoed");
        assert_eq!(echo["c1"], "u1");
    }

    #[tokio::test]
    async fn absent_client_created_ids_yields_none() {
        let dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Core/echo", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert!(response.created_ids.is_none());
    }
}
