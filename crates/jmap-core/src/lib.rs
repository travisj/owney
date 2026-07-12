//! A clean-room, framework-agnostic JMAP server core (RFC 8620).
//!
//! This crate handles the protocol-generic machinery — the request envelope,
//! method dispatch, result references, capabilities, and the session object —
//! and nothing else. Embedders register async method handlers against a
//! context type of their choosing; data types (RFC 8621 mail, etc.) live in
//! the embedder.
//!
//! # Overview
//!
//! [`Dispatcher`] is the main entry point. Create one, register method handlers,
//! and call [`Dispatcher::process`] to handle JMAP requests.
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
//!
//! # Request Flow
//!
//! The dispatcher processes JMAP requests through these stages:
//!
//! 1. **Validation** ([`Request`]): Verify the `using` capability list is non-empty,
//!    has no duplicates, and all capabilities are registered. Reject if any limit
//!    is exceeded (e.g., too many method calls).
//!
//! 2. **Dispatch**: For each method call in `methodCalls`:
//!    - Resolve any result references (`#key` arguments) to prior responses
//!      (see [`refs::resolve_references`]).
//!    - Look up the handler for the method name.
//!    - Call the handler with the resolved arguments and context.
//!    - Collect the result or error.
//!
//! 3. **Response Assembly** ([`Response`]): Build the response envelope with
//!    all method responses, session state, and any echoed `createdIds`.
//!
//! # The Generic Context Type (Ctx)
//!
//! Every handler receives an `Arc<Ctx>`, where `Ctx` is your own type. Use it
//! to carry:
//! - Authenticated user ID
//! - Database connections
//! - Rate limiters
//! - Tracing spans
//! - Feature flags
//! - Anything needed during request processing
//!
//! Example:
//!
//! ```ignore
//! #[derive(Clone)]
//! struct MyContext {
//!     user_id: String,
//!     db: Arc<Database>,
//!     rate_limiter: Arc<RateLimiter>,
//! }
//!
//! let mut dispatcher: Dispatcher<MyContext> = Dispatcher::new("v1");
//! dispatcher.register("Email/query", "urn:ietf:params:jmap:mail", |args, ctx| async move {
//!     // ctx.user_id, ctx.db, ctx.rate_limiter available here
//!     let account_id = args["accountId"].as_str().unwrap();
//!     ctx.db.query_emails(account_id, args).await
//! });
//! ```
//!
//! # Errors
//!
//! Two error types map to different response levels:
//!
//! - [`envelope::RequestError`]: Fails the entire request (RFC 8620 §3.6.1).
//!   Errors like unknown capability or exceeding limits.
//!   Returned as RFC 7807 problem-details with HTTP status 400.
//!
//! - [`envelope::MethodError`]: Fails a single method call (RFC 8620 §3.6.2).
//!   Appears inline in `methodResponses` as `["error", {type, description?}, callId]`.
//!   Returned as an [`Invocation`] with name `"error"`.
//!
//! # Panic Safety
//!
//! If a handler panics, the dispatcher catches it, logs it, and surfaces it
//! to the client as `MethodError::ServerFail`. Subsequent method calls in the
//! same request still execute.
//!
//! # Timeout Safety
//!
//! If [`Limits::max_call_duration`] is set, handlers that exceed it are
//! cancelled and return `MethodError::ServerFail` with a timeout message.
//! Ensure your handlers properly clean up on cancellation (use RAII guards).
//!
//! # Module Organization
//!
//! - [`envelope`]: Wire-level request/response types and method/request errors.
//! - [`refs`]: Result reference resolution (RFC 8620 §3.7).
//! - [`session`]: Session object construction (RFC 8620 §2).
//! - [`Dispatcher`] (this module): Method registration and request processing.

pub mod envelope;
pub mod refs;
pub mod session;

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;

use futures::FutureExt;
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
    pub max_call_duration: Option<std::time::Duration>,
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
            max_call_duration: None,
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
pub struct Dispatcher<Ctx: Send + Sync + 'static> {
    limits: Limits,
    /// capability urn → capability object (session `capabilities`).
    capabilities: BTreeMap<String, Value>,
    /// method name → (required capability, handler).
    methods: HashMap<String, (String, BoxedHandler<Ctx>)>,
    /// Opaque token bumped when server-side session-affecting config changes.
    session_state: String,
}

impl<Ctx: Send + Sync + 'static> std::fmt::Debug for Dispatcher<Ctx> {
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

    pub fn set_session_state(&mut self, state: impl Into<String>) {
        self.session_state = state.into();
    }

    /// Declare a capability (e.g. `urn:ietf:params:jmap:mail`) and its
    /// session capability object.
    pub fn add_capability(&mut self, urn: impl Into<String>, object: Value) {
        self.capabilities.insert(urn.into(), object);
    }

    pub fn capabilities(&self) -> &BTreeMap<String, Value> {
        &self.capabilities
    }

    /// Register a method handler under a slash-namespaced name (`"Mailbox/get"`,
    /// `"Email/set"`).
    ///
    /// The capability URN is automatically declared in the session (as an
    /// empty object) if it has not been declared before. Call
    /// [`Dispatcher::add_capability`] *before* `register` if you want the
    /// session capability object to advertise properties to clients.
    ///
    /// The handler receives the call's `arguments` [`Value`] (after all
    /// `#key` result references have been resolved by the dispatcher) and
    /// an [`Arc<Ctx>`] shared with the rest of the request.
    ///
    /// # Result-reference resolution
    ///
    /// Per RFC 8620 §3.7, the dispatcher replaces any `#foo` argument
    /// with the value extracted from the prior response matching
    /// `#foo.resultOf` × `#foo.path`. The handler sees the *resolved*
    /// arguments — it does not see `#foo` itself.
    ///
    /// # Cancellation safety
    ///
    /// The handler future may be cancelled by the dispatcher if a
    /// per-call timeout (see [`Limits::max_call_duration`]) elapses, or
    /// if the whole request is dropped. Handlers that hold locks or
    /// external resources must arrange to release them on cancellation
    /// (typically by holding them inside an RAII guard yielded by the
    /// future, not by side-effects of `.await`).
    ///
    /// # Panic safety
    ///
    /// A panic inside the handler is caught by the dispatcher and
    /// surfaced to the client as `MethodError::ServerFail`. Subsequent
    /// method calls in the same request still run.
    pub fn register<F, Fut>(
        &mut self,
        method: impl Into<String>,
        capability: impl Into<String>,
        handler: F,
    ) where
        F: Fn(Value, Arc<Ctx>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, MethodError>> + Send + 'static,
    {
        let cap: String = capability.into();
        if cap != CORE_CAPABILITY {
            self.capabilities
                .entry(cap.clone())
                .or_insert(Value::Object(Default::default()));
        }
        let boxed: BoxedHandler<Ctx> = Box::new(move |args, ctx| Box::pin(handler(args, ctx)));
        self.methods.insert(method.into(), (cap, boxed));
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
        let fut = async move {
            match self.limits.max_call_duration {
                Some(limit) => {
                    match tokio::time::timeout(limit, handler(arguments, ctx.clone())).await {
                        Ok(inner) => inner,
                        Err(_) => Err(MethodError::ServerFail("timeout".into())),
                    }
                }
                None => handler(arguments, ctx.clone()).await,
            }
        };
        match AssertUnwindSafe(fut).catch_unwind().await
        {
            Ok(value) => value,
            Err(panic) => {
                let msg = if let Some(s) = panic.downcast_ref::<&'static str>() {
                    (*s).to_owned()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "handler panicked".to_owned()
                };
                tracing::error!(method = %name, "handler panicked: {msg}");
                Err(MethodError::ServerFail(msg))
            }
        }
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
    async fn panicking_handler_becomes_server_fail() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.register("Thing/crash", CORE_CAPABILITY, |_args, _ctx| async {
            panic!("handler explosion");
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
        assert_eq!(response.method_responses[0].name(), "error");
        assert_eq!(
            response.method_responses[0].arguments()["type"],
            "serverFail"
        );
        assert!(response.method_responses[0].arguments()["description"]
            .as_str().unwrap().contains("handler explosion"));
    }

    #[tokio::test(start_paused = true)]
    async fn handler_exceeding_timeout_becomes_server_fail() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0").with_limits(Limits {
            max_call_duration: Some(std::time::Duration::from_millis(10)),
            ..Limits::default()
        });
        dispatcher.register("Thing/sleep", CORE_CAPABILITY, |_args, _ctx| async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok(json!({}))
        });
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Thing/sleep", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(
            response.method_responses[0].arguments()["type"], "serverFail",
        );
    }

    #[tokio::test]
    async fn subsequent_calls_run_after_a_panic() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.register("Thing/crash", CORE_CAPABILITY, |_args, _ctx| async { panic!("x") });
        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [
                        ["Thing/crash", {}, "c1"],
                        ["Core/echo", {"ok": 1}, "c2"],
                    ],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        assert_eq!(response.method_responses[0].name(), "error");
        assert_eq!(response.method_responses[1].name(), "Core/echo");
        assert_eq!(response.method_responses[1].arguments()["ok"], 1);
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

    #[tokio::test]
    async fn register_auto_declares_capability() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.register("Foo/get", "urn:example:auto", |_a, _c| async { Ok(json!({})) });
        assert!(dispatcher.capabilities().contains_key("urn:example:auto"));
    }

    #[tokio::test]
    async fn session_state_can_be_bumped() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.set_session_state("s1");
        let response = dispatcher.process(
            request(json!({"using": [CORE_CAPABILITY], "methodCalls": [["Core/echo", {}, "c1"]]})),
            Arc::new(()),
        ).await.expect("process");
        assert_eq!(response.session_state, "s1");
    }
}
