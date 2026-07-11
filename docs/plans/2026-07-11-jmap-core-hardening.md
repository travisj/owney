# jmap-core Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address the architecture, correctness, and implementer-facing gaps found in the `jmap-core` crate review: spec-noncompliant path evaluation, missing `created_ids` round-trip, unvalidated capability registration, fragile handler invocation, and implementer-facing documentation gaps — phased so each phase is independently shippable and downstream consumers (`ms-jmap-mail`, `ms-api`, `mailserverd`) keep compiling.

**Architecture:** Phase by severity. Phase 0 fixes existing test gaps; Phase 1 isolates spec compliance bugs that affect correctness today. Phase 2 introduces a new `MethodResult` return type that lets handlers return created-id maps without breaking existing handlers (a new variant alongside the existing `Result<Value, MethodError>` path). Phase 3 hardens robustness (panic containment, timeouts, bound tightening). Phase 4 documents the embedder contract end-to-end and adds tests for the JSON-pointer escape and edge cases. Every phase ends with `cargo test`, `cargo clippy -p jmap-core --all-targets -- -D warnings`, and `cargo doc -p jmap-core --no-deps` green.

**Tech Stack:** Rust 1.97, edition 2024, `serde`, `serde_json`, `thiserror`, `tokio` (dev-only). Workspace lints: `unsafe_code = forbid`, `missing_debug_implementations = warn`, `unwrap_used = warn` (allow in tests).

**Compatibility rule:** The crate's public API — `Dispatcher::new`, `register`, `add_capability`, `capabilities`, `with_limits`, `limits`, `process`, `CORE_CAPABILITY`, `Limits`, `Request`, `Response`, `Invocation`, `RequestError`, `MethodError`, `Session`, `Session::for_account` — must remain source-compatible with current downstream usage in `ms-api`, `ms-jmap-mail`, `bin/mailserverd`. Phase 2 is the one exception: it adds a new return type accepted by `register`, but the existing `Fn(Value, Arc<Ctx>) -> Future<Output = Result<Value, MethodError>>` shape must keep compiling.

---

## Phase 0 — Test infrastructure gaps (no behavior change)

Closes small holes in current test coverage so that later phases can rely on them.

### Task 0.1: Test that `Session` URL templates include the well-known placeholders

**Files:**
- Modify: `crates/jmap-core/src/session.rs:81-115` (existing test module)

**Step 1: Add failing assertions**

Extend the existing `session_shape` test in `crates/jmap-core/src/session.rs` with these assertions below the existing ones:

```rust
        assert!(value["uploadUrl"].as_str().unwrap().contains("{accountId}"));
        assert!(value["downloadUrl"].as_str().unwrap().contains("{blobId}"));
        assert!(value["eventSourceUrl"].as_str().unwrap().contains("{types}"));
```

**Step 2: Run the test**

Run: `cargo test -p jmap-core session::tests::session_shape`
Expected: PASS (these are positive assertions over current behavior, locking in placeholders).

**Step 3: Commit**

```bash
git add crates/jmap-core/src/session.rs
git commit -m "test(jmap-core): assert session url templates carry placeholders"
```

### Task 0.2: Test JSON-pointer escape handling in path evaluation

**Files:**
- Modify: `crates/jmap-core/src/refs.rs:110-184` (test module)

**Step 1: Add failing test for `/` and `~` in keys**

Add to the existing `tests` module in `crates/jmap-core/src/refs.rs`:

```rust
    #[test]
    fn json_pointer_escapes() {
        let prior = vec![Invocation(
            "Foo/get".to_owned(),
            json!({"data": {"a/b": 1, "c~d": 2}}),
            "c0".to_owned(),
        )];
        let args = json!({
            "#v": {"resultOf": "c0", "name": "Foo/get", "path": "/data/a~1b"},
        });
        let resolved = resolve_references(args, &prior()).expect("resolve");
        assert_eq!(resolved["v"], json!(1));

        let args = json!({
            "#v": {"resultOf": "c0", "name": "Foo/get", "path": "/data/c~0d"},
        });
        let resolved = resolve_references(args, &prior).expect("resolve");
        assert_eq!(resolved["v"], json!(2));
    }
```

**Step 2: Run it**

Run: `cargo test -p jmap-core refs::tests::json_pointer_escapes`
Expected: PASS — the existing code already does the right thing on line 88 of `refs.rs` (`replace("~1", "/").replace("~0", "~")`). This task just locks the behavior in.

**Step 3: Commit**

```bash
git add crates/jmap-core/src/refs.rs
git commit -m "test(jmap-core): cover json-pointer escapes in path eval"
```

### Task 0.3: Test handler panic containment contract today (documents current behavior)

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:220-380` (test module)

**Step 1: Add a test that captures current behavior**

This documents what happens today so Phase 3 can change it knowingly.

```rust
    #[tokio::test]
    async fn panicking_handler_is_currently_unhandled() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        // Wrap the panic in spawn; the dispatcher itself does not catch it yet.
        dispatcher.register("Thing/crash", CORE_CAPABILITY, |_args, _ctx| async {
            // returns normally; a future caller can still panic from outside
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
```

**Step 2: Run it**

Run: `cargo test -p jmap-core tests::panicking_handler_is_currently_unhandled`
Expected: PASS.

**Step 3: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "test(jmap-core): document current handler-panic behavior"
```

---

## Phase 1 — Spec compliance bugs

Fixes that change observable behavior today. Each task is TDD.

### Task 1.1: Implement `*` against objects in result-reference paths

**Files:**
- Modify: `crates/jmap-core/src/refs.rs:78-108`
- Modify: `crates/jmap-core/src/refs.rs:110-184` (test module)

**Step 1: Add the failing test**

In `crates/jmap-core/src/refs.rs`, extend the `prior()` helper in the test module to add an object value, and add this test:

```rust
    fn prior_with_object() -> Vec<Invocation> {
        vec![Invocation(
            "Foo/list".to_owned(),
            json!({
                "by_tag": {
                    "important": ["id1", "id2"],
                    "spam": ["id3"],
                }
            }),
            "c0".to_owned(),
        )]
    }

    #[test]
    fn wildcard_against_object_flattens_values() {
        let args = json!({
            "#ids": {"resultOf": "c0", "name": "Foo/list", "path": "/by_tag/*"},
        });
        let resolved = resolve_references(args, &prior_with_object()).expect("resolve");
        // Per RFC 8620 §3.7: wildcard on an object applies to all values
        // and flattens one level of arrays.
        assert_eq!(resolved["ids"], json!(["id1", "id2", "id3"]));
    }
```

**Step 2: Run it to verify it fails**

Run: `cargo test -p jmap-core refs::tests::wildcard_against_object_flattens_values`
Expected: FAIL with `InvalidResultReference("path /by_tag/* not found")` (today `eval_tokens` returns `None` for objects).

**Step 3: Implement**

In `crates/jmap-core/src/refs.rs`, change the `match value` block in `eval_tokens` so it includes an object wildcard branch before the `Value::Object` fall-through:

```rust
        Value::Object(map) if token == "*" => {
            let mut flattened = Vec::new();
            for (_k, item) in map {
                match eval_tokens(item, rest)? {
                    Value::Array(inner) => flattened.extend(inner),
                    other => flattened.push(other),
                }
            }
            Some(Value::Array(flattened))
        }
        Value::Object(map) => eval_tokens(map.get(token.as_str())?, rest),
        _ => None,
```

(This replaces the existing object branch — the wildcard branch must be *before* the indexed lookup because both arms destructure `Value::Object`.)

**Step 4: Run tests**

Run: `cargo test -p jmap-core`
Expected: PASS, all 12 tests + 3 new ones in Phase 0 + this one (16 total).

**Step 5: Commit**

```bash
git add crates/jmap-core/src/refs.rs
git commit -m "fix(jmap-core): wildcard against object in result references (RFC 8620 §3.7)"
```

### Task 1.2: Reject empty `using`

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:172-199`
- Modify: `crates/jmap-core/src/lib.rs:220-380` (test module)

**Step 1: Add failing test**

```rust
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
```

**Step 2: Run it**

Run: `cargo test -p jmap-core tests::empty_using_rejects_request`
Expected: FAIL — currently the dispatcher accepts an empty `using` and proceeds.

**Step 3: Implement**

In `crates/jmap-core/src/lib.rs`, in `process`, before the capability loop, add:

```rust
        if request.using.is_empty() {
            return Err(RequestError::NotRequest);
        }
```

**Step 4: Run tests**

Run: `cargo test -p jmap-core`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "fix(jmap-core): reject empty `using` per RFC 8620 §3.1"
```

### Task 1.3: Reject duplicate `using` URNs

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:172-199`
- Modify: `crates/jmap-core/src/lib.rs:220-380` (test module)

**Step 1: Failing test**

```rust
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
```

**Step 2: Run**

Run: `cargo test -p jmap-core tests::duplicate_using_is_rejected`
Expected: FAIL.

**Step 3: Implement**

Right after the `is_empty` check from Task 1.2:

```rust
        let mut seen = std::collections::HashSet::with_capacity(request.using.len());
        for capability in &request.using {
            if !seen.insert(capability.as_str()) {
                return Err(RequestError::NotRequest);
            }
            if !self.capabilities.contains_key(capability) {
                return Err(RequestError::UnknownCapability(capability.clone()));
            }
        }
```

Then remove the now-redundant `for capability in &request.using` loop above this code.

**Step 4: Run tests**

Run: `cargo test -p jmap-core`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "fix(jmap-core): reject duplicate capability URNs in using"
```

### Task 1.4: Tighten `ResultReference` deserialization to `deny_unknown_fields`

**Files:**
- Modify: `crates/jmap-core/src/refs.rs:11-17`

**Step 1: Add failing test**

```rust
    #[test]
    fn reference_with_unknown_field_is_an_error() {
        let args = json!({
            "#ids": {"resultOf": "c0", "name": "Foo/query", "path": "/ids", "extra": 1},
        });
        assert!(matches!(
            resolve_references(args, &prior()),
            Err(MethodError::InvalidResultReference(_))
        ));
    }
```

**Step 2: Run**

Run: `cargo test -p jmap-core refs::tests::reference_with_unknown_field_is_an_error`
Expected: FAIL — today `serde_json` silently drops `extra`.

**Step 3: Implement**

In `crates/jmap-core/src/refs.rs`, change:

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResultReference {
```

**Step 4: Run tests**

Run: `cargo test -p jmap-core`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/jmap-core/src/refs.rs
git commit -m "fix(jmap-core): deny unknown fields in result references per RFC 8620 §3.7"
```

---

## Phase 2 — `created_ids` round-trip (the blocker)

RFC 8620 requires `Foo/set` handlers to mint server IDs and have them appear in `Response.created_ids`. Today `Dispatcher::process` sets `created_ids: None` unconditionally. This phase widens the handler contract while preserving source compatibility.

### Task 2.1: Introduce a `MethodResult` enum

**Files:**
- Modify: `crates/jmap-core/src/envelope.rs`

**Step 1: Add the type**

Append to `crates/jmap-core/src/envelope.rs` (before the closing `#[cfg(test)]`):

```rust
/// What a method handler returns. `Data` carries a plain result; `Set`
/// additionally carries a `created[accountId][creationId] = id` map which
/// the dispatcher merges into the response's `created_ids` (RFC 8620 §3.6.2).
#[derive(Debug, Clone)]
pub enum MethodResult {
    Data(Value),
    Set {
        value: Value,
        created: BTreeMap<String, BTreeMap<String, String>>,
    },
}

impl From<Value> for MethodResult {
    fn from(value: Value) -> Self { MethodResult::Data(value) }
}
```

**Step 2: Build**

Run: `cargo check -p jmap-core`
Expected: succeeds; the new type is unused so far.

**Step 3: Commit**

```bash
git add crates/jmap-core/src/envelope.rs
git commit -m "feat(jmap-core): add MethodResult enum for set-style handlers"
```

### Task 2.2: Widen `BoxedHandler` to accept both return types

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:90-170`

We keep the existing `Fn(Value, Arc<Ctx>) -> Fut` shape working (source-compatible with `ms-jmap-mail`) and add an alternate path via a trait. Rust closures don't natively support “returns either A or B”, so we use a small sealed conversion.

**Step 1: Add a helper trait**

In `crates/jmap-core/src/lib.rs`, after `Limits`, add:

```rust
mod sealed {
    pub trait IntoMethodResult {
        type Fut: std::future::Future<Output = Result<super::MethodResult, super::MethodError>> + Send + 'static;
        fn into_handler(self, args: serde_json::Value, ctx: std::sync::Arc<()>) -> Self::Fut;
    }
}
```

Wait — we can't parameterize the trait over `Ctx` here without re-architecting. Use an explicit blanket implementation per-handler via the existing closure mechanism instead. Take the simpler path:

**Replace Steps 1–3 above with:**

**Step 1: Add a free function**

```rust
use envelope::MethodResult;

pub type BoxedHandler<Ctx> = Box<
    dyn Fn(Value, Arc<Ctx>) -> Pin<Box<dyn Future<Output = Result<MethodResult, MethodError>> + Send>>
        + Send
        + Sync,
>;
```

Replace the existing definition (lib.rs:90-94) with this. Existing closures returning `Result<Value, MethodError>` will no longer compile against this signature — **but a blanket `From` impl in Step 2 makes the migration seamless**, since `Result<Value, MethodError>` can be lifted into `Result<MethodResult, MethodError>` automatically with one coercion wrapper.

**Step 2: Blanket conversion**

Closure-handlers today return `Result<Value, MethodError>`. We give them a free `From` via two impls: convert a future returning `Value` into a future returning `MethodResult::Data(value)`, and convert `Result<Value, MethodError>` into `Result<MethodResult, MethodError>` via `From`.

We do this by changing **`register`**'s signature to accept any handler whose future output converts into `Result<MethodResult, MethodError>`.

```rust
impl<Ctx> Dispatcher<Ctx> {
    pub fn register<F, Fut, R>(&mut self, method: impl Into<String>, capability: impl Into<String>, handler: F)
    where
        F: Fn(Value, Arc<Ctx>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: Into<Result<MethodResult, MethodError>> + 'static,
    {
        let boxed: BoxedHandler<Ctx> = Box::new(move |args, ctx| {
            Box::pin(async move { handler(args, ctx).await.into() })
        });
        self.methods.insert(method.into(), (capability.into(), boxed));
    }
}
```

And add, in `envelope.rs`:

```rust
impl From<Result<Value, MethodError>> for Result<MethodResult, MethodError> {
    fn from(r: Result<Value, MethodError>) -> Self {
        r.map(MethodResult::Data)
    }
}
```

**Step 3: Verify downstream compiles unchanged**

Run: `cargo build --workspace`
Expected: succeeds. `ms-jmap-mail` handlers return `Result<Value, MethodError>` — the blanket lifts them. `ms-api` and `bin/mailserverd` are unaffected (they only call `process`).

**Step 4: Run all tests**

Run: `cargo test --workspace`
Expected: all tests pass.

**Step 5: Commit**

```bash
git add crates/jmap-core/src/lib.rs crates/jmap-core/src/envelope.rs
git commit -m "feat(jmap-core): handlers can return MethodResult; existing Value handlers still compile"
```

### Task 2.3: Merge `created_ids` into the response in `process`

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:172-220`

**Step 1: Update the `process` body to handle `MethodResult::Set`**

```rust
        let mut responses: Vec<Invocation> = Vec::with_capacity(request.method_calls.len());
        let mut created_ids: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for Invocation(name, arguments, call_id) in request.method_calls {
            let outcome = self
                .call(&name, arguments, &call_id, &responses, &request.using, &ctx)
                .await;
            match outcome {
                Ok(MethodResult::Data(result)) => {
                    responses.push(Invocation(name, result, call_id))
                }
                Ok(MethodResult::Set { value, created }) => {
                    for (account, by_creation) in created {
                        created_ids.entry(account).or_default().extend(by_creation);
                    }
                    responses.push(Invocation(name, value, call_id))
                }
                Err(err) => responses.push(err.invocation(&call_id)),
            }
        }

        let mut created_ids_out = request.created_ids.clone().unwrap_or_default();
        for (account, by_creation) in created_ids {
            created_ids_out.entry(account).or_default().extend(by_creation);
        }
        let created_ids = if created_ids_out.is_empty() { None } else { Some(created_ids_out) };

        Ok(Response { method_responses: responses, created_ids, session_state: self.session_state.clone() })
```

(Use `Out::or_default()`-style API; the `BTreeMap` entry API used here matches.)

**Step 2: Add a failing test**

In `crates/jmap-core/src/lib.rs`:

```rust
    #[tokio::test]
    async fn method_result_set_merges_created_ids() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.register("Foo/set", CORE_CAPABILITY, |_args, _ctx| async move {
            Ok::<_, MethodError>(MethodResult::Set {
                value: json!({"updated": {}, "created": {"c1": "id1"}}),
                created: [
                    ("a1".to_owned(), [("c1".to_owned(), "id1".to_owned())].into_iter().collect()),
                ].into_iter().collect(),
            })
        });

        let response = dispatcher
            .process(
                request(json!({
                    "using": [CORE_CAPABILITY],
                    "methodCalls": [["Foo/set", {}, "c1"]],
                })),
                Arc::new(()),
            )
            .await
            .expect("process");
        let created = response.created_ids.expect("created_ids present");
        assert_eq!(created["a1"]["c1"], "id1");
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
        assert_eq!(response.created_ids.expect("created_ids")["c1"], "u1");
    }
```

**Step 3: Run**

Run: `cargo test -p jmap-core tests::method_result_set_merges_created_ids tests::client_provided_created_ids_are_echoed`
Expected: PASS.

**Step 4: Run all tests**

Run: `cargo test --workspace`
Expected: PASS (downstream tests in `ms-jmap-mail` and `ms-api` still pass — they don't yet use `MethodResult::Set`).

**Step 5: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "feat(jmap-core): round-trip created_ids through the dispatcher (RFC 8620 §3.6.2)"
```

### Task 2.4: Wire `ms-jmap-mail` `Foo/set` handlers to return `MethodResult::Set`

**Files:**
- Modify: `crates/ms-jmap-mail/src/lib.rs` (the `email_set` function around line 321, `submission_set` around line 593, and any other `Set` result producers)
- Modify: `crates/ms-jmap-mail/src/lib.rs` `register` function (line 33-58)

**Step 1: Update the registered `Email/set` handler**

In `crates/ms-jmap-mail/src/lib.rs`, change `email_set`'s signature and body so it returns `MethodResult`:

- Change the function signature to return `Result<jmap_core::MethodResult, jmap_core::MethodError>`.
- Move the existing `json!({ "created": ..., "updated": ..., ... })` body into `MethodResult::Data(value)` first.
- Then add a `created` `BTreeMap` whose key is the `accountId` (from args), and whose inner map is `creationId → serverId`. Hoist the `"created"` map at line 321 (the `result.created` variable near line 321) into the `created` field.

The resulting return is:

```rust
Ok(jmap_core::MethodResult::Set {
    value: json!({ /* the existing result object */ }),
    created: [(account_id.to_owned(), result.created)].into_iter().collect(),
})
```

(Adjust `result.created` to be a `BTreeMap<String, String>` rather than a `serde_json::Map` if it isn't already.)

**Step 2: Update `Submission/set` similarly**

The handler at line 593 (`submission_set`) has its own `created` map. Wire the same `MethodResult::Set { ... }` return.

**Step 3: Run ms-jmap-mail tests**

Run: `cargo test -p ms-jmap-mail`
Expected: PASS. The end-to-end test at `crates/ms-jmap-mail/tests/mail_methods.rs` exercises `EmailSubmission/set`. Add an assertion to that file that `response.created_ids` includes the expected maps.

```rust
let responses = ...; // existing
// After the EmailSubmission/set call add:
assert_eq!(created["account_id"], ..., "expected createdIds for submission");
```

**Step 4: Run all tests**

Run: `cargo test --workspace`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/ms-jmap-mail
git commit -m "feat(ms-jmap-mail): return MethodResult::Set from Email/set and EmailSubmission/set"
```

---

## Phase 3 — Robustness

### Task 3.1: Push `Ctx: Send + Sync + 'static` bound up to the struct definition

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:96-218`

**Step 1: Move the bound**

Currently:

```rust
impl<Ctx: Send + Sync + 'static> Dispatcher<Ctx> {
    pub fn new(...) -> Self { ... }
    ...
}
```

Change to:

```rust
pub struct Dispatcher<Ctx: Send + Sync + 'static> { ... }

impl<Ctx: Send + Sync + 'static> Dispatcher<Ctx> { ... }
```

(The `Debug` impl also has the same constraint that needs to be checked — it doesn't today, but `&self.methods` works for any `Ctx`. Leave it.)

**Step 2: Build**

Run: `cargo build --workspace`
Expected: succeeds.

**Step 3: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "refactor(jmap-core): move Ctx bounds to struct for clearer failure modes"
```

### Task 3.2: Contain handler panics into `MethodError::ServerFail`

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:201-218` (the `call` method)
- Modify: `crates/jmap-core/src/lib.rs:220-380` (test module)

**Step 1: Add the failure test**

Replace the `panicking_handler_is_currently_unhandled` test from Phase 0:

```rust
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
```

**Step 2: Run to verify failure**

Run: `cargo test -p jmap-core tests::panicking_handler_becomes_server_fail`
Expected: FAIL with `thread '<unnamed>' panicked` (today's behavior — the panic escapes process and surfaces as a `JoinError`-style failure or test panic).

**Step 3: Implement**

Add to `crates/jmap-core/src/lib.rs`:

```rust
use std::panic::AssertUnwindSafe;
use futures::FutureExt; // optional — can avoid with std::panic::catch_unwind on FutureExt
```

We can avoid adding a `futures` dependency by using `tokio::task::JoinHandle` with `abort_handle` or by relying on the `AssertUnwindSafe` + `Future::catch_unwind` future trait method. The latter is in `std::future::FutureExt` only in unstable; the *pinned*, *sendable* un-winder is `futures::FutureExt`. Add `futures` to dev-dependencies only and implement the wrapper inline in `call`. (See Task 3.3 for the timeout wrapper, which is similar.)

A clean alternative that needs no new dependency:

```rust
        // call() body
        let span = tracing::Span::current(); // or a fresh one
        let args2 = arguments.clone();
        let handler = AssertUnwindSafe(handler);
        let fut = async move { handler(args2, ctx.clone()).await };
        let outcome = AssertUnwindSafe(fut).catch_unwind().await;
```

Add `futures = "0.3"` to `[dev-dependencies]` (and re-export via `pub` if needed for embedders — keep `dev` for now). Use `futures::FutureExt`.

```rust
        let outcome = AssertUnwindSafe(handler(arguments, ctx.clone()))
            .catch_unwind()
            .await;
        match outcome {
            Ok(Ok(MethodResult::Data(v))) => Ok(MethodResult::Data(v)),
            Ok(Ok(MethodResult::Set { value, created })) => Ok(MethodResult::Set { value, created }),
            Ok(Err(e)) => Err(e),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<&'static str>().map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "handler panicked".into());
                tracing::error!(method = %name, "handler panicked: {msg}");
                Err(MethodError::ServerFail(msg))
            }
        }
```

Update `Cargo.toml`:

```toml
[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }
futures = "0.3"
```

(futures is small; tracing is already in workspace deps.)

**Step 4: Run tests**

Run: `cargo test -p jmap-core`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/jmap-core/src/lib.rs crates/jmap-core/Cargo.toml
git commit -m "fix(jmap-core): contain handler panics into MethodError::ServerFail"
```

### Task 3.3: Add optional per-call timeout

**Files:**
- Modify: `crates/jmap-core/src/lib.rs` (add `max_call_duration: Option<Duration>` to `Limits`)
- Modify: `crates/jmap-core/src/lib.rs` (wrap handler await with `tokio::time::timeout`)

**Step 1: Add failing test**

```rust
    #[tokio::test(start_paused = true)]
    async fn handler_exceeding_timeout_becomes_server_fail() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0")
            .with_limits(Limits { max_call_duration: Some(std::time::Duration::from_millis(10)), ..Limits::default() });
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
```

**Step 2: Run**

Run: `cargo test -p jmap-core tests::handler_exceeding_timeout_becomes_server_fail`
Expected: FAIL (no timeout exists).

**Step 3: Implement**

Add `max_call_duration: Option<Duration>` to `Limits` with a `Default` of `None`. Wrap the `handler(arguments, ctx.clone()).await` from Task 3.2 with `tokio::time::timeout(self.limits.max_call_duration, ...)`. On timeout, return `Err(MethodError::ServerFail("timeout".into()))`.

**Step 4: Run tests**

Run: `cargo test -p jmap-core`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "feat(jmap-core): optional per-call timeout via Limits::max_call_duration"
```

### Task 3.4: Enforce `register`-after-`add_capability` ordering

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:158-170`
- Modify: `crates/jmap-core/src/lib.rs:220-380` (test module)

**Step 1: Failing test**

```rust
    #[tokio::test]
    async fn registering_under_unknown_capability_panics() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        // No prior add_capability("urn:example:foo").
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatcher.register("Foo/get", "urn:example:foo", |_a, _c| async { Ok(json!({})) });
        }));
        assert!(result.is_err(), "register must validate capability is declared");
    }
```

(Tests are allowed to use `catch_unwind`; workspace clippy permits `unwrap_used` in tests.)

**Step 2: Run**

Run: `cargo test -p jmap-core tests::registering_under_unknown_capability_panics`
Expected: FAIL (today the silent accept).

**Step 3: Implement**

Change the body of `register` to:

```rust
    pub fn register<F, Fut, R>(&mut self, method: impl Into<String>, capability: impl Into<String>, handler: F)
    where ... {
        let cap: String = capability.into();
        if cap != crate::CORE_CAPABILITY && !self.capabilities.contains_key(&cap) {
            panic!(
                "register: capability {cap:?} not declared via Dispatcher::add_capability first"
            );
        }
        // ... existing body, using `cap` directly
    }
```

Also expose an automatic-declare variant for ergonomics, since downstream callers in `ms-jmap-mail` use plain `add_capability` then `register` already (see `bin/mailserverd/src/main.rs` at line 467 and `ms-jmap-mail/src/lib.rs` line 33). Verify by reading:

- `crate/ms-jmap-mail/src/lib.rs` declares the capability in `register` (`add_capability` first, then each method). Confirmed earlier.
- `bin/mailserverd/src/main.rs:467` constructs a `Dispatcher::new("0")` and then registers methods — it must be updated to call `add_capability` for any non-core capability first, or we make `register` auto-declare. **Auto-declare** is more ergonomic and matches the existing call sites' behavior. Use that:

Change to:

```rust
        let cap: String = capability.into();
        if cap != crate::CORE_CAPABILITY {
            self.capabilities.entry(cap.clone()).or_insert(serde_json::json!({}));
        }
```

And update the failing test to assert auto-declare instead of panic:

```rust
    #[tokio::test]
    async fn register_auto_declares_capability() {
        let mut dispatcher: Dispatcher<()> = Dispatcher::new("s0");
        dispatcher.register("Foo/get", "urn:example:auto", |_a, _c| async { Ok(json!({})) });
        assert!(dispatcher.capabilities().contains_key("urn:example:auto"));
    }
```

Replace Task 3.4's failing test above with this one. The behavior matches current downstream usage so `mailserverd/src/main.rs:467` and `ms-jmap-mail/src/lib.rs:33` continue to compile and behave identically. Document this in a doc-comment on `register`.

**Step 4: Run tests**

Run: `cargo test --workspace`
Expected: PASS.

**Step 5: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "refactor(jmap-core): auto-declare capability on register; document contract"
```

---

## Phase 4 — Embedder documentation

### Task 4.1: Write a "writing a handler" guide doc-comment on `Dispatcher::register`

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:156-170`

**Step 1: Expand the doc-comment**

Replace the one-liner above `register` with:

```rust
    /// Register a method handler under the given slash-namespaced name
    /// (`"Mailbox/get"`, `"Email/set"`). The capability URN is
    /// automatically declared in the session if not already present; pass
    /// the capability object itself via `add_capability` *before* calling
    /// `register` if you want it to advertise properties to clients.
    ///
    /// The handler receives the call's `arguments` Value (after `#key`
    /// result references have already been resolved by the dispatcher) and
    /// an `Arc<Ctx>` shared with the rest of the request. The handler
    /// future must be cancellation-safe — the dispatcher may cancel it on
    /// timeout or dispatcher shutdown. Returning
    /// `Ok(MethodResult::Set { .. })` is required for `*\/set` handlers
    /// that mint server-side creation IDs; returning `Ok(value)` is
    /// equivalent to `Ok(MethodResult::Data(value))`.
```

**Step 2: Build docs**

Run: `cargo doc -p jmap-core --no-deps`
Expected: succeeds, warnings about broken links are tolerable but no errors.

**Step 3: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "docs(jmap-core): expand register doc-comment for implementers"
```

### Task 4.2: Add a module-level guide to `envelope.rs`

**Files:**
- Modify: `crates/jmap-core/src/envelope.rs:1-2`

**Step 1: Replace the module doc**

Replace the first two lines with:

```rust
//! The JMAP request/response envelope (RFC 8620 §3).
//!
//! - [`Request`] / [`Response`] are the wire-level types — `using` lists
//!   the capability URNs the request uses; `methodCalls` and
//!   `methodResponses` are parallel arrays of [`Invocation`]s.
//! - [`Invocation`] is `(name, arguments, callId)`. For responses the
//!   name is either the original method name (success) or `"error"`
//!   (failure), with arguments typed by [`MethodError`].
//! - [`RequestError`] is request-level and maps to an HTTP 400 with an
//!   RFC 7807 problem-details body (see [`RequestError::problem_details`]).
//! - [`MethodError`] is method-level; it appears inline in
//!   `methodResponses` as `["error", {type, description?}, callId]`.
//! - [`MethodResult`] is what handlers return. `Set` variants carry a
//!   `created` map which the dispatcher merges into the response's
//!   `createdIds` (RFC 8620 §3.6.2).
```

**Step 2: Build docs**

Run: `cargo doc -p jmap-core --no-deps`
Expected: succeeds.

**Step 3: Commit**

```bash
git add crates/jmap-core/src/envelope.rs
git commit -m "docs(jmap-core): module-level guide for envelope types"
```

### Task 4.3: Add a module-level guide to `session.rs`

**Files:**
- Modify: `crates/jmap-core/src/session.rs:1-2`

**Step 1: Replace the module doc**

```rust
//! The JMAP session object (RFC 8620 §2), served at `/.well-known/jmap`.
//!
//! [`Session`] is what clients `GET` to discover a server's capabilities,
//! accounts, and URLs. [`Session::for_account`] builds the single-account
//! shape; servers that support more than one account build [`Session`]
//! directly. URL templates use `{placeholder}` syntax that the client
//! fills in (e.g. `{accountId}`, `{blobId}`); see RFC 8620 §2 for the
//! complete list and `downloadUrl`/`uploadUrl` shape.
```

**Step 2: Build docs**

Run: `cargo doc -p jmap-core --no-deps`
Expected: succeeds.

**Step 3: Commit**

```bash
git add crates/jmap-core/src/session.rs
git commit -m "docs(jmap-core): module-level guide for Session types"
```

### Task 4.4: Add `set_session_state` setter

**Files:**
- Modify: `crates/jmap-core/src/lib.rs:117-130`

**Step 1: Add the method**

```rust
    pub fn set_session_state(&mut self, state: impl Into<String>) {
        self.session_state = state.into();
    }
```

**Step 2: Add test**

```rust
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
```

**Step 3: Run**

Run: `cargo test -p jmap-core tests::session_state_can_be_bumped`
Expected: PASS.

**Step 4: Commit**

```bash
git add crates/jmap-core/src/lib.rs
git commit -m "feat(jmap-core): add Dispatcher::set_session_state"
```

---

## Verification (run after every phase)

Run these from the repo root:

```bash
cargo check --workspace
cargo test --workspace
cargo clippy -p jmap-core --all-targets -- -D warnings
cargo doc -p jmap-core --no-deps
```

All must succeed with no errors or warnings (clippy is denied warnings on `jmap-core` specifically). The crate must remain `unsafe_code`-free, `MissingDebugImplementations`-free, and `unwrap_used`-free outside tests.

## Reference: RFC 8620 sections cited

- §2 — session resource: `Session`, `Session::for_account`, `Limits::core_capability`.
- §3.1 — request shape: `Request::using`.
- §3.6.1 — request-level errors: `RequestError`.
- §3.6.2 — method-level errors and `created`: `MethodError`, `MethodResult::Set`, response `createdIds`.
- §3.7 — result references: `refs::resolve_references`, `refs::eval_tokens` (wildcard against arrays and objects).
