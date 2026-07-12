# jmap-core

A clean-room, framework-agnostic JMAP server library implementing RFC 8620 (JSON Meta Application Protocol).

## What It Is

`jmap-core` is the protocol foundation for building JMAP servers. It handles the machinery that every JMAP implementation needs: request envelope parsing and validation, method dispatch, result references, capabilities negotiation, and session objects. It does *not* define mail data types, storage schemas, or how to authenticate users — those are your domain, plugged into `jmap-core` as async handlers.

Think of it as a blank canvas with the frame already painted. You bring your storage layer, your business logic, your authentication scheme. `jmap-core` ensures the JMAP protocol machinery works correctly.

## Philosophy

**Framework-agnostic.** No opinions about async runtimes, web frameworks, or storage engines. Write your handlers as plain Rust async functions. Embed `jmap-core` into `tokio`, `actix`, `axum`, or async-std servers equally well.

**Protocol-only.** No data types beyond the wire format. No opinions about `Mailbox`, `Email`, `Contact`, or any RFC 8621+ extension — those live in your crate or upstream. `jmap-core` is pure JMAP plumbing.

**Zero internal dependencies.** No coupling to the mailserver project it started in. Standalone publication-ready. Minimal public API surface.

**Handlers as values.** Every async method handler is just a `Fn(Value, Arc<Ctx>) -> impl Future<Output = Result<Value, MethodError>>`. Your context type `Ctx` carries authenticated accounts, database handles, rate-limit counters, or whatever you need.

## Features

- **Request envelope parsing** (RFC 8620 §3): Validates `using` capability list, parses method calls as `[name, arguments, callId]` triples.
- **Method dispatch** with panic containment: Register async handlers by name. Panics inside handlers surface as `MethodError::ServerFail`, not crashes. Subsequent method calls still run.
- **Result references** (RFC 8620 §3.7): Clients can reference prior response values via `#key` arguments. The dispatcher resolves paths like `/ids`, `/list/*/emailIds` before your handler sees them.
- **Capabilities and session objects** (RFC 8620 §2): Register capabilities with their advertised properties. Generate RFC-compliant session objects for client discovery.
- **Per-call timeouts**: Optional `max_call_duration` enforced by the dispatcher.
- **Server limits**: Enforce `maxCallsInRequest`, `maxObjectsInGet`, `maxObjectsInSet`, etc. Configurable via `Limits`.
- **Generic context type**: Your handlers receive an `Arc<Ctx>` — any type you define. Share database connections, rate limiters, feature flags, or tracing spans.

## Who It's For

JMAP server implementers who want:
- A reliable, minimal foundation that handles the protocol correctly
- Freedom to choose their runtime and architecture
- Clean separation between plumbing and business logic
- No framework lock-in

**Not** for:
- Clients (use a JMAP client library)
- Email clients specifically (look for JMAP Mail / RFC 8621)
- Traditional REST API servers (JMAP is not REST)

## Quick Example

Register a `Ping/ping` method and dispatch a request:

```rust
use jmap_core::{Dispatcher, CORE_CAPABILITY};
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mut dispatcher: Dispatcher<()> = Dispatcher::new("session-v1");
    
    // Register a ping method
    dispatcher.register("Ping/ping", CORE_CAPABILITY, |_args, _ctx| async {
        Ok(json!({"pong": true}))
    });
    
    // Build a request
    let request = serde_json::from_value(json!({
        "using": ["urn:ietf:params:jmap:core"],
        "methodCalls": [["Ping/ping", {}, "call-1"]],
    })).unwrap();
    
    // Process it
    let response = dispatcher.process(request, Arc::new(())).await.unwrap();
    
    // The response contains [name, result, callId] for each call
    assert_eq!(response.method_responses[0].arguments()["pong"], json!(true));
    println!("Session: {}", response.session_state);
}
```

For a complete working server example with HTTP and stdin, see `examples/simple_server.rs`.

## RFC 8620 Coverage

| Feature | Status |
|---------|--------|
| Request/response envelope | ✓ Complete |
| Method dispatch | ✓ Complete |
| Capabilities | ✓ Complete |
| Session object | ✓ Complete |
| Result references | ✓ Complete (§3.7) |
| Core limits | ✓ Complete (maxCallsInRequest, maxSizeRequest, etc.) |
| Server-defined errors | ✓ Complete |
| Halt on type error | ✓ (per RFC §3.1.1) |
| Per-call timeout | ✓ Optional (new in M0) |
| Panic containment | ✓ Complete |
| Mail extension (RFC 8621) | Not in scope (implement upstream) |
| Calendar (RFC 8625) | Not in scope |
| Contacts (RFC 8626) | Not in scope |

## Testing & Conformance

Currently `jmap-core` tests itself via unit tests in `src/lib.rs` covering:
- Basic round-trip (request → response)
- Capability negotiation and unknown capabilities
- Result reference resolution (simple and wildcard paths)
- Method-level and request-level error handling
- Panic containment and timeout enforcement
- Limit enforcement

A future conformance suite (IANA JMAP test vectors or similar) will validate against the RFC.

## Building & Publishing

### Standalone Build

```bash
cargo build -p jmap-core
cargo test -p jmap-core
```

### Publishing to crates.io

When ready for publication:

```bash
# Verify no workspace dependencies
grep -v "workspace = true" crates/jmap-core/Cargo.toml | grep path= || echo "No path deps"

# Bump version in workspace root (applies to all crates)
# Run from mailserver root:
cargo set-version -p jmap-core X.Y.Z

# Publish
cargo publish -p jmap-core --registry crates-io
```

### License & Commercial Use

`jmap-core` is licensed under **AGPL-3.0-only** (see `LICENSE` in the repository root).

**Closed-source or proprietary use**: Anthropic offers commercial license agreements that allow use under more permissive terms. If you're building a commercial JMAP server, contact Anthropic for licensing options.

## Contributing

This library intentionally has a minimal scope. Before proposing new features:
- Check if they belong in an extension capability (RFC 8621, 8625, 8626, etc.)
- Verify they aren't application logic (belongs in your handler)
- Ensure they're core to every JMAP implementation

Bug fixes, documentation, and examples are always welcome.

## See Also

- [RFC 8620 — JSON Meta Application Protocol (JMAP)](https://tools.ietf.org/html/rfc8620)
- [RFC 8621 — JMAP for Mail](https://tools.ietf.org/html/rfc8621)
- [JMAP Specifications](https://jmap.io/spec.html)
- For a complete server example using this crate, see `examples/simple_server.rs`

---

**Status**: Stable API, ready for standalone publication. Actively maintained as part of the Anthropic mailserver project.
