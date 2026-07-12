# Changelog

All notable changes to the `jmap-core` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive module-level documentation for `envelope`, `refs`, and `session` modules with examples
- Example: `examples/simple_server.rs` — a complete, production-quality JMAP server demonstrating HTTP integration, session discovery, and method dispatch
- Expanded `lib.rs` documentation: request flow, generic context type pattern, error handling, panic/timeout safety
- This changelog

### Changed
- Module documentation now includes detailed RFC 8620 references and practical examples
- Improved clarity on error types and their HTTP mappings (RequestError → 400, MethodError → inline)

### Status
- **API is frozen**: No breaking changes expected going forward
- **Ready for standalone publication** to crates.io once version 1.0.0 is released
- **Production-ready**: Used in Anthropic's mailserver project for core JMAP protocol handling

## [0.1.0] - 2026-07-10

### Added
- Initial release of `jmap-core`
- Core features:
  - Request envelope parsing and validation (RFC 8620 §3)
  - Method dispatch with generic async handler registration
  - Result reference resolution (RFC 8620 §3.7)
  - Capabilities and session object management (RFC 8620 §2)
  - Per-call timeout support via `Limits::max_call_duration`
  - Server limits enforcement (RFC 8620 §2)
  - Panic containment: panics in handlers surface as `MethodError::ServerFail`
  - Generic context type (`Ctx`) for embedder-provided state
- Comprehensive test suite covering:
  - Round-trip request/response
  - Capability validation
  - Result reference resolution (simple and wildcard paths)
  - Error handling (request-level and method-level)
  - Timeout and panic safety
  - Limit enforcement

---

## Notes for Downstream Users

- **No external dependencies beyond Tokio, Serde, and standard utilities**: Minimal dependency surface.
- **Framework-agnostic**: Integrate into any async HTTP framework (axum, actix, etc.)
- **License**: AGPL-3.0-only. Commercial use available under Anthropic's licensing agreement.
- **Documentation**: See `README.md` for overview, or `src/lib.rs` and module docs for API details.

## Future Considerations

- Potential conformance suite against IANA JMAP test vectors
- Performance benchmarks
- Streaming JSON parser for large requests (currently loads entire body in memory)
