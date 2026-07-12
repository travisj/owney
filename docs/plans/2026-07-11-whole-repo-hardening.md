# mailserver: Whole-Repo Hardening Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bring the entire `mailserver` workspace (12 crates, ~8,500 lines of Rust) to a reviewable, RFC-compliant, security-hardened state. Each phase ships a self-contained set of fixes that passes its own tests, clippy, and integration coverage without breaking downstream crates.

**Architecture:** Six phases, organized by blast radius (foundation → data → auth → mail-protocols → API/AI → documentation/polish). Each phase includes a verification step that locks in correctness before the next phase starts. Within each phase, tasks are independent when possible and cherry-picked into the same commit when coupled.

**Tech Stack:** Rust 1.97, edition 2024. Workspace lints: `unsafe_code = forbid`, `missing_debug_implementations = warn`, `unwrap_used = warn` (allowed in tests via `clippy.toml`). RFCs covered: 8620 (JMAP core), 8621 (JMAP mail), 5321/5322 (SMTP/MIME), 6376 (DKIM), 7489 (DMARC), 7208 (SPF), 8461 (MTA-STS), 7672 (DANE), 8617 (ARC), 5321 §5.1 (MX routing), 3460/3461 (DSN), 3156 (PGP/MIME), 9883 (WKD/Autocrypt), 6750/7235 (HTTP auth), 8887 (JMAP WS push), 1036 (DNS), 7396 (MDN), 7807 (problem-details).

---

## Global conventions for every phase

- Each task is TDD: failing test first (or asserting documented behavior), then minimal code, then verify pass.
- Each commit message follows `<type>(<crate>): <verb> <description>`.
- Verification command for every task: `cargo test -p <crate> && cargo clippy -p <crate> --all-targets -- -D warnings`. Workspace-wide verification at each phase end.
- Branch per phase: `hardening/phase-<N>-<slug>`. Squash-merge to main.
- Out-of-scope items deferred to phases below are flagged as `[defer]`.

---

## Phase 0 — Foundation hygiene (kill tech debt before anything else)

Rationale: many of the issues found in downstream crates are *caused* by gaps in `ms-core` (the "firewall" crate they depend on). Fix the foundation first; downstream reviews get shorter as the foundation hardens. Each task is small, isolated, and brings one clippy-warning or one typed-id gap to closure.

| # | Task | Files | Estimated effort |
|---|------|-------|---|
| 0.1 | Push `Ctx: Send + Sync + 'static` bounds — already done in jmap-core; mirror this style across `ms-api` if similar bindings exist | — | 0 |
| 0.2 | Re-home `Submitter` from `ms-core` (lib.rs) to `ms-delivery`; re-export from `ms-core` for backward compat | `crates/ms-core/src/lib.rs`, `crates/ms-delivery/Cargo.toml`, `bin/mailserverd/src/main.rs` | 0.5 d |
| 0.3 | Add typed ids: `CreateId(String)` and `EmailSubmissionId(Uuid)` to `ms-core::id` via the existing `uuid_id!` macro | `crates/ms-core/src/id.rs` | 0.25 d |
| 0.4 | `ModSeq::next` → `Option<Self>` (or saturating variant) + test at `u64::MAX` boundary | `crates/ms-core/src/id.rs` | 0.25 d |
| 0.5 | `InvalidBlobId` → split variants (`TooShort`/`TooLong`/`NonHex{index}`); document case-sensitivity in `Display` (uppercase in, lowercase out — pick one and codify) | `crates/ms-core/src/id.rs` | 0.25 d |
| 0.6 | `BlobId::to_hex` → `impl fmt::LowerHex` (avoid per-write allocation) | `crates/ms-core/src/id.rs` | 0.25 d |
| 0.7 | `DataType::EmailSubmission` — decide scope (per-account global today; per-identity tomorrow). Document the constraint and add `#[non_exhaustive]` on `DataType` | `crates/ms-core/src/id.rs` | 0.25 d |
| 0.8 | `Config::validate` — tighten regex (or honest rename to `looks_dnsish`); add `#[deny_unknown_fields]` regression test for the typo-friendly path | `crates/ms-core/src/config.rs` | 0.5 d |
| 0.9 | `Config::load` tests for the four failure paths (missing, permission-denied, parse, validate) | `crates/ms-core/src/config.rs` + new tests | 0.5 d |
| 0.10 | Add `BadInput` variant to `StorageError`; `enqueue` should reject malformed recipients with `BadInput`, not `Corrupt` | `crates/ms-storage/src/error.rs`, `crates/ms-storage/src/queue.rs` | 0.25 d |
| 0.11 | Pre-existing clippy warning in `crates/ms-mcp/src/lib.rs:102` (`let id = id.unwrap();`) → `let Some(id) = id else { return None };` (drives workspace-wide `-D warnings`) | `crates/ms-mcp/src/lib.rs` | 0.1 d |
| 0.12 | Fix rustdoc HTML warning at `crates/ms-core/src/config.rs:68` (backtick the `<hostname>` template literal) | `crates/ms-core/src/config.rs` | 0.1 d |

**End-of-phase verification**:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps
```

All four must be green. After Phase 0 the workspace has zero clippy warnings and the foundation crate's type safety is consistent.

---

## Phase 1 — Storage correctness (the most critical non-protocol work)

Rationale: `ms-storage` is the persistence layer everyone depends on. The storage review surfaced:
- One **real correctness defect** that wasn't flagged as Critical: `Db::call` panics become silent failures because the writer thread's connection is left in an unspecified state.
- Several type-safety leaks (`String` where typed ids should be) that defeat the foundation work in Phase 0.
- Modseq/event discipline that's correct but undocumented.

Done sequentially because each task touches the same files.

| # | Task | Files | Estimated effort |
|---|------|-------|---|
| 1.1 | **`Db::call` panic containment.** Wrap the writer thread's `job(&mut conn)` body in `std::panic::catch_unwind(AssertUnwindSafe(...))`. Roll back the transaction defensively. Send the panic back to the caller as `StorageError::WriterPanicked` (new variant). Test: a closure that panics returns Err, not poison; subsequent calls succeed. | `crates/ms-storage/src/db.rs`, `crates/ms-storage/src/error.rs` | 0.5 d |
| 1.2 | **Type-safe row mappings.** `MailboxRow.id: MailboxId`, `EmailRow.id: EmailId`, `ThreadId: ThreadId`, `BlobId: BlobId`, `AiAction.email_id: Option<EmailId>`, `ChangesResult.{created,updated}: Vec<EmailId>`, etc. Add typed-id newtypes where missing (`ThreadId`, `EmailId` — both already exist in `ms-core` but `mail_queries.rs` uses `String`). | `crates/ms-storage/src/mail_queries.rs`, `crates/ms-storage/src/ai_store.rs`, `crates/ms-storage/src/queue.rs`, `crates/ms-storage/src/pgp_store.rs` | 1 d |
| 1.3 | **Modseq rollback discipline** — test that mid-transaction rollback does NOT advance modseq. Currently `ingest.rs:454-476` tests the happy path; add a test where the second INSERT fails and verify the modseq reverts. | `crates/ms-storage/src/ingest.rs` + tests | 0.5 d |
| 1.4 | **`changes_since` regression test.** Drive storage through a series of mutations and verify the bucket boundaries (`created` vs `updated`, `hasMoreChanges`, exact `since` semantics). JMAP delta sync is too important to lack a regression test. | `crates/ms-storage/tests/integration.rs` (new) | 1 d |
| 1.5 | **`reset_stale_claims` test.** Simulate a stuck `sending` row, run the recovery, confirm transition to `queued`. | `crates/ms-storage/src/queue.rs` + tests | 0.25 d |
| 1.6 | **`create_account` concurrent-call test.** Two parallel `create_account` for the same email — one wins, one gets `Err`. | `crates/ms-storage/src/lib.rs` + tests | 0.25 d |
| 1.7 | **Atomic `put_blob` dedup** — replace early-return-on-exists with `INSERT ... ON CONFLICT DO NOTHING`. Removes a TOCTOU race in `lib.rs:196-211`. | `crates/ms-storage/src/lib.rs`, `crates/ms-storage/src/blob.rs` | 0.5 d |
| 1.8 | **`blob.write_atomically` durability.** Add `dir.sync_all()` after rename to match `master.key` durability. | `crates/ms-storage/src/blob.rs` | 0.25 d |
| 1.9 | **Master-key file mode guard.** Test that `keys.rs:45` produces a `0o600` master key. | `crates/ms-storage/src/keys.rs` + test | 0.25 d |
| 1.10 | **Resolve-thread forward-linkage bug.** `ingest.rs:307-327` doc-claims the SQL handles "messages that reference this one" but doesn't. Either implement (`SELECT id FROM emails WHERE message_id = ?`) or trim the comment. | `crates/ms-storage/src/ingest.rs` | 0.25 d |
| 1.11 | **Table-name interpolation guard.** `mail_queries.rs:225` formats a SQL string with a `table` name. Add a `match` table to `&'static str`; remove the `format!`. | `crates/ms-storage/src/mail_queries.rs` | 0.25 d |
| 1.12 | **Optimize `query_emails`.** Replace the three-statement count + page + state query with a single CTE using `count(*) OVER ()` and `OFFSET/LIMIT`. | `crates/ms-storage/src/mail_queries.rs` | 0.25 d |
| 1.13 | **Optimize `mailboxes()`.** Replace scalar subqueries for `total_emails`/`unread_emails` with a `LEFT JOIN email_mailbox … GROUP BY m.id`. | `crates/ms-storage/src/mail_queries.rs` | 0.25 d |
| 1.14 | **`ai_store.rs:147-154` O(N) lookup.** Add `WHERE id = ?1` index lookup. | `crates/ms-storage/src/ai_store.rs` | 0.1 d |
| 1.15 | **`due_queue_items` monotonicity comment.** Document that the writer task enforces at-least-once semantics via the `status='sending'` filter. | `crates/ms-storage/src/queue.rs` | 0.1 d |
| 1.16 | **Document the `Storage` trait decision.** Either introduce a `trait Storage: Send + Sync` (large refactor — *not now*) or document explicitly that the concrete struct is the API. Either is acceptable; pick one and document. | `crates/ms-storage/src/lib.rs` (module doc) | 0.25 d |

**End-of-phase verification**:

```bash
cargo test -p ms-storage
cargo test --workspace   # confirm no downstream regressions
cargo clippy --workspace --all-targets -- -D warnings
```

`tests/` directory created. `cargo test -p ms-storage` exercises both happy paths (already covered) and a real failure-injection test matrix. Downstream crates still pass.

---

## Phase 2 — Auth hardening (typed envelope + ARC awareness + cache + timeouts)

Rationale: `ms-authn` is the smallest "real" auth crate at ~457 LoC. Fixes here are independent and high-leverage. The two highest-impact changes (typed `AuthVerdict` and ARC chain exposure) are the biggest lift; the rest are minor.

| # | Task | Files | Estimated effort |
|---|------|-------|---|
| 2.1 | **Typed `AuthVerdict`.** Replace each `String` status field with a typed enum: `SpfStatus`, `DkimStatus`, `DmarcStatus` (`{Pass, Fail{reason}, TempError{cause}, PermError{cause}, None}`), `ArcStatus`. Keep `summary()` and `authentication_results()` for serialization. Update `ms-delivery` and `ms-smtp-in` consumers. | `crates/ms-authn/src/lib.rs`, downstream consumers | 2 d |
| 2.2 | **ARC chain exposure.** `arc: String` → `arc: Vec<ArcInstance>` with `{ i: u32, cv: ArcStatus, as_count: usize, seal_valid: bool }`. Tests: single-instance chain, multi-instance chain, broken-seal. | `crates/ms-authn/src/lib.rs` + tests | 1 d |
| 2.3 | **DKIM expiration surfaced.** `DkimSummary.expired_at: Option<i64>`. Compute at verify time. Test: signed-but-expired → flag, not pass. | `crates/ms-authn/src/lib.rs` + tests | 0.5 d |
| 2.4 | **DMARC reason propagation.** `strongest_dmarc` → typed `DmarcStatus::Fail(reason)`. | `crates/ms-authn/src/lib.rs` | 0.5 d |
| 2.5 | **Outer timeouts on `verify()`** — wrap each phase (`verify_spf`/`verify_dkim`/`verify_arc`/`verify_dmarc`) in `tokio::time::timeout(10s)`. Document default. | `crates/ms-authn/src/lib.rs` | 0.5 d |
| 2.6 | **LRU cache eviction.** Replace `entries.clear()` with TTL-bounded LRU (or `moka::Cache`). Document the choice. | `crates/ms-authn/src/cache.rs`, `Cargo.toml` | 1 d |
| 2.7 | **`Authenticator::new` → `Result`.** Replace `.expect("…")` with a typed error. | `crates/ms-authn/src/lib.rs` | 0.25 d |
| 2.8 | **`mail_from_domain` handles source-routes and null-reverse-path correctly.** Currently `bounce+tag@sub.remote.test` is OK, but `helo` is the silent fallback for edge cases. Use `Option<&str>` explicitly. | `crates/ms-authn/src/lib.rs` | 0.25 d |
| 2.9 | **`add_ipv6` / `add_mx` test helpers.** Add `add_ipv6(hostname, ip6)` and `add_mx(domain, pref, host)` for symmetric test coverage. | `crates/ms-authn/src/cache.rs` | 0.25 d |
| 2.10 | **Wire DMARC reporting seam.** Either add an `AggregateReporter` trait and a no-op default, or remove the `report` feature flag in `Cargo.toml`. Pick one and document. | `crates/ms-authn/src/lib.rs`, `Cargo.toml` | 0.5 d |
| 2.11 | **Test matrix filling** — SPF `softfail`/`neutral`/`+all`/`redirect`/`include`, DKIM `fail`-from-body-hash-mismatch + `fail`-from-bad-signature + multiple signatures, DMARC `quarantine`/`reject` enforcement, FCrDNS failure modes, ARC chain depth tests. | `crates/ms-authn/tests/verify.rs` | 2 d |
| 2.12 | **`authserv_id` quoted** in `authentication_results()` to avoid header injection. | `crates/ms-authn/src/lib.rs` | 0.1 d |

**End-of-phase verification**:

```bash
cargo test -p ms-authn
cargo test --workspace    # downstream still compiles
cargo clippy --workspace --all-targets -- -D warnings
```

**Total ~7 working days for one engineer.**

---

## Phase 3 — Outbound mail (`ms-delivery`): MTA-STS / DANE / DSN / retry policy

Rationale: the review found *every* major outbound-mail control is missing or wrong: no MTA-STS, no DANE, no-op STARTTLS fallback, hand-rolled non-RFC-3460 DSN, retry policy that ignores enhanced status codes. This is the highest-leverage phase for a mailserver claiming to "speak flawless standards-compliant SMTP to the rest of the world" — without these, the outbound path advertises a privacy posture it can't deliver.

Order: MTA-STS + DANE → STARTTLS gate → proper DSN → retry rewrite → tests.

| # | Task | Files | Estimated effort |
|---|------|-------|---|
| 3.1 | **`policy.rs` module** — `MtaStsPolicy` lookup via TXT + HTTPS policy fetch; cache in `tokio::sync::RwLock<HashMap>` with RFC 8461 max-age. Use `mail_auth::mta_sts::MtaSts`. | `crates/ms-delivery/src/policy.rs` (new), `Cargo.toml`, module wiring | 1.5 d |
| 3.2 | **DANE verification.** `_25._tcp.<exchange>` → `TlsaRecord`, wired into `mail_send`'s connector. Refuse delivery permanently when TLSA exists and cert mismatches. Use `mail_auth::tlsa::Tlsa`. | `crates/ms-delivery/src/worker.rs`, `crates/ms-delivery/src/policy.rs` | 1.5 d |
| 3.3 | **STARTTLS gate.** Replace silent plaintext-fallback (`worker.rs:183-199`) with policy check: opportunistic-allowed only when MTA-STS is `none` or unset; permanent-fail when MTA-STS is `enforce` and remote didn't TLS. | `crates/ms-delivery/src/worker.rs`, `crates/ms-delivery/src/lib.rs` (`DeliveryParams::allow_opportunistic_tls`) | 0.5 d |
| 3.4 | **Real RFC 3460 multipart/report DSN.** `bounce()` produces `multipart/report; report-type=delivery-status` with `Reporting-MTA`, `Final-Recipient: rfc822;<recipient>`, `Action`, `Status: 5.x.y`, `Diagnostic-Code: smtp; <text>`, `Original-Envelope-Id`, `Delivery-Date`. DKIM-sign the bounce. | `crates/ms-delivery/src/worker.rs` | 1 d |
| 3.5 | **Enhanced status code parsing.** Map `4.x.x` to retry, `5.1.x`/`5.7.x` to hard-fail, `5.2.x` to soft-retry (mailbox full is often transient). Regex-parse `reply.enhanced_status_code()` if exposed, else from reply text. | `crates/ms-delivery/src/worker.rs` (`map_send_error`) | 1 d |
| 3.6 | **Backoff jitter.** `delay * (1 + rand(-0.1..0.1))` to avoid thundering-herd. | `crates/ms-delivery/src/lib.rs` | 0.25 d |
| 3.7 | **DNSSEC on resolver.** `MxRouter::new` opts in to `validate_dnssec(true)` for future DANE correctness. | `crates/ms-delivery/src/router.rs` | 0.25 d |
| 3.8 | **DKIM signing header coverage.** Sign `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `Reply-To`, `MIME-Version`, `Content-Type` per RFC 6376 §5.4 best practice. | `crates/ms-delivery/src/dkim.rs` | 0.25 d |
| 3.9 | **Backoff doc + queue helper.** Document the at-least-once semantics in `lib.rs`; add `attempt_history` view for the admin queue. | `crates/ms-delivery/src/lib.rs` (doc) | 0.5 d |
| 3.10 | **Concurrent-worker test.** Spawn two `spawn_worker` handles against the same `Storage`; submit N messages; verify each delivered exactly once and no row in `status='sending'` after join. | `crates/ms-delivery/tests/loopback.rs` | 0.5 d |
| 3.11 | **Retry-then-success test.** `unreachable_relay_defers_with_backoff` only asserts "deferred"; add a second phase where the relay becomes reachable and the same row delivers. | `crates/ms-delivery/tests/loopback.rs` | 0.5 d |
| 3.12 | **MX preference + null-MX tests.** Inject MX records (pref 10, 20) and verify preference order; null MX → `Permanent`. | `crates/ms-delivery/src/router.rs` + tests | 0.5 d |
| 3.13 | **`map_send_error` unit test.** Verify 4xx retries, 5xx per-codes. | `crates/ms-delivery/src/worker.rs` | 0.25 d |
| 3.14 | **PGP-encrypted message roundtrip through SMTP.** Loopback test sends a PGP/MIME message; receiver decrypts successfully. | `crates/ms-delivery/tests/loopback.rs` + `crates/ms-pgp` helper | 0.75 d |
| 3.15 | **`AnyRouter::Mx` integration test.** Real DNS lookup (via the test seam) exercising MX records rather than only `StaticRouter`. | `crates/ms-delivery/tests/loopback.rs` | 0.5 d |
| 3.16 | **Bounce-content test.** Assert `Auto-Submitted: auto-replied`, `MAILER-DAEMON@`, and (after Task 3.4) the multipart/report shape. | `crates/ms-delivery/src/worker.rs` | 0.25 d |

**End-of-phase verification**:

```bash
cargo test -p ms-delivery
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

**Total ~9–10 working days for one engineer.**

---

## Phase 4 — Inbound SMTP (`ms-smtp-in`): CRLF-injection bug, rate-limiting, edge tests

Rationale: this is the ingress surface. The review caught a real CRLF-injection defect in `Received:` header construction (`session.rs:355-368`), plus two denial-of-service concerns (no connection rate-limit, no slow-client wall-clock timeout). Plus the test coverage is thin for a protocol engine.

| # | Task | Files | Estimated effort |
|---|------|-------|---|
| 4.1 | **CRLF injection fix.** Sanitize `self.helo` for `\r`/`\n` at `session.rs:198-199` and `:217`. Same for `from.address`, `to.address` if they go into the `Received:` header. | `crates/ms-smtp-in/src/session.rs` | 0.25 d |
| 4.2 | **Connection rate-limit.** Wrap `listener.accept().await` in a token-bucket keyed by `peer.ip()`. Even a simple `HashMap<IpAddr, (Instant, u32)>` with cleanup would do. | `crates/ms-smtp-in/src/server.rs` | 1 d |
| 4.3 | **Session wall-clock timeout.** Track `session_start = Instant::now()`; check before each read; configurable cap (default 1 h per Postfix convention). | `crates/ms-smtp-in/src/session.rs` | 0.5 d |
| 4.4 | **`ResponseTooLong` as connection-closing offense.** Treat `smtp_proto::Error::ResponseTooLong` as a hard-close, not an increment-and-continue. | `crates/ms-smtp-in/src/session.rs` | 0.25 d |
| 4.5 | **STARTTLS handshake-failure logged at `warn!`** (was `debug!`). | `crates/ms-smtp-in/src/session.rs` | 0.1 d |
| 4.6 | **`max_errors` / `read_timeout` exposed in `SmtpConfig`** (currently hardcoded in `from_config`). | `crates/ms-core/src/config.rs`, `crates/ms-smtp-in/src/lib.rs` | 0.25 d |
| 4.7 | **`AUTH` reply differentiates** "unknown mechanism" (504) from "no auth on this port" (538). | `crates/ms-smtp-in/src/session.rs` | 0.25 d |
| 4.8 | **State machine ASCII diagram** as a doc-comment on `src/session.rs`. | `crates/ms-smtp-in/src/session.rs` | 0.25 d |
| 4.9 | **Missing tests:** re-STARTTLS-after-TLS, EHLO-after-EHLO, RSET mid-transaction, idle-timeout 421, MAX_CONNECTIONS 421, EHLO-host-CRLF-injection, pipelined-after-error, no-recipients-bounce. | `crates/ms-smtp-in/tests/session.rs`, `crates/ms-smtp-in/tests/starttls.rs` | 1 d |
| 4.10 | **In-memory DATA streaming** — replace `data: Vec<u8>` with a streaming `deliver` call (or temp-file spill) so peak RSS = `n_connections × small_header_buffer`, not `× 25 MiB`. | `crates/ms-smtp-in/src/session.rs` | 1 d |
| 4.11 | **DOC: explicit per-port semantics.** Clarify that `ms-smtp-in` is the MX port; submission (:587/:465) is a separate crate or future work. | doc | 0.1 d |

**End-of-phase verification**: workspace green + the new CRLF-injection test must pass.

**Total ~4–5 working days.**

---

## Phase 5 — `ms-pgp` / `ms-jmap-mail` / `ms-mcp` / `ms-ai` / `ms-api` (medium-lift items)

Rationale: this is the cohesive set of "everything else." Each crate review had a small handful of important findings; grouping them by crate produces commits that are easy to review and don't entangle crates.

Order: PGP (lowest) → JMAP-Mail (highest test leverage) → MCP (quick wins) → AI (largest scope) → API (security-critical).

### 5.A. ms-pgp (1 week)

| # | Task | Effort |
|---|------|--------|
| 5.A.1 | `OwnKey` newtype that wraps `Cert` + storage fingerprint; remove `sequoia_openpgp::Cert` from public API | 1 d |
| 5.A.2 | `EncryptRequest`/`OpenResult`/`SigStatus` wire types; pin cross-crate contract | 0.5 d |
| 5.A.3 | `rotate` / `revoke` / `expire_at` key lifecycle (currently missing) | 1.5 d |
| 5.A.4 | Fix PGP/MIME protected-headers claim (either real RFC 3156 protected headers or drop the claim) | 0.5 d |
| 5.A.5 | Inbound signature-status: `SigStatus::Invalid` vs `SigStatus::None` distinction | 0.5 d |
| 5.A.6 | WKD direct-method handler (advanced-only today) | 0.5 d |
| 5.A.7 | `serde_json::json!` migration of `pgp_status` (no more ad-hoc format!) | 0.25 d |
| 5.A.8 | Replace hand-rolled header parsing with `mail_parser` (`copy_routing_headers`, `extract_armored`) | 0.5 d |
| 5.A.9 | Module-level embedder-contract doc + missing tests (signed-only, malformed autocrypt, signature-on-tampered-ciphertext, etc.) | 1 d |

**Total ~6 working days.**

### 5.B. ms-jmap-mail (1 week)

| # | Task | Effort |
|---|------|--------|
| 5.B.1 | Bug fix: `totalThreads`/`unreadThreads` mirror `unreadEmails`/`totalEmails` (`lib.rs:129-130`) | 0.1 d |
| 5.B.2 | `Identity/get` `name: null` when unset; cross-check submission `identityId` | 0.25 d |
| 5.B.3 | `Email/set` `destroy` returns `notDestroyed` entries with `forbidden` instead of silent no-op | 0.5 d |
| 5.B.4 | `Email/changes`, `Mailbox/changes`, `Thread/changes` populate `destroyed` array (requires storage soft-delete column) — Phase 1.4 setup helps | 1 d |
| 5.B.5 | `Email/get` honors `properties` subset | 1 d |
| 5.B.6 | `Mailbox/get`, `Thread/get`, `Identity/get` `properties` support | 0.5 d |
| 5.B.7 | Reject unknown `filter` keys at parse time with `invalidArguments` (no more silent fall-through) | 0.5 d |
| 5.B.8 | Real `QueryFilter` AST: at minimum `inMailbox`, `hasKeyword`, `notKeyword`, `allInThreadHaveKeyword` | 1.5 d |
| 5.B.9 | Real `Sort` parsing & validation (RFC 8621 §6.3.3) | 0.75 d |
| 5.B.10 | `fetchTextBodyValues`, `fetchHTMLBodyValues`, `fetchAllBodyValues`, `maxBodyValueBytes` parsing | 0.5 d |
| 5.B.11 | `EmailSubmission/changes` — register method, surface `cannotCalculateChanges` since storage doesn't yet track the modseq | 0.5 d |
| 5.B.12 | `EmailSubmission/set` `oldState`/`newState` honesty — either track a modseq or document "state never advances" | 0.25 d |
| 5.B.13 | Error mapping refinement: `StorageError::AccountNotFound` → `accountNotFound`, `StorageError::BlobNotFound` → `invalidArguments`, `StorageError::Corrupt("no email X")` → `notFound` in `notUpdated` | 0.5 d |
| 5.B.14 | Cache envelope parse (`email_json` does 500 mail-parser runs on a 500-item `Email/get`) | 0.5 d |
| 5.B.15 | `subject`/`from`/`to`/`cc` header injection prevention in `compose_from_jmap` | 0.25 d |
| 5.B.16 | `Email/set` `apply_create` keyword application — single modseq bump instead of two | 0.5 d |
| 5.B.17 | Tests for `notFound`, pagination clamping, `Mailbox/get ids`, `inMailbox` filter, `EmailSubmission/set` error paths, `Email/set update` errors — 12-15 test additions | 1 d |

**Total ~9 working days.**

### 5.C. ms-mcp (½ day)

| # | Task | Effort |
|---|------|--------|
| 5.C.1 | Fix `let id = id.unwrap();` at `lib.rs:102` (already in Phase 0.11) | 0 d |
| 5.C.2 | Add tool `annotations` (`destructive: true` on `move_email`/`send_email`, `idempotent: true` on `mark_read`) | 0.25 d |
| 5.C.3 | Document embedder contract on `handle` + module docs for `service.rs` | 0.25 d |
| 5.C.4 | Tests for unknown tool, missing args, `notifications/cancelled` | 0.5 d |

**Total ~1 day.**

### 5.D. ms-ai (1.5 weeks)

| # | Task | Effort |
|---|------|--------|
| 5.D.1 | Add `ai_actions` migration: `actor`, `model`, `confidence`, `rationale`, `cost_tokens_in`/`out`, `cost_usd`, `provider`, `latency_ms`, `error` | 0.5 d |
| 5.D.2 | Parse `usage` in `ClaudeProvider` and `OpenAiCompatProvider`; return `ProviderResponse { value, cost }` | 0.5 d |
| 5.D.3 | Per-skill budget table + `BudgetExceeded` error; worker skips account on budget exhaust | 1.5 d |
| 5.D.4 | Provider retry/backoff/429 handling; **worker cursor MUST NOT advance past transient model failures** (real bug) | 1.5 d |
| 5.D.5 | `wiremock` test suite for Claude + OpenAI (happy/401/429/529/malformed/timeout) | 1 d |
| 5.D.6 | Native `async fn` in `AiProvider`; `Arc<reqwest::Client>` reuse; per-request timeouts; manual `Debug` redacting `api_key` | 0.5 d |
| 5.D.7 | Typed `InversePatch` enum in `undo_action`; summary-annotation undo | 0.5 d |
| 5.D.8 | Central kill switch (`AiConfig::killswitch: HashSet<String>`) + per-account disabled skills | 0.25 d |
| 5.D.9 | Prompt-injection markers (`<<BEGIN EMAIL>>…<<END EMAIL>>`) + refusal detection + log to `ai_actions.error` | 0.5 d |
| 5.D.10 | Unit tests for `list_unsubscribe` parsing, category validation, summarize schema | 0.5 d |
| 5.D.11 | Undo compare-and-swap (refuse if user moved email since) | 0.25 d |
| 5.D.12 | Move `sender_message_count` race-fix to storage transaction boundary | 0.5 d |
| 5.D.13 | Real `Event` filter on `DataType::Email` in worker (not every event) | 0.25 d |

**Total ~7 working days.**

### 5.E. ms-api (1 week)

| # | Task | Effort |
|---|------|--------|
| 5.E.1 | Fix WKD content-type (`application/octet-stream` → `application/vnd.gpg.key`) | 0.1 d |
| 5.E.2 | Add CORS headers on WKD routes (`Access-Control-Allow-Origin: *`) | 0.1 d |
| 5.E.3 | Per-token `may_send` scope wiring (currently global); default `may_send` to `false` until wired | 0.5 d |
| 5.E.4 | Case-insensitive `Bearer` parsing | 0.1 d |
| 5.E.5 | Tests for `push.rs` (SSE account filter + WS subprotocol + `WebSocketPushEnable` toggle) and WKD (content-type + CORS + 404) | 1 d |
| 5.E.6 | Single `ApiError` enum with `IntoResponse` impl; uniform error shape | 0.5 d |
| 5.E.7 | `tower-http` request body limit (`RequestBodyLimitLayer`) against `dispatcher.limits().max_size_request` | 0.25 d |
| 5.E.8 | Real `healthz` (uptime + storage ping + structured JSON) and `/readyz` separation | 0.5 d |
| 5.E.9 | Auth middleware (`from_fn_with_state`) so protected routes can't forget to call `authenticate` | 0.5 d |
| 5.E.10 | Rate-limit / token-bucket on the auth path (`tower-governor` or hand-rolled per-IP) | 1 d |
| 5.E.11 | WebSocket idle/lifetime cap | 0.25 d |
| 5.E.12 | WKD hash-mapping cache (`HashMap<hash, account_id>`) | 0.25 d |
| 5.E.13 | SSE `id:` field on events so clients can pass `Last-Event-ID` (currently can't resync) | 0.5 d |

**Total ~5–6 working days.**

**Phase 5 total ~5 weeks of focused work** for one engineer.

---

## Phase 6 — Documentation, integration, polish

Rationale: the work in Phases 0–5 brings functional correctness. Phase 6 makes it *usable*: module-level docs, embedder walkthroughs, integration-test coverage, CI gates.

| # | Task | Effort |
|---|------|--------|
| 6.1 | `ms-mcp` README documenting embedder contract + setup steps | 0.25 d |
| 6.2 | `ms-smtp-in` state-machine ASCII diagram in module docs | 0.25 d |
| 6.3 | Top-level `docs/PATTERNS.md` — "how to add a new JMAP method" / "how to add a new AI skill" / "how to add a new SMTP-in test" | 0.5 d |
| 6.4 | Replace `mailserverd config example` round-trip test — add `Config::example()` → `Config::load` round-trip in `ms-core` | 0.25 d |
| 6.5 | `cargo doc --workspace --no-deps` clean in CI (currently `ms-core` had an HTML-tag warning fixed in Phase 0.12) | 0.1 d |
| 6.6 | CI gate: workspace-wide `cargo clippy --all-targets -- -D warnings` must pass (unblocked by Phase 0.11) | 0.25 d |
| 6.7 | CI gate: workspace-wide `cargo test` must pass; add a `cargo test --workspace --no-fail-fast` script | 0.1 d |
| 6.8 | `docs/PLAN.md` updates: removed MTA-STS-vhost/MSG-related claims that don't exist; mark items addressed by phases | 0.25 d |
| 6.9 | Add an integration test crate `tests/mailserver_e2e.rs` exercising SMPT-in → SMTP-inject → AI categorized → JMAP query end-to-end | 1 d |
| 6.10 | Bisect-friendly commits — confirm each phase's branch cherry-picks cleanly onto `main` | 0.25 d |

**End-of-repo verification**:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps
rustup component add cargo-audit && cargo audit   # for any uncleared advisories
```

All five must pass.

---

## Out-of-scope (intentionally not in any phase)

These are real but not in this plan because they need design discussion:

- **`ms-crypto` new crate** — extract sequoia wrappers, JMAP-side id codecs, argon2 KDF derivation into a single firewall crate (the `ms-pgp` work in 5.A.1 sets this up but the crate doesn't exist yet).
- **`ms-mail` unified type passing** — the project has split mail-domain types across `ms-core`, `ms-storage`, `ms-jmap-mail`, `ms-pgp`. A future consolidation pass could fold these into one or two crates.
- **MTA-STS vhost in `ms-api`** — review assumed this existed; it doesn't. Out of scope (or add as its own dedicated phase if priorities change).
- **IMAP read-bridge** — listed in `PLAN.md` as M7. Not in this plan.
- **Multi-account support** — currently the entire codebase is single-account. Phase 1.16 documents the per-account constraint; the plan defers the actual multi-tenant refactor.
- **DKIM DANE-ADSP** — the markdown review listed it; `mail-auth` has support but it's not RFC DANE (RFC 7672); defer.

---

## Estimate summary

| Phase | Effort (eng. days) | Net cumulative |
|-------|---------------------|----------------|
| 0 (foundation) | 2.5 | 2.5 |
| 1 (storage) | 5 | 7.5 |
| 2 (auth) | 7 | 14.5 |
| 3 (delivery) | 9–10 | 24 |
| 4 (smtp-in) | 4–5 | 28.5 |
| 5 (PGP / jmap-mail / mcp / ai / api) | 24 | 52.5 |
| 6 (docs + polish) | 3 | 55.5 |

**~55 working days for one focused engineer, ~11 weeks at full focus.** Multiple engineers can parallelize Phases 4, 5.A, 5.B, 5.D, 5.E (they touch separate crates with minimal cross-dependencies).

## Branch strategy

- One branch per phase: `hardening/phase-0-foundation`, `hardening/phase-1-storage`, …
- Each branch is rebased onto the previous before merge.
- Subagent-driven workflow per phase (as in `jmap-core-hardening`).
- Final reviewer dispatched per branch (see prior work for the template).

## Execution handoff

Two options for the user (mirroring prior pattern):

1. **Subagent-driven (this session)** — I drive Phase 0 task-by-task with subagent + two-stage review per task. Faster iteration, higher review fidelity, ~3 days of clock time given context overhead.
2. **Parallel session** — open a new session with `executing-plans`; one engineer, full plan, batch checkpoints. Lower context cost per task but slower review.

For Phase 0 specifically (12 small tasks), option 1 is recommended; for Phases 1–6 with multi-day tasks, option 2 is more efficient. A mix is reasonable: subagent-driven for Phases 0, 4, 5.C (small); parallel session for the others.
