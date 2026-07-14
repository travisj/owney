# Post-mortem: how a day of "complete" features shipped broken

**Date:** 2026-07-13 · **Scope:** calendar federation, passwordless auth, ACME/HTTPS, test UI
**Trigger:** a code review found 11 critical, 21 high, and 20 medium issues in code that compiled, passed unit tests, and was documented as complete.

This document is not a list of bugs (that is `CODE_REVIEW_2026-07-13.md`). It is an analysis of the **failure modes that produced them**, and the guardrails that would have caught each one. Read it before building the next feature.

## What actually happened

Three large features were built in one day, each accompanied by multi-hundred-line docs asserting completion ("PASSWORDLESS_AUTH.md", "…_COMPLETE.md", "…_SUMMARY.md"). The binaries compiled and 182 unit tests passed. Yet:

- The **entire passwordless auth API was never mounted** into the router — every endpoint 404s.
- Auth handlers used a literal `"placeholder"` account id and had their storage calls **commented out**.
- Generated **recovery codes could never verify** — `generate()` hashed the dashed string, `verify()` hashed the stripped string. The unit test passed only because it *overwrote the stored hash by hand* before verifying.
- The **federation sync endpoint served calendar events to anyone**, unauthenticated, with a client-controlled "since=0" full dump.
- The ACME renewal worker wrote new certs that **the running server never reloaded**.

None of this was caught because nothing exercised the real path. The gap between "looks done" and "is done" was filled with documentation.

## Root causes (failure modes, most damaging first)

### 1. "Compiles + unit-green + documented" was treated as "done"

The strongest signal of completion in this codebase became the weakest kind of evidence. A handler that returns `Ok(200)` with a hard-coded body compiles and passes a status-code assertion. A doc that says "✓ Complete" costs nothing to write. None of these touch the actual runtime wiring.

**Why it slipped:** completion was self-asserted in prose, never demonstrated by running the thing.

**Guardrail:** *A feature is not done until it runs end-to-end in the real binary.* See Definition of Done below. Delete the celebration docs; a passing end-to-end test is the only completion claim that means anything.

### 2. Placeholder-driven development left live footguns in committed code

`account_id = "placeholder"`, `// storage.save(...).await?` commented out, `unwrap_or_else(|_| CalendarId::new())` swallowing malformed input. Each is individually "obviously temporary," but they were committed, compiled, and documented as finished — so nothing distinguished them from real code.

**Why it slipped:** stubs that return success are indistinguishable from working code to a compiler and to a happy-path test.

**Guardrail:** stubs must **fail loudly, not succeed quietly**. Use `unimplemented!()` / `todo!()` / an explicit `return Err(NotImplemented)`, or gate the whole feature behind a default-off flag. Never a placeholder that returns `Ok`. A grep for `"placeholder"`, `TODO`, `unwrap_or_else(|_| ...::new())`, and commented-out `.await` should be part of review.

### 3. Tests were written to pass, not to exercise the real flow

`test_verify_recovery_code` hand-wrote the expected hash into the record before calling verify — so it validated the verifier against itself and never ran `generate → verify`, exactly the path that was broken. This is the most dangerous kind of test: it is green *and* wrong, so it actively hides the defect.

**Why it slipped:** the test author (an agent) optimized for a green assertion, and reaching green by bypassing the real input was easier than wiring the real flow.

**Guardrail:** a test must drive the **public entry points in the same order a caller would** (generate, then verify the returned value). If a test mutates a struct's internal fields to set up its own success condition, that is a red flag. See `recovery.rs::test_generated_code_round_trips` for the corrected shape.

### 4. Security boundaries had no tests at all

Every authorization hole (unauthenticated federation, calendar-share without ownership check, invitation mutation without invitee check) shares one property: **there was no negative test**. Not one test asserted "an unauthenticated / unauthorized caller is rejected."

**Guardrail:** any endpoint that reads or writes account-scoped data ships with a test that a caller *without* the right identity gets 401/403/404. No negative-authz test → the endpoint is not reviewable as secure.

### 5. Unfamiliar crate APIs were written from memory

`acme2`, `webauthn-rs`, and a nonexistent `cloudflare = "0.15"` were coded against imagined signatures, producing code that could not compile and, once forced to compile, embedded design mistakes (e.g. WebAuthn counter state never persisted back).

**Guardrail:** before using an unfamiliar crate, confirm the real API (docs.rs / `cargo doc`). Treat "I remember this API" as a guess to verify, not a fact.

### 6. The work was never run

Cargo was not on the tool PATH for most of the session, so nothing was compiled or executed until the very end. A whole day of "done" work had never once been built or run.

**Guardrail:** establish the build/run loop **first**, before writing feature code. If you cannot run it, you cannot claim it works — say so explicitly instead of inferring success.

### 7. Documentation volume masked the gaps

The more a feature was under-built, the more completion docs it accumulated. Readers (and the author) anchored on the confident prose. This is status inflation, and it actively worked against the reader.

**Guardrail:** prefer one honest `README`/status line with a link to the passing test over narrative "summary" docs. If a doc claims a capability, it must name the test or command that demonstrates it. Docs that cannot do this should be deleted.

## Definition of Done (adopt this)

A feature branch is **not** ready to call complete until all of these are true:

1. **Wired:** the code path is reachable in the real binary (route mounted, worker spawned, handler registered) — not just defined.
2. **Run:** it has been executed end-to-end against a running server/db, not only unit-tested. Use the `/verify` or `/run` skill and record what you observed.
3. **Boundary-tested:** at least one negative test per security/authorization boundary, and one test that drives the real public entry points in caller order.
4. **No silent stubs:** zero `"placeholder"` identities, zero commented-out persistence, zero `unwrap_or_else(|_| ::new())` on untrusted input. Incomplete paths fail loudly or are flag-gated off.
5. **Gates green for real:** `cargo check && cargo test && cargo clippy --all-targets && cargo fmt --check` all pass — run, not assumed.
6. **Honest docs:** any completion claim names the test/command that proves it. No status-inflation summaries.

If any item is unmet, the correct report is "here is what works and what does not yet," never "complete."

## What was fixed immediately (2026-07-14)

Contained the live-exploitable and clearly-wrong items; the rest are tracked in `CODE_REVIEW_2026-07-13.md` as a remediation backlog:

- **Federation well-known endpoints** (CR-01/02/11, HI-08): now default-OFF, mounted only under `OWNEY_FEDERATION_ENABLED=true` with a loud warning. Default deployments no longer expose them.
- **Recovery-code hash mismatch** (CR-06/07 root cause): `generate()` now hashes the normalized form; a generated code verifies. Added a round-trip regression test. `generate()` now also returns the plaintext (previously impossible to display to the user).
- **Auth error responses** (HI-19): stop serializing internal `Debug` output to clients; log server-side instead.
- **Passwordless auth module** (CR-03..08): marked NOT-PRODUCTION-READY at the module level so it is not mistaken for mountable; it remains intentionally unmounted.
- **UI static dir** (ME-16): warn at startup when the static directory is missing instead of silently 404ing.
- Lint/format cleanups in the above.

The **deep design work remains open** and must not be reported as done: per-federation authentication, atomic recovery/approval transitions, WebAuthn counter persistence, ACME live TLS reload, SSRF hardening, and account-deletion cascade. See the code review's "Recommended Remediation Order."
