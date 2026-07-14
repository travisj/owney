# Code Review: Commits Made on 2026-07-13

**Review status:** Read-only review; no fixes applied  
**Review range:** `6eddf2a^..HEAD`  
**Commits reviewed:** 10 commits authored on 2026-07-13  
**Aggregate change:** 75 files, approximately 16,732 additions and 68 deletions  
**Reviewer focus:** Security, authorization, tenant isolation, correctness, data integrity, operational behavior, migrations, test coverage, and deployment quality

## Executive Summary

The review found multiple production-blocking issues across calendar federation, passwordless authentication, ACME/HTTPS renewal, account deletion, and UI/runtime integration. The most serious concerns are unauthenticated federation endpoints, incomplete authentication wiring, placeholder account identities in authentication handlers, QR pairing without proof of possession, non-atomic recovery-code redemption, missing federation state transitions, and certificate renewal without live TLS reload.

The code compiles and the current library tests pass, but the tests largely cover isolated happy paths. They do not exercise the HTTP authorization boundaries, complete authentication flows, federation round trips, account deletion with new tables, ACME issuance/renewal, or the deployed UI against the running server.

**Recommendation:** Do not deploy the calendar federation, passwordless authentication, or ACME renewal functionality until the Critical and High findings are addressed and covered by integration tests.

## Review Scope

### Commits

1. `6eddf2a` — `feat(calendar): storage layer for sharing, delegation, and federation`
2. `94ed570` — `feat(calendar): add sync framework, tests, and federation docs`
3. `24ba75e` — `docs(calendar): add federation roadmap and sync protocol spec`
4. `b21f6dc` — `feat(calendar): implement event sync endpoint for federation polling`
5. `054acd6` — `docs(calendar): add comprehensive implementation summary`
6. `152c762` — `feat(calendar): implement background sync worker (Phase 2.5)`
7. `bcb782b` — `docs(calendar): add Phase 2.5 summary and completion notes`
8. `aec4086` — `docs(project): add comprehensive CLAUDE.md guide`
9. `72d962b` — `feat(auth): implement complete passwordless authentication REST API`
10. `13bed12` — `fix: make workspace compile and pass tests after first full build`

### Areas examined

- Calendar sharing, invitations, federation, synchronization, and JMAP methods
- Well-known federation and account-discovery endpoints
- Passwordless authentication, passkeys, recovery codes, QR pairing, and approvals
- Storage migrations, foreign keys, deletion behavior, and synchronization state
- ACME certificate issuance, DNS providers, renewal, TLS configuration, and secrets
- API router wiring, background workers, static UI integration, and build artifacts
- Existing unit tests, workspace checks, formatting, linting, and UI build behavior

## Severity Definitions

- **Critical:** Security vulnerability, authentication bypass, cross-tenant exposure, data corruption, or a feature that cannot safely be deployed.
- **High:** Major correctness, availability, integrity, or deployment defect likely to cause user-visible failure or operational outage.
- **Medium:** Important reliability, protocol, maintainability, or scale issue that should be addressed before broad production use.
- **Low:** Hygiene, observability, documentation, or non-blocking quality issue.
- **Risk:** A concern requiring design confirmation or additional evidence; not presented as a confirmed defect.

## Critical Findings

### CR-01 — Unauthenticated federation sync exposes calendar events

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/wellknown.rs:155-265`

The `/.well-known/owney/calendar/sync/{federation_id}` endpoint does not require authentication, a signature, a shared secret, or a trusted-peer check. Anyone who obtains or guesses a federation ID can retrieve calendar metadata and events.

The endpoint also does not verify that the federation is active or authorized for the requesting peer. A federation in `pending`, `error`, or revoked state can still serve data.

**Impact:** Cross-tenant calendar disclosure, including event titles, descriptions, and timestamps.

**Suggested remediation:** Require a per-federation bearer token, signed request, mTLS identity, or equivalent authenticated peer mechanism. Check federation status and bind the credential to the specific federation and remote server. Until that exists, disable the endpoint or gate it behind a strict trusted-server allowlist.

### CR-02 — Caller-controlled sync timestamps can force a full event dump

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/wellknown.rs:189-210`

The endpoint trusts caller-supplied `since_timestamp` values. A caller can request `since=0` and receive all events. There is no monotonicity check, token integrity check, or server-side enforcement of the federation's last trusted cursor.

**Impact:** Combined with CR-01, a caller can request the complete calendar history rather than only authorized incremental changes.

**Suggested remediation:** Use an opaque, authenticated cursor derived from server state. Ignore arbitrary client timestamps unless they are signed or bound to the federation. Enforce monotonic cursors and reject stale or invalid tokens.

### CR-03 — Passwordless authentication routes are not mounted

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:810-844`, `crates/owney-api/src/lib.rs:60-81`

`auth_routes()` is defined but is not merged into the main API router. No runtime path constructs and supplies the required `AuthState`.

**Impact:** The documented passwordless endpoints return 404 and the feature is not operational. This also creates a dangerous mismatch between documentation and the deployed binary.

**Suggested remediation:** Either complete the router/state integration with end-to-end tests, or remove/gate the unfinished feature so it cannot be mistaken for a deployable authentication system.

### CR-04 — Passwordless session tokens are incompatible with existing bearer authentication

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/challenge_store.rs:111-197`, `crates/owney-api/src/lib.rs:165-192`

Passwordless handlers issue `owk_` tokens into an in-memory `SessionTokenManager`, while the existing API authentication path validates tokens through storage-backed account tokens. There is no integration between the two systems.

**Impact:** Even if the routes are mounted, passwordless-issued tokens cannot authenticate normal API requests. Tokens also disappear on process restart and cannot work reliably across multiple instances.

**Suggested remediation:** Use one token-validation path. Prefer a durable, revocable session-token store with expiry, account-state checks, and token hashing. Add an end-to-end test from passkey/recovery login through an authenticated JMAP request.

### CR-05 — QR pairing confirms arbitrary codes and creates an approving device

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:747-792`

`qr_code_pairing_confirm` does not validate the supplied pairing code against the challenge store. It stores an empty public key, uses the literal account ID `"placeholder"`, and grants `can_approve = true`.

**Impact:** The flow does not prove possession of the QR pairing secret or a device key. If connected to a real account, an attacker could create an approving device and authorize login requests.

**Suggested remediation:** Validate and consume the pairing challenge, bind it to a specific login/account flow, require proof of possession of a device key, reject empty public keys, and default new devices to non-approving until enrollment is complete.

### CR-06 — Recovery-code redemption is not atomic and permits replay races

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:530-568`, `crates/owney-storage/src/passwordless.rs:303-351`

The handler first reads an unused recovery code and then separately marks it used. The update does not include `AND used = 0` and the two operations are not in one transaction.

**Impact:** Concurrent requests can redeem one supposedly single-use recovery code multiple times and mint multiple sessions.

**Suggested remediation:** Perform lookup and conditional consumption in one transaction, using `UPDATE ... WHERE id = ? AND used = 0 RETURNING ...` or checking affected rows. Mint the token only after the conditional update succeeds.

### CR-07 — Recovery-code generation returns codes that are never persisted

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:477-528`

The endpoint returns generated codes, but the storage call is commented out. The handler uses the literal account ID `"placeholder"` and is not protected by an authenticated account context.

**Impact:** Users receive recovery codes that cannot be redeemed. If persistence is later enabled without fixing the placeholder, it could create a cross-account authentication defect.

**Suggested remediation:** Require an authenticated account, use the shared recovery-code generator, persist hashes transactionally, and test generation → redemption end to end.

### CR-08 — Approval endpoints use placeholder identities and lack authorization

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:572-716`

Approval creation uses `account_id = "placeholder"`. Status and approval handlers have no authenticated source-device or account binding. Approval updates do not require the request to still be pending, and the device disabled state is not checked.

**Impact:** The approval flow is not connected to real accounts and would be unsafe to expose. Concurrent requests can both report successful approval, and disabled devices may continue approving.

**Suggested remediation:** Bind every approval request to an authenticated login transaction, use a conditional atomic status transition, check expiry/status/device-disabled state, and require a signed approval payload from the enrolled device.

### CR-09 — Federation invitation acceptance does not create an active federation

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-storage/src/calendar_sharing.rs:299-311`, `crates/owney-jmap-mail/src/calendar_methods.rs:218-249`

Accepting an invitation only updates the invitation status. It does not create or activate the `calendar_federation` row that the worker queries.

**Impact:** Users can receive a successful acceptance response while synchronization never starts.

**Suggested remediation:** In one transaction, verify the invitee, create the federation state with a trusted remote identity and initial cursor, update the invitation, and trigger an initial sync.

### CR-10 — Calendar sharing does not enforce calendar ownership

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-jmap-mail/src/calendar_methods.rs:87-182`, `crates/owney-storage/src/calendar_sharing.rs:115-158`

The caller account is checked against the JMAP request, but storage does not verify that the caller owns the calendar being shared. A user can submit another account's calendar ID.

**Impact:** Any authenticated account may grant access to another tenant's calendar.

**Suggested remediation:** Enforce ownership inside storage, not only at the handler. Verify the calendar's owner before every share/invitation operation and add negative authorization tests.

### CR-11 — Federation invitation input is unauthenticated and identity is spoofable

**Severity:** Critical  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/wellknown.rs:87-150`

The invitation receiver accepts caller-supplied `inviter_account_id`, `inviter_server_url`, and calendar ID without authenticating the remote server or verifying ownership. Invalid IDs are silently replaced with newly generated IDs.

**Impact:** Forged invitations, identity spoofing, invalid federation records, and possible cross-tenant metadata manipulation.

**Suggested remediation:** Authenticate inter-server requests, validate all IDs strictly, verify the inviter owns the referenced calendar on the authenticated remote server, and reject malformed input with 400 rather than substituting IDs.

## High Findings

### HI-01 — Sync worker is never spawned

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/background_worker.rs:42-95`, `bin/owneyd/src/main.rs:559-714`

The worker implementation exists but the production binary does not spawn it. Federations will not poll remote servers.

**Suggested remediation:** Spawn the worker as part of server startup, propagate shutdown, observe task failure, and add a runtime startup test or integration harness.

### HI-02 — Remote event IDs are discarded, causing duplicate events

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/calendar_sync.rs:101-143`, `crates/owney-storage/src/calendar.rs:171`

The sync code checks for the remote event ID but creates a new local ID when the event is absent. Future syncs cannot find the prior copy.

**Impact:** Repeated polling creates duplicate calendar events.

**Suggested remediation:** Preserve the remote ID as the local stable ID, or add a unique `(federation_id, remote_event_id)` mapping and upsert through it.

### HI-03 — Sync writes and cursor updates are not atomic

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/calendar_sync.rs:60-98`, `crates/owney-storage/src/calendar_sharing.rs:353-370`

Event upserts, deletions, and federation cursor updates occur as separate operations. A partial failure leaves partially applied data and an old cursor. Successful updates also leave status as `syncing` rather than transitioning back to an active state.

**Suggested remediation:** Use one storage transaction for event mutations and cursor/state update. Define explicit state transitions and recovery for interrupted syncs.

### HI-04 — Deletes cannot propagate through federation

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/wellknown.rs:200-228`, `crates/owney-api/src/wellknown.rs:261`, `crates/owney-storage/src/calendar.rs:327-356`

The endpoint always returns an empty `removed_event_ids` list and there is no soft-delete/tombstone mechanism. Physically deleting an event removes the evidence needed by incremental peers.

**Suggested remediation:** Add a tombstone table or `deleted_at`/modseq fields, retain deletion records for the synchronization horizon, and test remote deletion propagation.

### HI-05 — Invitation mutation lacks invitee authorization

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-jmap-mail/src/calendar_methods.rs:218-249`, `crates/owney-storage/src/calendar_sharing.rs:299-311`

Accept/reject operations update by invitation ID without verifying that the caller is the intended invitee. A caller who learns an ID may mutate another user's invitation.

**Suggested remediation:** Add caller account/email predicates to the update query and verify ownership before mutating. Return not-found or forbidden consistently.

### HI-06 — Invitation reject path is a successful no-op

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-jmap-mail/src/calendar_methods.rs:238-244`

The handler returns a rejected response but never updates storage. The invitation remains pending and reappears.

**Suggested remediation:** Implement a storage-level reject operation, enforce invitee authorization, and test repeated get/set behavior.

### HI-07 — Federation discovery and sync enable SSRF

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/federation.rs:67-147`, `crates/owney-api/src/calendar_sync.rs:138-176`

Remote URLs are derived from user-controlled email domains or stored federation data. Requests lack a strict allowlist, redirect policy, DNS-rebinding protection, and consistent connect timeout. Attacker-controlled federation records can point requests at internal services.

**Suggested remediation:** Require HTTPS, validate hostnames against trusted federation policy, reject private/link-local destinations after DNS resolution, disable cross-origin redirects, reuse a configured client, and impose connect/read timeouts.

### HI-08 — Public account lookup leaks account and calendar metadata

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/wellknown.rs:50-85`

The public endpoint confirms account existence and returns account ID, calendar IDs, and calendar names.

**Suggested remediation:** Authenticate peer discovery or return only minimal non-sensitive information. Add rate limiting and uniform responses where enumeration resistance is required.

### HI-09 — Account deletion omits new dependent tables

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-storage/src/lib.rs:325-376`

The hand-maintained deletion list omits new passwordless, calendar federation, calendar, event, and related tables. Foreign keys lack consistent cascade behavior.

**Impact:** Deletion may fail with foreign-key errors or leave sensitive orphan records.

**Suggested remediation:** Prefer declarative `ON DELETE CASCADE` where appropriate, otherwise delete in dependency order. Add a test that creates every new record type and deletes the account.

### HI-10 — ACME renewal does not reload the live TLS configuration

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-acme/src/acme.rs:271-291`, `bin/owneyd/src/main.rs:605-610`, `crates/owney-api/src/renewal.rs`

Renewal writes new certificate files, but the SMTP listener loads the TLS configuration only once at startup.

**Impact:** The process continues serving the old certificate until restart; eventual certificate expiry can cause mail outages.

**Suggested remediation:** Use an atomic certificate update plus `ArcSwap`/reloadable acceptor, or explicitly restart/reconfigure listeners after renewal. Add renewal and reload integration tests.

### HI-11 — ACME credentials and generated config lack secure permission handling

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-core/src/config.rs:161-183`, `bin/owneyd/src/main.rs:334-336`

The Cloudflare token is represented as a normal string in configuration, and setup writes configuration without explicitly enforcing owner-only permissions.

**Impact:** Token disclosure can grant DNS control over the zone and enable certificate issuance for arbitrary hosts.

**Suggested remediation:** Prefer environment/secret-manager references, use secret wrappers, enforce `0600`, validate existing config permissions, and avoid printing secrets.

### HI-12 — ACME DNS challenge creation is not idempotent

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-acme/src/provider.rs:34-80`

Retries can attempt to create duplicate or conflicting TXT records. A failed attempt can leave stale records that cause subsequent issuance to fail.

**Suggested remediation:** List existing challenge records, reuse matching values, clean up conflicting stale records safely, and make retries idempotent.

### HI-13 — Missing certificate does not trigger immediate initial issuance

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/renewal.rs:18-89`

The renewal worker waits on its periodic interval when the certificate is absent instead of initiating issuance immediately.

**Impact:** A first deployment may run without TLS for up to a day, depending on configuration.

**Suggested remediation:** Separate initial issuance from renewal and fail startup or issue immediately when required certificates are missing.

### HI-14 — Invalid IDs are silently replaced with new IDs

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/wellknown.rs:102-103`, `crates/owney-storage/src/calendar_sharing.rs` ID parsing sites

Malformed calendar/account IDs are converted to fresh IDs using `unwrap_or_else(|_| ...::new())`.

**Impact:** Bad or corrupted data can appear to succeed while pointing at unrelated/nonexistent records, hiding integrity failures.

**Suggested remediation:** Reject malformed API input and return a typed corruption/storage error for malformed database values.

### HI-15 — Calendar JMAP authorization and filtering are incomplete

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-jmap-mail/src/calendar_methods.rs:54-85`, `:184-216`

`Calendar/get` ignores requested IDs, lists owned calendars only, omits shared calendars, and hard-codes `isSubscribed`. `CalendarInvitation/get` ignores IDs and always reports no missing IDs.

**Suggested remediation:** Implement JMAP `ids` filtering, return owned and authorized shared calendars, calculate rights/subscription state, and populate `notFound` correctly.

### HI-16 — Calendar share uses hard-coded inviter URL

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-jmap-mail/src/calendar_methods.rs:145-160`

Federated invitations use `https://example.com` rather than configured server identity.

**Impact:** Remote peers cannot reliably call back to the real server and the identity field is spoofed/misleading.

**Suggested remediation:** Inject the configured public URL into the JMAP context and persist the discovered/validated peer URL.

### HI-17 — Approval updates permit races and disabled devices

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:670-716`, `crates/owney-storage/src/passwordless.rs:617-643`

Approval does not condition the update on `status = pending`, does not check device disabled state, and does not verify a device signature.

**Suggested remediation:** Perform one atomic conditional update, check device state, reject already-processed requests, and require signed approval payloads.

### HI-18 — Passkey counters and backup state are not persisted correctly

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:451-470`, `crates/owney-storage/src/passwordless.rs:189-211`

Authentication updates only a counter/timestamp path. The updated WebAuthn passkey state and backup flags are not fully persisted; storage also lacks a monotonic counter guard.

**Impact:** Clone detection and authenticator backup-state reporting can be stale or bypassed.

**Suggested remediation:** Persist the complete post-authenticator state transactionally and reject counter rollback at the storage boundary.

### HI-19 — Authentication error responses expose internal debug details

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/auth.rs:243-256`

The API serializes internal error `Debug` output into client responses.

**Impact:** Internal implementation details and authentication failure structure are exposed to attackers.

**Suggested remediation:** Return stable, generic public errors and log detailed diagnostics server-side with appropriate redaction.

### HI-20 — Recovery codes use unsalted fast hashes and have no rate limiting

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-authn-v2/src/recovery.rs:107`, `crates/owney-api/src/auth.rs:530-570`

Recovery codes are hashed with unsalted SHA-256, and the endpoint has no effective per-IP/account attempt limiting.

**Suggested remediation:** Use a password-code appropriate KDF such as Argon2id with per-code salt, add rate limiting/lockout, and avoid exposing account existence through response differences.

### HI-21 — Authentication challenge/session stores are unbounded in memory

**Severity:** High  
**Status:** Confirmed  
**Location:** `crates/owney-api/src/challenge_store.rs:21-197`

Cleanup exists but is not scheduled, and maps have no capacity limits. Public challenge endpoints could grow memory indefinitely.

**Suggested remediation:** Add bounded storage, scheduled cleanup, per-IP/global rate limits, and durable/shared state if multiple workers are supported.

## Medium Findings

### ME-01 — Worker backoff configuration is unused

**Location:** `crates/owney-api/src/background_worker.rs:19-95`

`max_backoff_secs` is configured but not applied. Failed peers are retried at the normal interval, and error states have no automatic recovery path.

### ME-02 — Sync worker is sequential and creates HTTP clients per request

**Location:** `crates/owney-api/src/calendar_sync.rs:138-159`

Federations are polled serially and a new `reqwest::Client` is created per call. Reuse a configured client and bound concurrency with a semaphore.

### ME-03 — Sync cursor is timestamp-based and can miss boundary updates

**Location:** `crates/owney-api/src/wellknown.rs:201-235`, `crates/owney-storage/src/calendar.rs:327-356`

Using `updated_at > since` can miss events updated at the cursor boundary. Use a monotonic modseq or `(timestamp, stable ID)` cursor.

### ME-04 — Sync token is predictable and can repeat

**Location:** `crates/owney-api/src/wellknown.rs:230-235`

Tokens are based on current Unix seconds and are not opaque, authenticated, or guaranteed unique.

### ME-05 — Permissions are stored but not enforced

**Location:** `crates/owney-storage/src/calendar_sharing.rs:49-68`, `:115-158`

Delegation/sharing permission structures are advisory; storage operations do not consistently check them.

### ME-06 — Calendar mutations do not publish state-change events/modseqs

**Location:** `crates/owney-storage/src/calendar.rs`, `crates/owney-storage/src/calendar_sharing.rs`

Calendar changes are invisible to push/state-change consumers. Extend the event model and publish mutations when calendar APIs require it.

### ME-07 — Calendar event update cannot distinguish “unchanged” from “clear”

**Location:** `crates/owney-storage/src/calendar.rs:262-314`, `crates/owney-api/src/calendar_sync.rs:114-122`

Option fields are used as update selectors, so there is no way to clear nullable fields. Sync code can also mishandle remote null descriptions.

### ME-08 — `list_active_federations` uses questionable SQLite ordering syntax

**Location:** `crates/owney-storage/src/calendar_sharing.rs:400-407`

`ORDER BY last_sync_at ASC NULLS FIRST` may fail on deployed SQLite versions. Use portable SQLite syntax and add a runtime query test.

### ME-09 — Missing duplicate and uniqueness handling for invitations/shares

**Location:** `crates/owney-storage/src/migrations.rs:301-318`, `crates/owney-storage/src/calendar_sharing.rs:131-145`

Repeated invitations/shares produce duplicates or opaque unique-constraint errors. Add explicit uniqueness and conflict/update behavior.

### ME-10 — Passwordless endpoints leak account/credential existence

**Location:** `crates/owney-api/src/auth.rs:383-475`

Different errors reveal whether an account or passkey exists. Normalize external responses and rate-limit attempts.

### ME-11 — Passwordless challenge state is process-local

**Location:** `crates/owney-api/src/challenge_store.rs:21-103`

Restarts and multiple instances invalidate in-progress flows. Either document a strict single-process deployment or use shared state.

### ME-12 — WebAuthn RP ID/origins are derived too narrowly from hostname

**Location:** `crates/owney-api/src/auth.rs:32-47`, `crates/owney-authn-v2/src/passkey.rs:74-96`

There is no explicit RP ID/origin configuration or startup validation for all deployed hostnames.

### ME-13 — `excludeCredentials` is not used during passkey registration

**Location:** `crates/owney-api/src/auth.rs:302-305`

The same authenticator can be repeatedly registered. Supply existing credential IDs to WebAuthn registration.

### ME-14 — Auth database material is stored as plaintext blobs

**Location:** `crates/owney-storage/src/passwordless.rs`, migration 17→18

Passkey material and recovery hashes are stored in the SQLite database without the blob-store/master-key protection used elsewhere.

### ME-15 — UI build artifacts are tracked and build output is destructive

**Location:** `ui/vite.config.ts:1-10`, `crates/owney-api/static/assets/*`

The build empties a runtime source directory and generated hashed assets are committed. This creates stale artifacts and can delete hand-managed static files.

### ME-16 — UI runtime static-directory default is likely wrong

**Location:** `crates/owney-api/src/lib.rs:61-62`

The runtime defaults to `./static`, while the UI build writes to `crates/owney-api/static`. Running from the project root can produce UI 404s.

### ME-17 — UI calls unregistered calendar methods

**Location:** `ui/src/components/CalendarTester.tsx:36-37`, `crates/owney-jmap-mail/src/lib.rs:36-69`

Calendar tester actions reference methods not registered by the dispatcher.

### ME-18 — ACME RSA key generation blocks async worker

**Location:** `crates/owney-acme/src/acme.rs:177`

Synchronous RSA generation can block a Tokio worker. Use `spawn_blocking` or ECDSA where supported.

### ME-19 — TLS 1.2 is enabled globally without explicit policy

**Location:** workspace TLS dependency configuration

Review whether TLS 1.2 is required and make protocol policy explicit rather than enabling it globally by default.

### ME-20 — Account deletion and migration upgrade coverage is missing

**Location:** `crates/owney-storage/src/lib.rs:325-376`, `crates/owney-storage/src/migrations.rs:423-443`

There is no comprehensive deletion test with new tables and no upgrade test from a pre-change schema through the current version.

## Low Findings and Hygiene

1. `cargo diff --check` reports widespread trailing whitespace in new documentation and a blank line at EOF in `crates/owney-api/src/auth.rs`.
2. `cargo fmt --all -- --check` fails across multiple files, including new code and pre-existing touched files.
3. `cargo clippy --workspace --all-targets -- -D warnings` fails on `crates/owney-authn-v2/src/recovery.rs` for `single_char_add_str`, `len_zero`, and `useless_format`.
4. `owney-acme` has no meaningful automated tests.
5. The UI has no `npm test` script.
6. Error handling collapses database errors into 404/not-found responses in well-known handlers, reducing observability.
7. `reqwest::Client` instances are repeatedly constructed rather than configured and reused.
8. Several storage paths silently downgrade malformed JSON/permissions instead of surfacing corruption.
9. The server metadata response has no configured administrator contact.
10. Recovery-code display/generation formats differ between the API and `owney-authn-v2`.
11. `Calendar/get` omits expected rights fields such as `myRights` and hard-codes subscription state.
12. Documentation claims and implementation state diverge in several places, especially around “complete” authentication and “Phase 2.5 complete” federation behavior.

## Confirmed Test and Coverage Gaps

The following scenarios are not covered by the current tests and should be added before relying on the affected features:

### Federation and calendar

- Unauthenticated sync endpoint is rejected.
- Account lookup does not leak private calendar metadata.
- Invitation sender authentication and calendar ownership are verified.
- Accept creates the correct federation/sharing rows.
- Reject persists and removes the invitation from pending results.
- Invitation mutations are limited to the intended invitee.
- Calendar share rejects non-owned calendars.
- `Calendar/get` returns shared calendars, applies IDs, and reports rights.
- Remote event IDs remain stable across repeated syncs.
- Partial sync failure does not advance the cursor.
- Remote deletes produce removed IDs/tombstones.
- Timestamp/cursor boundary updates are not lost.
- Worker backoff and recovery behavior work as configured.
- SQLite active-federation ordering works with null cursors.

### Passwordless authentication

- Full passkey registration and authentication against storage.
- Passwordless session token authenticates a normal API/JMAP request.
- Disabled accounts cannot finish passkey or recovery authentication.
- Recovery-code generation persists and round-trips through redemption.
- Concurrent recovery-code redemption only succeeds once.
- QR pairing rejects invalid/replayed codes and requires device proof.
- Approval requests are bound to the correct account and source device.
- Concurrent approvals have exactly one successful transition.
- Disabled devices cannot approve.
- Passkey counters, backup flags, and rollback handling persist correctly.
- Auth errors do not expose internal debug details.
- Challenge/session storage is bounded and cleaned up.

### ACME/HTTPS and operations

- Initial issuance when certificates are missing.
- Renewal updates the live TLS acceptor without restart.
- DNS challenge creation is idempotent across retries.
- DNS provider credentials are not exposed through config permissions/logs.
- Certificate/key writes are atomic and owner-only.
- ACME provider behavior is tested against a controlled/staging service.

### Storage and lifecycle

- Existing databases upgrade cleanly through all new migrations.
- Account deletion removes all dependent calendar and auth rows.
- Foreign-key behavior is validated with actual dependent records.
- Malformed stored identifiers return errors rather than generated IDs.

## Verification Performed

The following commands were run after the review:

| Command | Result |
|---|---|
| `cargo check --workspace` | Passed |
| `cargo test --workspace --lib` | Passed; 170 library tests reported passing |
| `cargo clippy --workspace --all-targets -- -D warnings` | Failed in `crates/owney-authn-v2/src/recovery.rs` on three lint errors |
| `cargo fmt --all -- --check` | Failed; multiple formatting differences reported |
| `npm run build` in `ui/` | Passed; Vite produced the static bundle |
| `npm test -- --run` in `ui/` | Failed; `package.json` has no `test` script |
| `git diff --check 6eddf2a^..HEAD` | Reported trailing whitespace and an extra blank line at EOF |

Passing compilation and unit tests do not establish that the reviewed features are safe or deployable because the critical runtime paths are not covered by those tests.

## Recommended Remediation Order

1. Disable or protect all public federation well-known endpoints.
2. Remove all placeholder authentication identities and either finish or gate the passwordless routes.
3. Implement durable, integrated session-token validation.
4. Fix QR pairing and approval proof-of-possession/authorization.
5. Make recovery-code consumption atomic and rate-limited.
6. Enforce calendar ownership and invitation authorization in storage.
7. Complete invitation acceptance/rejection state transitions.
8. Make sync IDs, cursors, deletes, transactions, and worker startup correct.
9. Fix account deletion and migration upgrade behavior.
10. Implement ACME certificate reload, safe secret handling, initial issuance, and idempotent DNS updates.
11. Add HTTP/integration tests for every security boundary and full user flow.
12. Resolve formatting/lint failures and align documentation with actual runtime behavior.

## Review Conclusion

Today’s commits contain substantial useful groundwork, but the implemented security boundaries and production wiring are incomplete. The largest risk is that the documentation and compile/test results can make the changes appear complete while several key paths are either unauthenticated, unreachable, placeholder-backed, or operationally inactive. The findings above should be treated as a pre-deployment remediation list rather than optional polish.
