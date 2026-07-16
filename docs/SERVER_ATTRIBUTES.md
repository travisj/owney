# Server-Added Email Attributes

**Status**: Implemented and verified end-to-end 2026-07-15 (see Verification below)
**Supersedes**: the `ai_annotations` table (M5), which is now dormant

## What this is

When the server receives an email, detectors attach structured, per-kind data
("attributes") that clients read alongside the email:

| Kind             | Producer                              | Payload |
|------------------|---------------------------------------|---------|
| `unsubscribe`    | deterministic (`detect_unsubscribe`)  | `{http, mailto, oneClick}` (RFC 8058/2369) |
| `calendarInvite` | deterministic (`detect_calendar_invite`) | `{method, uid, summary, location, organizer, start, end, startAt, endAt}` |
| `summary`        | model-backed (`summarize`)            | `{summary, actionItems}` |
| `needsAttention` | **reserved, not implemented**         | — |

The data model accepts arbitrary kinds; adding a detector requires no schema
change.

## Data model

`email_attributes` (migration 19→20, `crates/owney-storage/src/migrations.rs`):

- **One attribute per (email, kind)** — `UNIQUE(email_id, kind)`; re-detection
  upserts `content` and `updated_at`.
- **Dismissal is sticky**: `dismissed_at` is set by the account owner and is
  *not* cleared by re-detection. A future kind that must "re-raise" on new
  evidence (e.g. `needsAttention`) will need an explicit un-dismiss path —
  none exists today.
- `content` is a JSON string; shape is per-kind and not validated by storage.
- Old `ai_annotations` rows were copied in (newest per `(email_id, kind)`
  wins; the old table allowed duplicates). `ai_annotations` itself is kept
  dormant — dropping it is deferred to a future migration after a release
  ships on the new table.

## The modseq contract

Every attribute write (`set_email_attribute`, `dismiss_email_attribute` in
`crates/owney-storage/src/attributes.rs`) bumps the **Email** modseq, stamps
the parent email's `updated_modseq`, and publishes `Event::StateChange` — all
in one transaction. Consequences:

- Clients learn about late-arriving attributes through the ordinary
  `Email/changes` + push cycle: the email shows up in `updated`, they
  re-fetch, and `serverAttributes` is in the Email object.
- No separate `EmailAttribute/get` or `/changes` exists, deliberately —
  attributes ride the Email object's state.
- The enrichment worker only processes `changes.created`, so its own
  attribute writes (which surface as `updated`) do not re-trigger it.

## JMAP surface

**Read** — `Email/get` returns a `serverAttributes` property (also valid in
`properties` selection):

```json
"serverAttributes": {
  "unsubscribe": {
    "value": {"http": "https://…", "mailto": "…", "oneClick": true},
    "dismissed": false,
    "createdAt": "2026-07-15T00:12:39Z",
    "updatedAt": "2026-07-15T00:12:39Z"
  }
}
```

**Write** — one mutation only, under capability
`urn:owney:params:jmap:attributes`
(`crates/owney-jmap-mail/src/attribute_methods.rs`):

```json
["EmailAttribute/dismiss",
 {"accountId": "…", "emailId": "…", "kind": "calendarInvite"}, "0"]
```

Returns `{emailId, kind, dismissed: true, newState}`. Errors: `forbidden`
(email belongs to another account), `invalidArguments` (no active attribute
of that kind), `accountNotFound` (accountId is not the authenticated
account). Dismissing an already-dismissed attribute is an error, so a client
acting on stale state notices.

MCP's `get_email` returns the same data as `serverAttributes` (kind, content,
dismissed) — `crates/owney-mcp/src/service.rs`.

## Detector pipeline

Detectors are skills in the enrichment worker
(`crates/owney-ai/src/worker.rs`), a durable modseq-cursor loop woken by the
event bus. The calendar-invite detector collects `text/calendar` /
`application/ics` / `*.ics` MIME parts in `EmailContext::load` and extracts
the first VEVENT with a minimal RFC 5545 reader (`crates/owney-ai/src/ics.rs`
— line unfolding, quoted-param-aware property split, TEXT unescaping).
`startAt`/`endAt` epoch values are computed only for unambiguous UTC
(`…Z`) and all-day (`YYYYMMDD`) forms; TZID-local times pass through as raw
strings for the client to interpret.

**Behavior change (2026-07-15)**: the worker is now spawned even when
`ai.enabled = false`. In that mode it runs metadata-only detectors
(unsubscribe, calendar invite) via `AiConfig::deterministic_only()` — no
mail is moved (screener off) and no model is called. Previously a disabled
AI config meant no enrichment at all.

## What works / what doesn't yet

Works (each claim names its proof):

- Upsert, dismissal stickiness, modseq bump, StateChange publish, cross-account
  rejection — `cargo test -p owney-storage attributes` (4 tests)
- Migration data copy + dedup — `cargo test -p owney-storage migrations`
- `Email/get` projection, dismiss round-trip, cross-account `forbidden` /
  `accountNotFound` — `cargo test -p owney-jmap-mail --lib` (3 tests)
- ICS parsing (folding, TZID passthrough, all-day, no-VEVENT) —
  `cargo test -p owney-ai --lib ics`
- Detector end-to-end through the worker —
  `cargo test -p owney-ai --test enrichment` (calendar_invite_in_mime_part_is_detected)
- Live server: SMTP ingest with List-Unsubscribe + ICS → push StateChange →
  `Email/get` shows both attributes → dismiss → push → re-fetch dismissed →
  second account's dismiss rejected `forbidden` (manual run 2026-07-15,
  scratch instance, schema v20)

Not yet:

- `needsAttention` detector (kind reserved only)
- Un-dismiss (no API; dismissal is permanent for a given attribute)
- Multiple VEVENTs per message (only the first is extracted)
- TZID-aware epoch conversion (raw values passed through instead)
- Attribute-based `Email/query` filtering (e.g. "has an undismissed invite")
- Batched attribute loading in `Email/get` (one query per email; fine at
  current scale, matches the existing per-row blob fetch)
