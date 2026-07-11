# Founding Plan: An AI-Native, PGP-Native Mailserver in Rust

## Context

Email is the most successful federated protocol ever shipped — and it has barely advanced in decades. This project re-imagines the mailserver from first principles: a single Rust binary you deploy on your own domain in minutes, which speaks flawless standards-compliant SMTP to the rest of the world, but whose native interface is a modern realtime API (JMAP + MCP), with AI woven into the core (screening, categorization, summarization, drafting, one-click unsubscribe) and PGP handled so invisibly that users never touch a keyring. The eventual goal includes first-party clients; this plan covers the server.

Research (July 2026) confirms the niche is open: no mailserver has first-party MCP, every polished AI email client is Gmail-locked, and **no standalone JMAP server library exists in any language's ecosystem** — building one is both our largest greenfield component and a publishable contribution.

## Decisions (locked with user)

| Decision | Choice |
|---|---|
| Trust model | **Trusted personal server** — server holds keys, encrypts at rest, AI processes plaintext. PGP for transit + server-managed key discovery/publication |
| Protocols | **SMTP in/out + JMAP + REST + MCP first**; IMAP read-bridge in M7; no IMAP in v1 |
| AI runtime | **Pluggable provider trait; Claude API first-class default**, OpenAI-compatible/Ollama supported |
| Deployment | **Single static binary, SQLite + encrypted blob store**, built-in ACME, setup wizard generating/verifying DNS records, built-in backup/restore; Docker as thin wrapper |
| License | **AGPL-3.0** (dual-license option retained via copyright ownership) |
| PGP backend | **sequoia-openpgp 2.4** (LGPL — compatible with AGPL; high-level misuse-resistant API), behind an internal trait |
| Multi-user | **Multi-account schema from day one; single-user admin flows in v1** (users created via CLI) |
| Screener UX | **HEY-style Screener mailbox** — unknown/uncertain senders land there; approve/block teaches the system |
| SQLite driver | `rusqlite` behind a dedicated writer task (full FTS5/backup-API access); 1-day spike in M0 to confirm vs sqlx |
| Name | Working name `mailserver`; candidates below |

### Name candidates (pick anytime; crates use a neutral `ms-` prefix until then)
- **Loft** — a pigeon loft is where homing pigeons live; short, warm, "mail comes home"
- **Herald** — the messenger who speaks for you; fits the AI-agent angle
- **Homer** — homing pigeon breed + the poet; playful
- **Aviary** — where all your birds/messages live; suits multi-account future

## Workspace Layout

Single Cargo workspace, one deployable binary. `jmap-core` is designed for standalone crates.io publication.

```
mailserver/
├── Cargo.toml                  # workspace, shared deps/lints, release profile (LTO, strip)
├── crates/
│   ├── ms-core                 # domain types, ids, config schema, error taxonomy, firewall traits
│   ├── ms-storage              # SQLite (WAL, rusqlite writer task) + encrypted content-addressed blobs, migrations, modseq
│   ├── ms-events               # typed tokio::broadcast bus (StateChange, DeliveryEvent, AiEvent, SecurityEvent)
│   ├── ms-smtp-in              # inbound SMTP :25/:465/:587, session state machine over smtp-proto, rustls
│   ├── ms-authn                # SPF/DKIM/DMARC(RFC 9989 tree walk)/ARC via mail-auth + FCrDNS → AuthVerdict
│   ├── ms-delivery             # durable outbound queue, MX routing, MTA-STS/DANE (hand-built), DKIM sign, retries, bounces
│   ├── ms-pgp                  # key lifecycle, WKD, Autocrypt, encrypt/sign/verify/decrypt (sequoia behind trait)
│   ├── jmap-core        (pub)  # clean-room generic JMAP server lib: RFC 8620 envelope/dispatch/blobs/push + RFC 8887 WS
│   ├── ms-jmap-mail            # RFC 8621 Mailbox/Email/Thread/EmailSubmission bound to storage; vendor `urn:<name>:ai` capability
│   ├── ms-search               # FTS (SQLite FTS5 first; tantivy behind trait), snippets
│   ├── ms-ai                   # AiProvider trait (Claude, OpenAI-compat), skills, audit log + undo, budgets
│   ├── ms-mcp                  # MCP server (rmcp; streamable HTTP + stdio), scoped tool tokens
│   ├── ms-api                  # axum: JMAP endpoints, REST, SSE/WS push, auth, WKD well-known, MTA-STS vhost, health
│   ├── ms-setup                # wizard: DNS record gen (MX/SPF/DKIM/DMARC/MTA-STS/TLS-RPT/WKD) + verification, ACME, preflight
│   ├── ms-backup               # consistent snapshots (SQLite backup API + blob manifest), restore, schedules, off-site
│   ├── ms-testkit              # in-process server harness, testcontainers fixtures, JMAP conformance suite, live-fire e2e
│   └── ms-cli                  # admin subcommands
└── bin/mailserverd             # single binary: serve | setup | backup | admin | doctor
```

**Foundation stack**: tokio, rustls 0.23 (PQ-hybrid TLS default), axum, hickory-resolver 0.26, mail-parser 0.11, mail-auth 0.11, mail-send 0.6, mail-builder, smtp-proto 0.2, sequoia-openpgp 2.4, rusqlite, rmcp. **Avoid**: Stalwart server code and `sieve-rs` (AGPL-incompatible-with-our-independence goals aside, we want clean-room JMAP anyway), async-std (dead), OpenSSL.

**Design rule (bus-factor firewall)**: every risky dependency (Stalwart `mail-*` crates — single maintainer; PGP backend; FTS engine; AI provider) sits behind an internal trait in `ms-core`, so a vendored fork or swap is a one-crate change.

## Architecture

### Inbound flow
```
:25/:465/:587 → rustls → ms-smtp-in session (FCrDNS, rate limits; SPF at MAIL FROM;
  recipient validation at RCPT — reject unknown users HERE, never bounce later)
→ ms-authn: parse → DKIM verify → DMARC aligned → ARC verify → AuthVerdict
→ Screening (in-SMTP, hard ~5–8s budget): deterministic rules first (blocklists, DMARC
  p=reject honor, user rules) → optional cheap AI screener (fail-open, strict timeout)
  → verdict ladder: accept | Screener mailbox (default for "unsure") | 550 at DATA.
  Reject-at-SMTP-time or accept — NEVER accept-then-bounce (no backscatter).
→ ms-pgp: decrypt if encrypted-to-us, verify sigs, harvest Autocrypt/attached keys → pgp_peers
→ ms-storage (one txn): encrypted raw blob + decrypted-plaintext blob, Email row, thread
  linkage, AuthVerdict + PgpStatus, per-type modseq bump, FTS insert
→ ms-events broadcast → JMAP push (SSE/WS) + webhooks         [realtime clients]
                      → async AI enrichment: categorize (→ keyword/mailbox patch),
                        summarize (→ ai_annotations), RFC 8058 unsubscribe detection
```
Expensive AI runs **after** the 250 OK; only the optional cheap screener is synchronous.

### Outbound flow
```
JMAP EmailSubmission | REST /send | MCP send_email  →  one internal SubmissionService
→ mail-builder MIME (+ RFC 9788 header protection when encrypting)
→ ms-pgp: recipient keys (peer table → WKD fetch); encrypt iff ALL recipients have usable
  keys (or user forces); sign by default; inject Autocrypt header on every outbound message
→ DKIM sign (RSA-2048 always, Ed25519 dual-sign optional) → durable queue
→ per-domain workers: MX resolve → MTA-STS policy fetch/cache (+ DANE when DNSSEC) →
  mail-send delivery; backoff 1m/5m/30m/2h/4h…≤48h → DSN; bounce parse → submission status
→ Sent copy stored via the inbound storage path (searchable, threaded, AI-visible)
```

### Storage model (JMAP-shaped from day one)
- Tables: `accounts`, `mailboxes`, `emails`, `email_mailbox`, `email_keyword`, `threads`, `blobs`, `states` (per-account per-type modseq for `/changes`), `push_subscriptions`, `identities`, `submissions`+`queue`, `pgp_own_keys`, `pgp_peers`, `ai_annotations`, `ai_actions`, `rules`, `unsubscribe_targets`.
- Blobs: filesystem, blake3 content-addressed, per-blob XChaCha20-Poly1305 keys wrapped by a master key (0600 keyfile, optional passphrase). Raw RFC 5322 original always retained.
- **Explicit encryption boundary**: blob bodies + PGP secret keys always encrypted; SQLite metadata + FTS index hold plaintext (inherent to server-side search in the trusted-server model). Documented threat model; disk encryption recommended; SQLCipher later.
- Delta-sync discipline: all writes go through the `ms-storage` API, which bumps modseq — this single rule makes JMAP `/changes`, push, and realtime sync trivial.

### Realtime
`ms-events` = typed `tokio::broadcast`. Consumers: JMAP push manager (coalesced StateChange over EventSource + RFC 8887 WebSocket), signed webhooks, AI worker pool, MCP notifications, metrics. No external broker. Lossy-lag is fine: push is a hint, `/changes` from the last state token is the truth.

## AI Layer

- `AiProvider` trait (chat + tools + JSON-schema output + capability/cost class); `ClaudeProvider` default, `OpenAiCompatProvider` covers Ollama/vLLM/gateways. Config maps **skill → provider+model+budget** (cheap/local for screening, Claude for drafting).
- **Skills**: Screener (sync-optional, fail-open), Categorizer, Summarizer, Unsubscribe agent (RFC 8058 List-Unsubscribe-Post → one POST; mailto/link flows require confirmation), Drafter (drafts only, never auto-send), NL search (query → structured JMAP filter, executed locally).
- **Audit + undo**: every AI mutation goes through the same `CommandService` as humans, tagged `actor: Ai{skill,model}`, recorded in `ai_actions` with an `inverse_patch`, confidence, and rationale. Undo = apply inverse patch. Per-skill kill switch + daily token budgets. Sending is never autonomous in v1.
- **MCP** (`ms-mcp`): tools are 1:1 wrappers over the internal service layer — `search_email`, `get_email`, `get_thread`, `list_mailboxes`, `move_email`, `label_email`, `mark_read`, `delete_email`, `create_draft`, `send_email` (scoped permission), `summarize_thread`, `unsubscribe`, `screen_sender`, `get_ai_activity`, `undo_action`. Streamable HTTP + stdio; scopes bound to tokens. JMAP vendor capability `urn:<name>:ai` exposes the same methods to our clients — MCP and JMAP are two skins over one service layer.

## PGP-Native Design

Emission posture (2026-correct): **v4 keys (Ed25519/X25519), SEIPDv1 default for GnuPG-legacy interop, SEIPDv2 when recipient signals support, RFC 9980 PQ ML-KEM-768+X25519 subkeys feature-gated; accept v6 inbound; never emit LibrePGP v5.**

1. Keygen at account creation; secret keys wrapped by master key; user never sees a keyring. Autocrypt-2-style ~10-day rotating encryption subkeys behind a flag (forward secrecy).
2. Publication: WKD served at `/.well-known/openpgpkey/` (wizard verifies), Autocrypt header on every outbound message, optional keys.openpgp.org upload.
3. Harvesting: Autocrypt headers, attached keys, gossip → `pgp_peers` state machine (available/mutual/reset).
4. Opportunistic encryption on send + sign-by-default; per-message override.
5. Per-message stored `pgp_status {encrypted, signature, key_change}` surfaced via JMAP vendor property so clients render trust without doing crypto; key-change for a known peer raises a `SecurityEvent`.
6. Trusted-server consequence: plaintext indexed and AI-visible; per-peer "sensitive" flag excludes a correspondent from AI + FTS.

## Roadmap (8 milestones, ~7–9 months solo)

- **M0 — Skeleton (1–2 wk)**: workspace compiles; ms-core config; ms-storage with migrations + encrypted blob round-trip in tests; ms-events; `mailserverd serve` runs; CI (fmt, clippy, test, cargo-deny). Includes rusqlite-vs-sqlx spike.
- **M1 — Receives real mail (3–4 wk)**: SMTP inbound + STARTTLS/ACME, session state machine, SPF/DKIM/DMARC/ARC verdicts stored, threading, `admin inbox/show` CLI. **Demo**: point MX at a VPS, send from Gmail, read it with auth verdicts via CLI.
- **M2 — Sends mail that lands (3–4 wk)**: setup wizard (DNS gen + verification polling), DKIM signing, durable queue/retries/bounces, MTA-STS outbound, submission auth, `doctor`, smarthost relay mode. **Demo**: fresh domain → all DNS green → Gmail "Show original" shows SPF/DKIM/DMARC pass, inbox placement. **Gate: go/no-go on the self-hosted-deliverability thesis.**
- **M3 — JMAP core + realtime (5–6 wk, largest greenfield)**: `jmap-core` lib, ms-jmap-mail (get/set/query/changes + EmailSubmission), SSE + RFC 8887 WS push, bearer auth, minimal web debug UI. **Demo**: a third-party JMAP client does live mail; two sessions see each other's changes in realtime.
- **M4 — PGP-native (3–4 wk)**: keygen, WKD serving, Autocrypt in/out, harvesting, opportunistic encrypt/sign, decrypt/verify with stored status, key-change alerts. **Demo**: encrypted round-trip with Thunderbird + Delta Chat, zero manual key handling; `gpg --locate-keys` finds our user via WKD.
- **M5 — AI + MCP (4–5 wk)**: provider abstraction, Screener/Categorizer/Summarizer/Drafter, audit+undo, RFC 8058 one-click unsubscribe automation, Screener mailbox UX, MCP server with scoped tokens. **Demo**: Claude over MCP triages a live inbox — categorize, summarize, draft, unsubscribe — every action visible and undoable. *The "make email fun again" demo.*
- **M6 — Self-hosting polish (3–4 wk)**: static releases (linux x86_64/aarch64, macOS) + thin Docker, scheduled consistent backups + tested restore, safe self-update, continuous `doctor` (DNS drift, blocklists, cert expiry, queue health), DMARC aggregate-report ingestion. **Demo**: fresh VPS → running in <10 min; kill the box, restore, nothing lost.
- **M7 — Hardening + bridges + beta (4–6 wk)**: fuzzing campaigns (SMTP/MIME/PGP/JMAP), load tests, NL-search skill, tantivy upgrade if FTS5 bites, **IMAP4rev2 read-only bridge**, security review, public beta, publish `jmap-core`. **Demo**: Apple Mail reads the mailbox over IMAP; external beta users self-host.

Schedule risks: M2 (deliverability) and M3 (JMAP scope).

## Testing & Verification

- **Property tests** (proptest): SMTP session never panics on arbitrary command sequences; threading; modseq invariants (`/changes` replay always converges); backoff schedule.
- **Fuzzing** (cargo-fuzz, nightly CI): SMTP commands, MIME at our boundary, PGP packets, JMAP envelopes.
- **JMAP conformance suite** (built in ms-testkit from RFC 8620/8621 MUSTs — none exists publicly; doubles as `jmap-core`'s published test suite) + interop with 2–3 real JMAP clients per milestone.
- **Container integration** (testcontainers): Postfix/Mox peer for SMTP loopback; GnuPG matrix (2.2/2.4/sq) encrypt/sign/verify against our output; rspamd as adversarial outbound-hygiene check.
- **Live-fire e2e** (env-gated, dedicated accounts): send to Gmail test account, assert `Authentication-Results` pass + inbox placement via Gmail API; receive from Gmail/Outlook, assert our verdicts. Run before every release.
- **Backup drills in CI**: restore previous release's backup into the new version, run conformance suite (migration + restore in one test).
- **Per-milestone manual verification**: each milestone's Demo line above is its acceptance test, executed on a real VPS + real domain.

## Risks

1. **Self-hosted outbound deliverability** → wizard preflight (port-25 probe, PTR/FCrDNS, blocklist lookup) before commit; first-class smarthost mode keeping DKIM + all features; DMARC report ingestion for visibility. M2 is a cheap kill/pivot gate.
2. **JMAP scope creep** → frozen to mail-only core; all nonstandard surface in one vendor capability; conformance suite defines done.
3. **Single-maintainer Stalwart crates** → pinned versions, cargo-deny advisories, trait firewall, upstream goodwill.
4. **PGP legacy interop / LibrePGP schism** → conservative emission profile, accept-everything-reasonable inbound, GnuPG CI matrix.
5. **AI false positives at SMTP time** (cardinal sin) → verdict ladder defaults to Screener-not-reject; hard rejects only from deterministic rules/explicit blocks; everything logged + reversible.
6. **AI cost/latency/privacy** → per-skill model routing, hard token budgets, fail-open timeouts, per-peer exclusion, supported full-local mode.
7. **Solo-dev scope (this is 4 products)** → demo-gated milestones with explicit cut lines (IMAP bridge cuttable; calendars never in v1); publish `jmap-core` to attract contributors.

## First files to create (M0, dependency order)

1. `Cargo.toml` — workspace manifest, shared dep versions, lints, release profile
2. `crates/ms-core/src/lib.rs` — domain types, config schema, firewall traits
3. `crates/ms-storage/src/lib.rs` — schema, modseq discipline, encrypted blob store
4. `crates/ms-events/src/lib.rs` — typed event bus
5. `bin/mailserverd/src/main.rs` — `serve | setup | backup | admin | doctor` scaffold
6. `crates/ms-smtp-in/src/session.rs` — SMTP session state machine (start of M1)
