# owney

A mailserver for today: a single Rust binary you deploy on your own domain in minutes. It speaks flawless, standards-compliant SMTP to the rest of the world — but its native interface is a modern realtime API (JMAP + REST + MCP), with AI woven into the core (screening, categorization, summarization, drafting, one-click unsubscribe) and OpenPGP handled so invisibly that you never touch a keyring.

**Status: M7 Week 3 — IMAP read-only bridge shipped; preparing for public beta.**

## What It Does

owney is a personal mailserver for self-hosters who want:

- **Complete ownership**: your server, your domain, your keys. Everything runs under your control.
- **Modern protocols**: native JMAP + REST + MCP APIs alongside IMAP (read-only) and SMTP. Real-time push via WebSocket and Server-Sent Events.
- **AI-first mail**: Claude integrated at the core for intelligent screening, categorization, summarization, and draft composition — all auditable and undoable.
- **Cryptography by default**: OpenPGP key generation at account creation, WKD publication, Autocrypt headers, opportunistic encryption. Zero keyring UX.
- **Production-grade mail**: flawless SPF/DKIM/DMARC/ARC verification, MTA-STS outbound policy enforcement, DANE support, durable delivery queues with smart retries.
- **One binary**: SQLite + encrypted blob store, built-in ACME, setup wizard that generates and verifies DNS records, consistent backups with tested restore.

## Why It Matters

Email is the most successful federated protocol ever shipped — and it has barely advanced in 30 years. Existing solutions force a choice:
- **Commercial**: Gmail/Outlook lock you into their ecosystem and AI practices.
- **Self-hosted**: Dovecot + Postfix + rspamd stacks are powerful but require a DevOps team.
- **Modern clients**: Mimestream, Superhuman, HEY all speak only proprietary APIs or Gmail.

owney splits the difference: a mailserver sophisticated enough for production deliverability, simple enough to run on a $5/month VPS, and intelligent enough to be genuinely useful. JMAP + MCP mean external clients (web, mobile, desktop) can speak the server's native language. Publishing `jmap-core` as a standalone library unblocks the first open JMAP server ecosystem.

## Current State (M7 Week 3)

### What's Working

✅ **Inbound mail**: SMTP :25/:465/:587 with STARTTLS/TLS, SPF/DKIM/DMARC/ARC verification, threading, deterministic + AI screening (HEY-style Screener mailbox).

✅ **Outbound mail**: DKIM signing, MTA-STS policy enforcement, DANE support, durable queue with smart retries (1m/5m/30m/2h/4h backoff up to 48h), DSN bounce handling.

✅ **JMAP core**: RFC 8620/8621 envelope + dispatch, Email/Mailbox/Thread/EmailSubmission methods, stateful `/changes` with modseq discipline, RFC 8887 WebSocket + Server-Sent Events push.

✅ **PGP-native**: account-creation key generation, WKD serving, Autocrypt in/out, key harvesting state machine, per-message encryption/signature status.

✅ **AI + audit**: Screener (sync, optional, fail-open), Categorizer, Summarizer, RFC 8058 one-click unsubscribe automation. Every AI action logged, attributed, and reversible.

✅ **MCP server**: 1:1 wrapper over internal services (`search_email`, `get_email`, `move_email`, `send_email`, `summarize_thread`, etc.) with scoped token permissions.

✅ **Self-hosting polish**: static releases (Linux x86_64/aarch64, macOS), Docker wrapper, scheduled consistent backups with tested restore, safe self-update, continuous `doctor` daemon.

✅ **IMAP read-only bridge**: IMAP4rev2 connection-oriented mail access; write operations redirect to JMAP for audit trail.

### What's Not Yet

❌ **Calendar/Contacts**: v2 feature; in-scope for extensibility but not v1.

❌ **Full IMAP write support**: deliberate architectural choice (write flows through JMAP for audit).

❌ **Web client**: owney is an API-first server; third-party JMAP clients (Glow, Mimestream, etc.) are the primary surface.

❌ **Mobile first-party clients**: native iOS/Android use JMAP + MCP to the server.

❌ **Tantivy full-text search**: FTS5 (SQLite) is sufficient for M7; tantivy upgrade is a follow-up if needed.

## Getting Started

**TL;DR**: 5-minute quick start below. For production setup, see `docs/GETTING-STARTED.md` (interactive 30 min) or `docs/SETUP.md` (complete reference).

### Quick Start (5 minutes)

```bash
# 1. Get the binary
curl -fsSL https://releases.github.com/owney/latest/owneyd-$(uname -s) \
  -o /usr/local/bin/owneyd && chmod +x /usr/local/bin/owneyd

# 2. Initialize on a fresh VPS (requires a domain you control)
owneyd setup --domain example.com

# 3. Follow the wizard: it generates DNS records, verifies them, and sets up TLS via ACME

# 4. Create your account
owneyd admin create-account you@example.com

# 5. Point your mail client to mail.example.com (JMAP or IMAP)
```

See `docs/GETTING-STARTED.md` for a fuller walkthrough.

## Status & Roadmap

| Milestone | Status | Theme |
|-----------|--------|-------|
| **M0** | ✅ Done | Workspace, config, storage, async runtime |
| **M1** | ✅ Done | Inbound SMTP, SPF/DKIM/DMARC/ARC, threading |
| **M2** | ✅ Done | Outbound DKIM, MTA-STS, delivery queue, setup wizard |
| **M3** | ✅ Done | JMAP core lib (jmap-core published to crates.io), realtime push |
| **M4** | ✅ Done | PGP-native (keygen, WKD, Autocrypt, opportunistic encryption) |
| **M5** | ✅ Done | AI + MCP (Claude provider, audit + undo, Screener, Categorizer, Summarizer) |
| **M6** | ✅ Done | Self-hosting polish (static releases, Docker, backups, doctor daemon) |
| **M7** | 🔄 Week 3 | Hardening, fuzzing, IMAP read-only bridge, **public beta launch** |
| **M8** (Q4 2026) | 📋 Planned | Calendar/Contacts, tantivy FTS, cloud backup integrations |

**Next**: Public beta July 2026. See `docs/BETA-LAUNCH.md` for launch checklist.

## Principles

- **Trusted personal server**: your server, your domain, your keys. Everything
  encrypted at rest; AI processes your mail on your machine's terms.
- **Interop is non-negotiable**: correct SMTP in/out, SPF/DKIM/DMARC/ARC,
  MTA-STS, deliverability first. The modern parts never break the old ones.
- **One binary**: SQLite + encrypted blob store, built-in ACME, setup wizard
  that generates and verifies your DNS records, built-in backup/restore.
- **AI with an audit trail**: every AI action is recorded, attributed, and
  undoable. Drafts, never autonomous sends.
- **PGP-native**: keys generated at account creation, published via WKD,
  Autocrypt in/out, opportunistic encryption. Zero keyring UX.

## Layout

Cargo workspace; one deployable binary (`bin/owneyd`), crate-per-concern
under `crates/`. `crates/jmap-core` (M3) is a clean-room generic JMAP server
library intended for standalone publication.

## License

AGPL-3.0-only. See `LICENSE`.
