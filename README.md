# mailserver (working name)

A from-first-principles mailserver for today: a single Rust binary you deploy on
your own domain in minutes. It speaks flawless, standards-compliant SMTP to the
rest of the world — but its native interface is a modern realtime API (JMAP +
REST + MCP), with AI woven into the core (screening, categorization,
summarization, drafting, one-click unsubscribe) and OpenPGP handled so invisibly
that you never touch a keyring.

Status: **M0 — skeleton**. See `docs/PLAN.md` for the founding plan.

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

Cargo workspace; one deployable binary (`bin/mailserverd`), crate-per-concern
under `crates/`. `crates/jmap-core` (M3) is a clean-room generic JMAP server
library intended for standalone publication.

## License

AGPL-3.0-only. See `LICENSE`.
