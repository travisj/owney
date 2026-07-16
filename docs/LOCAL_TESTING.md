# Local Testing Lab

**Status**: Implemented and verified end-to-end 2026-07-15
**Tool**: `scripts/lab.sh` — two local instances, no DNS, no TLS, no root

## What it is

`scripts/lab.sh` runs two complete mailserver instances on localhost and gives
you one-line commands to feed mail in, inspect what the server did with it,
call JMAP, and exercise calendar federation between them:

```
alice: domain alice.local   SMTP 127.0.0.1:2525   API http://127.0.0.1:8381
bob:   domain bob.local     SMTP 127.0.0.1:2526   API http://127.0.0.1:8382
```

Each instance's `[delivery] smarthost` points at the other's SMTP port, so
alice→bob mail flows through the real pipeline (submit → queue → DKIM sign →
SMTP → receive → auth-verify → spam-scan → ingest → enrichment) with **zero
DNS lookups**. State lives in `.lab/` (gitignored). Ports are chosen to never
collide with a production instance on 25/8380.

## Quickstart

```bash
scripts/lab.sh build          # cargo build the debug binary
scripts/lab.sh up             # init + start both instances (idempotent)
scripts/lab.sh send alice invite
scripts/lab.sh inbox alice screener     # first contact lands in the screener!
scripts/lab.sh jmap alice Email/query '{"accountId":"$ACCOUNT_ID"}'
scripts/lab.sh down           # clean shutdown (SIGINT → WAL checkpoint)
scripts/lab.sh reset          # nuke .lab/ and start over
```

Run `scripts/lab.sh` with no arguments for the full command list.

## Testing inbound mail + server processing

Fixtures are injected over real SMTP as an external sender
(`carol@external.test` by default):

| Fixture      | What it exercises |
|--------------|-------------------|
| `plain`      | Basic ingest, threading, screener routing |
| `newsletter` | `List-Unsubscribe` + one-click → `unsubscribe` server attribute |
| `invite`     | `text/calendar` VEVENT attachment (with a folded line) → `calendarInvite` server attribute |

```bash
scripts/lab.sh send alice newsletter
scripts/lab.sh send alice invite
scripts/lab.sh send-raw alice path/to/message.eml   # anything else
```

Verify the enrichment results (the worker runs within a couple of seconds):

```bash
scripts/lab.sh jmap alice Email/query '{"accountId":"$ACCOUNT_ID"}'
scripts/lab.sh jmap alice Email/get \
  '{"accountId":"$ACCOUNT_ID","ids":["<id>"],"properties":["subject","serverAttributes"]}'
scripts/lab.sh jmap alice EmailAttribute/dismiss \
  '{"accountId":"$ACCOUNT_ID","emailId":"<id>","kind":"calendarInvite"}'
```

The literal string `$ACCOUNT_ID` in jmap args is replaced with the instance's
real account id (fetched from the session and cached).

## Testing outbound / cross-server delivery

```bash
scripts/lab.sh send-between alice bob --subject "hello"
scripts/lab.sh inbox bob screener        # arrives within ~2s (queue poll)
scripts/lab.sh show bob <email_id>       # raw message — DKIM-Signature present
scripts/lab.sh queue alice               # should be empty after delivery
```

## Testing calendar federation

The lab always starts serve with federation enabled and wired for loopback
(env vars below). Full smoke flow:

```bash
scripts/lab.sh admin alice create-calendar alice@alice.local Team
# -> created calendar Team (<cal_id>)
scripts/lab.sh admin alice create-event alice@alice.local <cal_id> \
  --title Standup --start 1784710800 --end 1784712600

scripts/lab.sh jmap alice Calendar/share \
  '{"accountId":"$ACCOUNT_ID","calendarId":"<cal_id>","inviteeEmail":"bob@bob.local","sharingType":"sharing"}'
# -> {"federated": true, "invitationId": "<inv_id>", "status": "pending"}

scripts/lab.sh jmap bob CalendarInvitation/get '{"accountId":"$ACCOUNT_ID"}'
scripts/lab.sh jmap bob CalendarInvitation/set \
  '{"accountId":"$ACCOUNT_ID","action":"accept","invitationId":"<inv_id>"}'

# Within ~10s the SyncWorker pulls; the mirror calendar + events appear:
scripts/lab.sh jmap bob Calendar/get '{"accountId":"$ACCOUNT_ID"}'
sqlite3 .lab/bob/data/mail.db "SELECT title, origin FROM calendar_events;"
```

`sharingType` is required (no default). This drives the real signed-HTTP
federation protocol — discovery, TOFU cert pinning, PGP-signed requests,
replay protection — just over loopback http.

## Pointing real JMAP clients at the lab

The JMAP session's `apiUrl` uses logical hostnames (`http://alice.local:8381`)
because the federation identity is derived from the URL host. `lab.sh` itself
always talks to `127.0.0.1` directly, but a real client following the session
document needs name resolution — a one-time `/etc/hosts` addition:

```bash
scripts/lab.sh hosts        # prints the two lines to append (needs sudo to edit)
scripts/lab.sh token alice  # bearer token for the client
scripts/lab.sh session alice
```

Session URL for a client: `http://alice.local:8381/.well-known/jmap` with
`Authorization: Bearer <token>`.

## How the no-DNS trick works

- **Outbound**: `[delivery] smarthost` selects a `StaticRouter` that returns a
  fixed relay for every domain — no MX lookups (`bin/owneyd/src/main.rs`,
  `crates/owney-delivery/src/router.rs`). Outbound TLS is opportunistic and
  falls back to plaintext for the localhost peer.
- **Inbound**: STARTTLS only activates when `[tls]` is configured; plaintext
  SMTP works. SPF/DKIM/DMARC checks run but are fail-open (verdicts recorded
  as `Authentication-Results`, never blocking). The DNSBL check is currently
  a stub.
- **Federation**: env vars read by `FederationConfig::from_env`
  (`crates/owney-api/src/fed_sig.rs`):
  - `OWNEY_FEDERATION_ENABLED=1`
  - `OWNEY_FEDERATION_ALLOW_PRIVATE_IPS=1` — permits http + loopback targets
  - `OWNEY_FEDERATION_URL_OVERRIDES=alice.local=http://127.0.0.1:8381,bob.local=http://127.0.0.1:8382`
    — logical domain → wire URL map, applied to every outbound federation call
  - `OWNEY_FEDERATION_SYNC_INTERVAL_SECS=10` — fast reconciliation pulls
    (default 300)

## Gotchas

1. **"Where's my email?" → the screener.** The deterministic HEY-style
   screener routes the FIRST message from any sender to the `screener`
   mailbox; later messages from that sender go to the inbox. `lab.sh inbox`
   prints a hint when this happens. Turn it off with `enabled = false` under
   `[ai]` in `.lab/<i>/mailserver.toml` (unsubscribe/calendar-invite
   detection still runs; note the config is regenerated on every `up`).
2. **Self-send is unsupported.** The smarthost routes ALL outbound to the
   peer, which rejects recipients for other domains. `send-between alice
   alice` errors with an explanation; use `send alice <fixture>` to test
   inbound instead.
3. **Delivery latency ≤2s.** Mail queued by the admin CLI is picked up by
   serve's polling worker (`poll_interval_secs = 2`); there is no
   cross-process wake.
4. **Doctor log noise.** The health daemon logs DNS failures for `.local`
   domains every 60s in `server.log` — cosmetic.
5. **AI is `provider = "none"`.** Deterministic skills only; no API key
   needed. Model-backed skills (categorize, summarize) need a real provider —
   edit the generated config if you want them.

## What works / what doesn't yet

Works (verified live 2026-07-15): up/down/status/reset/logs lifecycle;
all three fixtures producing their server attributes; `send-raw`; alice↔bob
delivery with DKIM signature present; self-send guard; the full federation
smoke (share → accept → event synced with `origin=remote` in ~10s);
`jmap`/`session`/`token` helpers; restart idempotency (tokens and federation
state survive `down`/`up`).

Not yet:
- No `lab.sh` subcommand wraps the federation smoke (it's the documented flow
  above; automate once the flow stabilizes).
- No IMAP (serve never binds it) and no push-event tail command — use
  `curl -N http://127.0.0.1:8381/jmap/eventsource -H "Authorization: Bearer $(scripts/lab.sh token alice)"`.
- Calendar events can be created only via `admin create-event` (no JMAP
  `CalendarEvent/set` exists yet).
