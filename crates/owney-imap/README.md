# owney-imap: IMAP4rev2 Read-Only Bridge

RFC 9051 (IMAP4rev2) server that lets standard email clients (Thunderbird, Apple Mail, iOS Mail, Outlook) **read** the mailbox while forcing **sends** through JMAP.

## Why Read-Only?

JMAP offers end-to-end encryption and signing by default. If clients could APPEND (send) via IMAP, they'd bypass that protection. Instead:

- **Read**: IMAP clients fetch messages, flags, folders (standard IMAP4rev2)
- **Send**: Clients are redirected to use JMAP EmailSubmission (preserves encryption/signing)

## Supported Commands

✅ **Fully implemented (stub phase 1)**:
- `LOGIN`, `LOGOUT`, `CAPABILITY`
- `SELECT`, `LIST`, `NOOP`

✅ **Planned (phase 2)**:
- `SEARCH`, `FETCH`, `STATUS`
- `LSUB`, `NAMESPACE`
- `STARTTLS`

❌ **Explicitly Blocked**:
- `APPEND` → "Use JMAP EmailSubmission"
- `STORE` → "Use JMAP Email/set"
- `DELETE`, `EXPUNGE` → "Use JMAP Email/set with destroy"
- `COPY`, `MOVE` → "Use JMAP Email/set"

## Client Compatibility

| Client | Status | Notes |
|--------|--------|-------|
| Thunderbird | 🟡 Planned | Will work once SEARCH/FETCH implemented |
| Apple Mail | 🟡 Planned | iOS/macOS support in phase 2 |
| Outlook | 🟡 Planned | Via IMAP mode |
| Gmail Web | ✅ Use JMAP | Native client via /jmap endpoint |

## Architecture

```
IMAP Client (port 143/993)
    ↓
TcpListener (accept connections)
    ↓
ImapSession (per-connection state machine)
    ↓
Handler (command dispatch)
    ↓
Storage (JMAP queries)
```

## Configuration

Add to `mailserver.toml`:

```toml
[imap]
listen = "0.0.0.0:143"
enabled = true
```

Set `enabled = false` to disable the bridge entirely.

## Testing

```bash
# Connect with telnet
telnet localhost 143

# Or with a real IMAP client: use your normal username + password
```

## Future Work

- [ ] Real mailbox SELECT (fetch from Storage)
- [ ] SEARCH → JMAP query translation
- [ ] FETCH → email + attachments in IMAP format
- [ ] Multi-part MIME rendering
- [ ] IMAP IDLE (push-alike)
- [ ] STARTTLS + certificate validation
- [ ] RFC 6858 (UTF8=ACCEPT) for non-ASCII mailbox names
