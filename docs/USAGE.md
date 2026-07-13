# owney Usage Guide

This guide covers operational tasks for server administrators and end-user features. For deployment, see `docs/GETTING-STARTED.md` and `docs/SETUP.md`.

## Contents

- [Admin Operations](#admin-operations)
- [End-User Features](#end-user-features)
- [Chat Mode (Real-Time Email)](#chat-mode-real-time-email)
- [Spam Filtering](#spam-filtering)
- [Monitoring & Troubleshooting](#monitoring--troubleshooting)

---

## Admin Operations

### Account Management

#### Create an Account

```bash
owneyd admin create-account user@example.com
```

Output:
```
Account created: user@example.com
Password: msk_abc123def456ghi789jklmnopqrstu
```

**Save the password securely** — it's used for JMAP/IMAP authentication. Offer to the user or store in a password manager. It's a bearer token (format: `msk_*`), not derivable.

#### List All Accounts

```bash
owneyd admin list-accounts
```

Output:
```
user@example.com (created 2026-07-11)
admin@example.com (created 2026-07-10)
archive@example.com (created 2026-06-15, disabled)
```

#### Reset a Password

Passwords cannot be changed; generate a new account token:

```bash
owneyd admin reset-token user@example.com
```

Outputs new `msk_*` token. The old token continues to work; you must manually revoke it (see below) to force reconnection.

#### Disable an Account (Soft-Delete)

Disables login and mail delivery to that account without deleting data:

```bash
owneyd admin disable-account user@example.com
```

Use case: user left, but you want to archive their mail or restore them later.

- Prevents login via JMAP/IMAP
- Stops accepting mail to that address or its aliases
- Data remains intact in the database

#### Re-Enable a Disabled Account

```bash
owneyd admin enable-account user@example.com
```

Restores login and mail delivery. All mail and aliases persist.

#### Delete an Account (Permanent)

```bash
owneyd admin delete-account user@example.com --confirm
```

**Irreversible.** Removes:
- Account record
- All emails and attachments
- All aliases
- All auth tokens
- All spam training data

Requires `--confirm` flag as a safety check.

---

### Email Aliases

Aliases let users receive mail at multiple addresses while keeping one inbox. Permanent aliases never expire; temporary aliases auto-disable after a set time.

#### Create a Permanent Alias

```bash
owneyd admin create-alias \
  --account user@example.com \
  --alias notifications@example.com \
  --label "automated alerts"
```

- `--account`: the main account that receives mail
- `--alias`: the address to create
- `--label`: optional human-readable note

Mail to `notifications@example.com` arrives in `user@example.com`'s inbox.

#### Create a Temporary Alias

```bash
owneyd admin create-alias \
  --account user@example.com \
  --alias temp2024@example.com \
  --label "e-commerce signup" \
  --expires-in-days 30
```

The alias automatically deactivates after 30 days. The account can't receive mail at that address once expired, but the alias record remains for audit.

#### List Aliases for an Account

```bash
owneyd admin list-aliases user@example.com
```

Output:
```
notifications@example.com (label: automated alerts, created 2026-07-11, active)
temp2024@example.com (label: e-commerce signup, created 2026-07-01, expires 2026-08-01, active)
shopping@example.com (label: purchased 2026-06-01, created 2026-06-01, active)
```

Shows expiration dates and active status.

#### Deactivate an Alias

```bash
owneyd admin deactivate-alias notifications@example.com
```

- Stops accepting mail to that address immediately
- Does not delete the alias record (retained for audit)
- User can re-activate via JMAP API (optional feature, TBD)

---

### Spam Filtering Configuration

#### Check Current Spam Settings

Spam filtering is configured in `mailserver.toml`:

```toml
[spam]
enabled = true
reject_threshold = 0.9      # Reject messages with score >= 0.9
quarantine_threshold = 0.7  # Route to "junk" if score >= 0.7
dnsbl_zones = [
  "zen.spamhaus.org",       # SpamHaus Combined Blocklist
  "bl.spamcop.net"          # SpamCop Blocklist
]
```

#### Enable/Disable Spam Filtering

To disable globally:

```toml
[spam]
enabled = false
```

Restart the daemon:

```bash
sudo systemctl restart owneyd
```

#### Adjust Thresholds

**Reject threshold** (default 0.9): Messages scoring >= 0.9 are rejected with a permanent 550 error. The sender sees the bounce immediately.

**Quarantine threshold** (default 0.7): Messages scoring >= 0.7 (but < 0.9) are routed to the "junk" mailbox instead of "inbox". The user can review and recover.

Recommended tuning:
- **Aggressive** (fewer false positives): reject_threshold = 0.95, quarantine_threshold = 0.8
- **Conservative** (fewer false negatives): reject_threshold = 0.85, quarantine_threshold = 0.6

#### Add a DNSBL Zone

To add another blacklist (e.g., Spamhaus PBL for residential IPs):

```toml
[spam]
dnsbl_zones = [
  "zen.spamhaus.org",
  "bl.spamcop.net",
  "pbl.spamhaus.org"        # Spamhaus Policy Block List
]
```

Restart after editing.

#### Monitor Spam Scores

Current implementation stores spam verdicts in the database. Query recent scores:

```bash
sqlite3 /var/lib/owney/mail.db \
  "SELECT email_id, spam_results FROM emails ORDER BY received_at DESC LIMIT 10"
```

Example output:
```
msg_abc123def456|{"score": 0.82, "matched_rules": ["ALL_CAPS_SUBJECT", "MISSING_MESSAGE_ID"], "dnsbl_hits": [], "bayes_prob": 0.68}
msg_xyz789ijk012|{"score": 0.45, "matched_rules": [], "dnsbl_hits": ["zen.spamhaus.org"], "bayes_prob": null}
```

---

## End-User Features

### Overview

owney exposes mail via multiple protocols:

| Protocol | Use Case | Status |
|----------|----------|--------|
| **JMAP** | Modern API, all features, real-time push | ✅ Recommended |
| **IMAP** | Legacy clients, read-only | ✅ Supported |
| **REST** | Simple HTTP API | ✅ Partial |
| **MCP** | Claude AI assistant integration | ✅ Supported |

### Connecting to JMAP

#### Get the JMAP Endpoint

```
https://mail.example.com/.well-known/jmap
```

#### Credentials

- **Username**: email address (e.g., `user@example.com`)
- **Password**: the `msk_*` bearer token from account creation

#### Recommended JMAP Clients

- **Glow** (web): https://glow.fm — full-featured web client, real-time sync
- **Mimestream** (iOS): modern native app
- **Thunderbird** (desktop): with JMAP add-on

#### JMAP Capabilities

owney supports RFC 8620/8621:

- `Email/get`, `Email/set`, `Email/query` — full mail access
- `Mailbox/get`, `Mailbox/set` — folder management
- `Thread/get` — conversation threading
- `EmailSubmission/set` — composing and sending
- `changes` — efficient sync (modseq discipline)
- `push` — WebSocket real-time notifications (RFC 8887)
- `Identity/get` — send-as addresses and aliases

### Connecting to IMAP

#### IMAP Details

- **Host**: `mail.example.com`
- **Port**: `993` (TLS required)
- **Username**: email address
- **Password**: `msk_*` bearer token

#### Limitations

IMAP is **read-only**:
- ✅ Download mail
- ✅ Mark read/unread, flag, label
- ❌ Compose/send (use JMAP or Webmail)
- ❌ Create folders (use JMAP)

This is intentional: all write operations flow through JMAP for audit trail. See `docs/PLAN.md` § Audit Trail.

### Using Aliases in JMAP

When you have aliases, JMAP `Identity/get` returns them:

```json
{
  "identities": {
    "user@example.com": {
      "name": "Your Name",
      "email": "user@example.com"
    },
    "notifications@example.com": {
      "name": "Your Name",
      "email": "notifications@example.com"
    },
    "temp2024@example.com": {
      "name": "Your Name",
      "email": "temp2024@example.com"
    }
  }
}
```

When composing, choose `from:` via the identity email. Mail clients typically offer a dropdown.

### Sending Email

#### Via JMAP

Use `EmailSubmission/set` with the desired `Identity` email:

```json
{
  "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
  "methodCalls": [
    ["EmailSubmission/set", {
      "create": {
        "send1": {
          "identityId": "notifications@example.com",
          "email": {
            "to": [{"email": "recipient@example.com"}],
            "subject": "Alert",
            "bodyStructure": {"type": "text/plain", "partId": "body"}
          },
          "emailIds": ["draft_id"]
        }
      }
    }, "0"]
  ]
}
```

#### SPF/DKIM/DMARC

owney automatically signs outbound mail with DKIM. Receiving servers verify your domain:

- **DKIM**: signed by owney (public key in `_domainkey._report.example.com`)
- **SPF**: configured during setup (TXT record `v=spf1 ip4:<your-ip> ~all`)
- **DMARC**: configured during setup (TXT record `v=DMARC1; p=quarantine; ...`)

Ensure these DNS records are in place before sending volume. Verify with:

```bash
dig TXT _domainkey._report.example.com +short
dig TXT example.com +short
dig TXT _dmarc.example.com +short
```

### OpenPGP / Encryption

#### Receiving Encrypted Mail

If a sender has published a PGP key (via WKD or Autocrypt header), owney automatically decrypts mail encrypted to you.

The JMAP `Email/get` includes `pgpStatus`:

```json
{
  "email": {
    "id": "msg_123",
    "pgpStatus": {
      "encrypted": true,
      "signed": true,
      "signerEmail": "sender@example.com",
      "verifiedSignature": true
    }
  }
}
```

#### Sending Encrypted Mail

When composing a reply to an encrypted message, clients (Glow, Mimestream) offer an "encrypt" toggle. owney looks up the recipient's WKD key and encrypts opportunistically.

#### Key Publication

Your public key is published via WKD at:

```
https://mail.example.com/.well-known/openpgpkey/example.com/user
```

Senders can import it automatically; most modern mail clients (Thunderbird, Apple Mail with plugin) support this.

### Screener (AI Screening)

#### How It Works

When mail arrives, the Screener analyzes it (using Claude, run locally on your server) and marks it with metadata:

- ✅ **Pass**: legitimate mail, inbox
- ⚠️ **Review**: potential spam, Screener mailbox (separate from Junk)
- ❌ **Fail**: spam, rejected at SMTP

#### Accessing Screener Results

In JMAP, check the `screening` field in `Email/get`:

```json
{
  "email": {
    "id": "msg_456",
    "screening": {
      "verdict": "review",
      "reason": "Unknown sender with suspicious link",
      "confidence": 0.87
    }
  }
}
```

#### Disabling Screener

The Screener is optional and fail-open (if Claude is unavailable, mail still arrives).

To disable globally, edit `mailserver.toml`:

```toml
[ai]
enabled = false
```

---

## Chat Mode (Real-Time Email)

Chat mode delivers emails in real-time like instant messaging, rather than queuing them. Messages are still stored as full RFC 5322 emails for audit trail, but delivery is prioritized and notifications are immediate.

### Sending Chat-Mode Emails

When composing via JMAP, set the `chatMode` flag:

```json
{
  "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
  "methodCalls": [
    ["Email/set", {
      "create": {
        "draft1": {
          "mailboxIds": {"drafts-mailbox-id": true},
          "chatMode": true,
          "subject": "Quick question",
          "to": [{"email": "alice@example.com"}],
          "bodyStructure": {"type": "text/plain", "partId": "body"},
          "bodyValues": {"body": {"value": "Can you review the doc?"}}
        }
      }
    }, "0"],
    ["EmailSubmission/set", {
      "create": {
        "submit1": {
          "emailId": "#draft1",
          "chatMode": true
        }
      }
    }, "1"]
  ]
}
```

Receiving clients get WebSocket push notifications immediately instead of checking inbox every 30 seconds.

### Recipient Preferences

Users can configure how they want to receive emails from specific contacts:

```json
{
  "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
  "methodCalls": [
    ["ChatPreference/set", {
      "create": {
        "bob": {
          "contactEmail": "bob@example.com",
          "preference": "auto_chat"
        },
        "spam": {
          "contactEmail": "notifications@spam.bot",
          "preference": "never_chat"
        }
      }
    }, "0"]
  ]
}
```

**Preference values**:
- `"auto_chat"`: Always treat mail from this sender as chat (immediate delivery), even if sender doesn't request it
- `"never_chat"`: Never treat mail from this sender as chat, even if sender requests it
- `"respect_sender"`: Default; sender's chatMode flag determines delivery (false if not set)

### Checking Email Chat Status

In `Email/get`, the `chatMode` field shows whether an email was sent with chat intent:

```json
{
  "email": {
    "id": "msg_123",
    "chatMode": true,
    "subject": "Quick question"
  }
}
```

### Chat Mode Delivery

**For local recipients** (same server): delivered immediately via WebSocket.
**For remote recipients** (different mail server): sent with expedited retry backoff (30s → 2m → 10m → 1h, max 8h).

---

## Spam Filtering

### How It Works

Three layers:

1. **DNSBL** (DNS Blacklist): check sender IP against public blocklists (SpamHaus, SpamCop)
2. **Heuristic Rules**: detect missing headers, ALL-CAPS subjects, suspicious attachments
3. **Naive Bayes**: per-account machine learning trained on user's past spam/ham decisions

All three scores are combined (0.0–1.0 scale).

### Spam Scores and Routing

| Score | Action | Visibility |
|-------|--------|------------|
| < 0.7 | Deliver to Inbox | Normal |
| 0.7–0.89 | Deliver to Junk | User can review, recover |
| ≥ 0.9 | Reject (550 error) | Sender sees permanent bounce |

### Training the Classifier (Future)

To improve Bayes accuracy, move misclassified mail:

- **False positive** (spam classified as ham): Move to Junk → triggers training update
- **False negative** (ham classified as spam): Move to Inbox → triggers training update

**Note**: Training is not yet integrated. For now, move mail manually; scoring is advisory.

### DNSBL Hits

If a sender's IP is on a public blacklist, you see `dnsbl_hits` in the spam verdict:

```json
{
  "dnsbl_hits": ["zen.spamhaus.org"]
}
```

This contributes ~0.3 to the score. If you trust the sender despite the listing, ask them to contact the blacklist provider.

---

## Monitoring & Troubleshooting

### Health Check

```bash
owneyd doctor
```

Checks:
- ✅ Database integrity
- ✅ TLS certificate expiration
- ✅ DNS records (MX, SPF, DMARC, DKIM)
- ✅ Disk space
- ✅ Queue depth and stuck messages

Run daily during the first week; weekly after that.

### View Logs

```bash
# Real-time (follow mode)
sudo journalctl -u owneyd -f

# Last 100 lines
sudo journalctl -u owneyd -n 100

# Since last boot
sudo journalctl -u owneyd -b
```

**Key log markers**:
- `message delivered`: inbound SMTP success
- `dkim: signed`: outbound signing
- `spam_score`: spam verdict applied
- `ERROR`: failures (DNS, auth, DB, etc.)

### Monitor Resource Usage

```bash
# Process stats
top -p $(pgrep owneyd)

# Disk usage
du -sh /var/lib/owney/

# Database size
ls -lh /var/lib/owney/mail.db
```

Expected on a small instance:
- **Memory**: 100–200 MB at rest, 200–400 MB under load
- **Disk**: 50–100 MB per month of mail (depends on attachment size)

### Check Queue Depth

```bash
sqlite3 /var/lib/owney/mail.db \
  "SELECT COUNT(*) as pending FROM queue WHERE status = 'queued'"
```

If growing: check `doctor` for DNS issues or peer rejections.

### Check Connection Count

```bash
ss -tnp | grep owneyd | wc -l
```

Expect 1–10 connections at idle, 50–200 during active sync.

### Test Mail Delivery

Send a test mail from an external provider (Gmail, Proton, etc.) to your account:

```bash
# Watch logs in real-time
sudo journalctl -u owneyd -f

# Send from Gmail to user@example.com
# Watch for "message delivered" log line
```

### Diagnose Common Issues

#### "Mail not arriving"

1. Check MX record:
   ```bash
   dig MX example.com +short  # should show mail.example.com
   ```

2. Port 25 open?
   ```bash
   curl -v smtp://mail.example.com:25  # should connect
   ```

3. Check logs for errors:
   ```bash
   sudo journalctl -u owneyd -n 50 | grep -i error
   ```

4. Run doctor:
   ```bash
   owneyd doctor
   ```

#### "Client can't connect (JMAP/IMAP)"

1. TLS certificate valid?
   ```bash
   openssl s_client -connect mail.example.com:993 -showcerts
   ```

2. Firewall allows 443/993?
   ```bash
   sudo ss -tlnp | grep owneyd
   ```

3. Check auth error in logs:
   ```bash
   sudo journalctl -u owneyd -f  # watch for "auth failed"
   ```

4. Verify password (bearer token):
   ```bash
   owneyd admin list-accounts  # check account exists
   owneyd admin reset-token user@example.com  # get new token
   ```

#### "High CPU or Memory"

1. Check for stuck queries:
   ```bash
   sudo journalctl -u owneyd | grep -i "timeout\|deadlock"
   ```

2. Check active connections:
   ```bash
   ss -tnp | grep owneyd
   ```

3. Restart if needed:
   ```bash
   sudo systemctl restart owneyd
   ```

#### "Spam filtering too aggressive/lenient"

Adjust thresholds in `mailserver.toml` and restart:

```toml
[spam]
reject_threshold = 0.88      # Lower = more strict
quarantine_threshold = 0.65  # Lower = quarantine more
```

Then restart:

```bash
sudo systemctl restart owneyd
```

---

## Advanced Topics

### Backup & Restore

#### Create a Backup

```bash
owneyd backup create --output /var/backups/owney/$(date +%Y%m%d-%H%M%S).tar
```

This archives the database and blob store. Store offsite.

#### Restore from Backup

```bash
# Stop the server
sudo systemctl stop owneyd

# Restore
owneyd backup restore --input /var/backups/owney/20260711-143022.tar

# Restart
sudo systemctl start owneyd
```

See `docs/SETUP.md` § Disaster Recovery for details.

### Database Queries

Direct SQLite access (when the server is stopped):

```bash
# Account list
sqlite3 /var/lib/owney/mail.db "SELECT id, email, created_at, disabled_at FROM accounts"

# Email count per account
sqlite3 /var/lib/owney/mail.db \
  "SELECT a.email, COUNT(e.id) FROM accounts a LEFT JOIN emails e ON a.id = e.account_id GROUP BY a.id"

# Outbound queue status
sqlite3 /var/lib/owney/mail.db \
  "SELECT recipient, error, retry_count FROM queue WHERE status = 'queued' LIMIT 10"
```

### Performance Tuning

If the database grows large (100k+ emails):

1. **Enable WAL mode** (already default, but verify):
   ```bash
   sqlite3 /var/lib/owney/mail.db "PRAGMA journal_mode = WAL"
   ```

2. **Vacuum** (stop server first):
   ```bash
   sqlite3 /var/lib/owney/mail.db "VACUUM"
   ```

3. **Index new queries** (contact support or file an issue if slow).

---

## Getting Help

- **Logs**: `sudo journalctl -u owneyd -f`
- **Health check**: `owneyd doctor`
- **Issue tracker**: https://github.com/anthropics/owney/issues
- **Community**: #owney on Matrix
- **Documentation**: https://github.com/anthropics/owney/tree/main/docs

---

**Last updated**: 2026-07-12
