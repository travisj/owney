# Getting Started with owney

**TL;DR**: Deploy a full mailserver in 5 minutes. See `docs/SETUP.md` for production details and troubleshooting.

## Prerequisites

- A domain you control (with DNS access)
- A fresh VPS or bare metal server (2+ cores, 4GB RAM, 20GB disk)
  - Recommended: DigitalOcean, Linode, or AWS EC2
- SSH access to the server
- Port 25 (SMTP inbound) must be open

## 1. Get the Binary (2 min)

```bash
# On your server:
curl -fsSL https://releases.github.com/owney/latest/owneyd-$(uname -s)-$(uname -m) \
  -o /usr/local/bin/owneyd && chmod +x /usr/local/bin/owneyd

# Verify:
owneyd --version
```

(Or build from source: `git clone ... && cargo build --release`.)

## 2. Run Setup Wizard (2 min)

The wizard generates DNS records, configures TLS via ACME, and creates your config file.

```bash
sudo owneyd setup --domain example.com
```

Follow prompts:
1. **Email address**: admin@example.com
2. **TLS provider**: Let's Encrypt (ACME) — wizard will provision a cert
3. **DNS hosting**: manual entry, Route53, Cloudflare, or BIND (wizard guides you)

## 3. Verify DNS (30 sec)

The wizard generates these records. Add them to your domain's DNS:

```
# MX record (priority 10)
mail.example.com  A  <your-server-ip>
example.com       MX 10 mail.example.com

# SPF (tighten existing SPF or create new)
example.com       TXT "v=spf1 ip4:<your-server-ip> ~all"

# DMARC policy
_dmarc.example.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

# DKIM (owney generates this after first run; add it after step 5)
_domainkey._report.example.com TXT "v=DKIM1; k=rsa; p=..."
```

Wait 5–15 minutes for propagation:

```bash
dig MX example.com +short  # should show your server
dig TXT example.com +short # should show SPF record
```

## 4. Start the Server (30 sec)

```bash
# Via systemd (recommended):
sudo systemctl enable owneyd
sudo systemctl start owneyd
sudo systemctl status owneyd

# Or in the foreground (for debugging):
owneyd serve --config /etc/owney.toml
```

## 5. Create Your Account (30 sec)

```bash
owneyd admin create-account you@example.com
# → saves password to stdout; copy it securely
```

## 6. Connect a Mail Client (1 min)

### JMAP (Recommended)
- Host: `mail.example.com`
- Port: `993` (TLS) or `80` (plain)
- Auth: `you@example.com` + password from step 5
- Endpoint: `https://mail.example.com/.well-known/jmap`

**Supported clients**: Glow (web), Mimestream (iOS), Thunderbird (w/ CardDAV plugin)

### IMAP (Read-Only)
- Host: `mail.example.com`
- Port: `993` (TLS)
- Username: `you@example.com`
- Password: from step 5

**Supported clients**: Apple Mail, Thunderbird, Outlook, K-9 Mail, etc.

**Note**: IMAP is read-only; compose/send routes through JMAP or REST API for audit trail.

## 7. Test It (1 min)

Send yourself a test email from Gmail or another email provider:

```bash
# Send to: you@example.com
# Check owney logs: sudo journalctl -u owneyd -f
```

Watch logs for:
- `inbound: message received` (mail arrived)
- `dkim: signed` (outbound working)
- `thread: linked to thread` (conversation threading)

If nothing arrives, see **Troubleshooting** below.

## 8. Set Up Backups (Optional, 1 min)

Backups are critical for self-hosted mail. Configure one:

### Local Backups
```bash
mkdir -p /var/backups/owney
echo "0 2 * * * owneyd --config /etc/owney.toml backup create --output /var/backups/owney" | crontab -
```

### S3 Backups (AWS)
```bash
owneyd setup-backup --type s3 --bucket owney-backup-example-com
```

Test restore in `docs/SETUP.md` § Step 8.

## 9. Enable Monitoring (Optional, 2 min)

```bash
# Health check
owneyd doctor

# Watch logs in real-time
journalctl -u owneyd -f

# Check queue depth
sqlite3 /var/lib/owney/mail.db "SELECT COUNT(*) FROM queue WHERE status = 'queued'"
```

## Troubleshooting

### "No mail arriving"
```bash
# 1. Check MX record points to your server
dig MX example.com +short

# 2. Port 25 open?
telnet mail.example.com 25  # should connect

# 3. Check logs
journalctl -u owneyd -n 100

# 4. Run doctor
owneyd doctor
```

### "Sent mail stuck in queue"
```bash
# Check queue depth
sqlite3 /var/lib/owney/mail.db "SELECT recipient, error FROM queue LIMIT 5"

# Common issues: DNS resolution, MTA-STS policy, peer rejection
# Run doctor to diagnose
owneyd doctor
```

### "Client can't connect"
```bash
# Verify TLS cert is valid
openssl s_client -connect mail.example.com:993 -showcerts

# Check firewall allows port 993 (IMAP) / 443 (JMAP API)
ss -tlnp | grep owneyd

# Review logs for auth errors
journalctl -u owneyd -f
```

### "CPU/Memory high"
```bash
# Monitor system resources
top -p $(pgrep owneyd)

# Check active connections
sqlite3 /var/lib/owney/mail.db "SELECT COUNT(*) FROM smtp_sessions"

# Review doctor output for stuck processes
owneyd doctor
```

## Next Steps

- **Full setup guide**: `docs/SETUP.md` (production config, disaster recovery, monitoring)
- **Roadmap**: `docs/PLAN.md` (what's coming)
- **API docs**: Run `cargo doc --open` or visit https://docs.rs/owney
- **Chat**: Join us on Matrix: `#owney:matrix.org`
- **Issues**: Report bugs or request features on GitHub

## Tips for First Week

1. **Monitor closely**: watch logs, check `doctor` daily, test backup/restore
2. **Communicate**: tell friends your server is live; inbound mail = proof it works
3. **Document setup**: save DNS records, TLS cert paths, backup S3 location
4. **Subscribe to updates**: watch GitHub releases for patches
5. **Join community**: Matrix room for questions and troubleshooting

---

**Deployed owney? Let us know on GitHub or Matrix!**
