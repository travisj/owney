# Public Beta Launch Checklist

Internal launch-day document for owney public beta (July 2026). This checklist ensures all monitoring, communication, and support infrastructure is in place before announcing to the public.

## Pre-Announcement Checks (48 hours before)

### Code & Releases
- [ ] **Tag stable release**: `git tag -s v0.7.0 -m "Public beta launch"`
- [ ] **Verify binary checksums**: SHA256 hashes match on Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64
- [ ] **Test docker build**: `docker build -t owney:v0.7.0 .` succeeds and runs; image < 150MB
- [ ] **Verify release notes**: GitHub Release page includes:
  - What's shipped (M0–M7 summary)
  - Known limitations (no web client, no Calendar v1, IMAP read-only)
  - Security contact (`security@owney.dev`)
  - Links to docs (GETTING-STARTED.md, SETUP.md)
- [ ] **Backup last prod config**: snapshot `main` commit, tag, release.

### Infrastructure
- [ ] **Demo server ready**: owney instance running at `beta.owney.dev` with 2+ test accounts
- [ ] **Monitoring active**:
  - [ ] Prometheus scraping metrics from demo server (uptime, queue depth, SMTP connections)
  - [ ] Grafana dashboard: "owney beta" with CPU/Memory/Disk, SMTP delivery rate, JMAP API latency
  - [ ] Alerting enabled: page on crash (exit code), queue > 10k, API latency > 1s
- [ ] **Logging centralized**: demo server logs stream to Loki or CloudWatch
- [ ] **S3 backups**: demo server backups upload to `s3://owney-beta-backups/` hourly
- [ ] **DNS healthy**: `dig MX beta.owney.dev`, `dig TXT beta.owney.dev` (SPF/DMARC in place)
- [ ] **TLS cert valid**: `openssl s_client -connect beta.owney.dev:993` shows valid cert, > 7 days until expiry

### Documentation
- [ ] **Getting started**: `docs/GETTING-STARTED.md` reviewed; all links work
- [ ] **Setup guide**: `docs/SETUP.md` tested on fresh $5 VPS (DigitalOcean/Linode)
- [ ] **Troubleshooting**: common errors (DNS not propagating, port 25 blocked, cert expiry) documented
- [ ] **FAQ**: link to Discourse/GitHub Discussions ready
- [ ] **API docs**: JMAP/REST/MCP surface documented; `cargo doc --open` renders cleanly

### Support Infrastructure
- [ ] **GitHub Issues enabled**: template for bug reports includes:
  ```markdown
  ## Checklist
  - [ ] Ran `owneyd doctor` and included output
  - [ ] Checked logs: `journalctl -u owneyd -n 100`
  - [ ] Reproduced on clean setup (not config-specific)
  
  ## Description
  ...
  
  ## Logs & Diagnostics
  ...
  ```
- [ ] **GitHub Discussions enabled**: category "Announcements" (readonly), "Getting Started", "Troubleshooting", "Showcase"
- [ ] **Matrix room created**: `#owney:matrix.org` with welcome message + channel rules
- [ ] **Email alias ready**: `support@owney.dev` → Travis (triage every 24h initially)
- [ ] **Security contact**: `security@owney.dev` published; GPG key (if any) linked in SECURITY.md

### Legal & Privacy
- [ ] **SECURITY.md**: vulnerability disclosure policy in place, response SLA (48h for public beta)
- [ ] **PRIVACY.md**: document what server collects (auth logs, AI audit trail), data retention policy
- [ ] **Terms**: if running demo server, TOS posted or linked
- [ ] **License audit**: AGPL-3.0 compliance (no GPL-only deps snuck in), dual-license path (if any) documented

## Announcement Channels (Launch Day)

### Tier 1: Core Communities (8 AM UTC)
- [ ] **Hacker News**: submitted by 8 AM UTC, title framing: "owney — a self-hosted JMAP mailserver with AI screening (open beta)" or "Show HN: owney — single-binary mailserver, JMAP native"
- [ ] **Rust Reddit** (`r/rust`): cross-post with link to HN + GitHub
- [ ] **Lobsters** (if eligible): Lobsters.to submission
- [ ] **GitHub Trending**: verify repo shows on https://github.com/trending/rust (automatic if stars/forks spike)

### Tier 2: Topical Communities (8:30 AM UTC)
- [ ] **Email/Protocol Forums**: mail-core listserv, JMAP Working Group, Postfix mailing list
- [ ] **Self-hosted Forums**: r/selfhosted, r/privacy, Discourse.selfhosted.forum
- [ ] **AI/ML Communities**: r/OpenAI (if Claude integration is headline), prompt-engineering communities
- [ ] **Rust Security**: r/RustSecurity announcement thread

### Tier 3: Direct Outreach (9 AM UTC+)
- [ ] **Email**: reach out to:
  - [ ] Mimestream, Glow maintainers (JMAP client authors)
  - [ ] Fastmail, ProtonMail (check if they engage with JMAP ecosystem)
  - [ ] JMAP Working Group members
- [ ] **Mastodon/Twitter**: thread covering features, link to GitHub, demo video (if available)
- [ ] **Dev.to**: cross-post article or announcement

### Tier 4: Press (next week, if coverage emerges)
- [ ] Email templates drafted for journalist outreach
- [ ] Demo video recorded (2–3 min: "Send email → AI categories it → JMAP client shows in real-time")

## Monitoring & Metrics (Launch Week)

### Real-time Dashboard (live during announcement)

Track these metrics for the first 48 hours:

**User Acquisition**
- GitHub stars/forks velocity (target: 100+ stars/day for successful HN launch)
- Repo clone rate (GitHub API: `git clone` counts)
- Demo server login attempts (failed/successful auth counts)

**System Health**
- SMTP inbound volume to demo server (messages/hour)
- JMAP API request rate (requests/sec, by endpoint)
- API latency p95 (target: < 500ms)
- Queue depth (target: < 100 queued at any time)
- Crash rate (target: 0; page ops on exit code != 0)
- Disk usage (target: < 80% until we hit 10k emails)

**Infrastructure**
- Deployment/release rollback events (track if needed)
- Backup success rate (target: 100%)
- TLS cert validity (alert if < 7 days)

**Support Load**
- Issues filed (GitHub)
- Messages in Matrix room
- Support email response time (target: < 24h first response)

### Alert Thresholds

Page ops if any of:
- **Crash**: owneyd exits with code != 0 on demo server
- **API Error Rate**: > 5% 5xx in 5 min window
- **Queue**: > 5k queued messages
- **Latency**: p95 > 2s for 5 min
- **Disk**: > 85% full
- **TLS Cert**: < 7 days until expiry
- **Security**: any vulnerability reports received

Slack notif (no page) if:
- GitHub star count > 500 (track milestone)
- HN rank > 10
- Support queue > 10 open issues

## What We'll Monitor

### Crash Rates & Stability
- owneyd panic count (via logs, alert on any panics)
- Backup restore test success rate (run daily)
- Database integrity checks (`PRAGMA integrity_check` monthly)

### Delivery Issues
- Inbound bounce rate (emails we reject due to domain policy)
- Outbound delivery rate (% of messages leaving queue, target: > 99%)
- Peer rejection rate (by domain; identify blocklisting issues)
- Queue age (oldest queued message, alert if > 1h)

### Security Events
- Failed auth attempts (track per-IP, alert if > 10/min from single IP)
- SPAM screener FP rate (users who unscreen legit mail from Screener; target: < 1%)
- DKIM/SPF/DMARC fail rate (inbound, target: < 5% legitimate mail)
- Suspicious query patterns (e.g., Email/get with 1000000 items; alert on malformed JMAP)

### User Experience
- IMAP vs JMAP client adoption (track by User-Agent header)
- Most common errors in logs (weekly summary)
- Average API response time by endpoint (identify slow paths)
- Backup/restore time (track for users planning self-host)

### Support Indicators
- Most-filed issues (group similar tickets; may indicate doc gap)
- Most-asked questions in Matrix (surface as FAQ)
- Setup failure rate (estimate from "not receiving mail" threads)

## Escalation & Decision Tree

### If HN Front-Page Hits
- [ ] Scale demo server (add CPU/RAM or rate-limit new signups)
- [ ] Pin post in Matrix with link to setup docs
- [ ] Monitor support queue; may need async response template

### If Critical Bug Found
- [ ] **Code**: patch `main`, tag point release (e.g., v0.7.1)
- [ ] **Announce**: GitHub release notes + Matrix pinned message
- [ ] **Demo server**: deploy patch within 2 hours
- [ ] **Notify users**: if security-impacting, email `security@owney.dev` subscribers

### If Deliverability Degrades
- [ ] Check queue; if > 5k, investigate MX routing or peer rejections
- [ ] Run `owneyd doctor` output; check DNS/TLS/blocklists
- [ ] Contact top rejecting peers (e.g., "blocked by Gmail antispam")
- [ ] Consider smarthost relay mode for demos

### If Major Security Issue Discovered
- [ ] Do not announce until patch ready
- [ ] Prepare CVE with CISA
- [ ] Notify security@owney.dev subscribers 1 hour before public disclosure
- [ ] Emergency release + tagged commit

## Post-Launch (Week 2+)

- [ ] **Retrospective**: what worked, what surprised us, user feedback trends
- [ ] **Roadmap adjustment**: M8 priorities based on feedback (e.g., "everyone wants web client")
- [ ] **Sustainability**: plan for ongoing support (can we sustain Matrix + GitHub issues volume?)
- [ ] **Contributor onboarding**: if contributors show up, have CONTRIBUTING.md ready

## Rollback Plan

If launch is severely broken:

1. **Demo server**: `git checkout v0.6.x && systemctl restart owneyd` (preserve data via backups)
2. **Announcement**: Pin message in Matrix: "We found an issue with v0.7.0; reverting to v0.6.x for 24h while we fix it"
3. **Communication**: update GitHub issue, close HN thread if possible, email early users
4. **Fix**: branch from `main`, ship v0.7.1 within 24h
5. **Re-announcement**: "v0.7.1 ready, issue was [explanation], relaunching" on Hacker News with new link (if possible) or Matrix + GitHub

---

**Owner**: Travis Johnson
**Last Updated**: July 11, 2026
**Next Review**: Post-launch (July 15, 2026)
