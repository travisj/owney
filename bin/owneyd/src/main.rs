//! The single deployable binary.

mod handler;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use owney_core::Config;
use owney_events::EventBus;
use owney_storage::Storage;

use crate::handler::ServerCore;
use std::future::Future;

#[derive(Debug, Parser)]
#[command(
    name = "owneyd",
    version,
    about = "A mailserver for today",
    max_term_width = 100
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(long, short, global = true, default_value = "mailserver.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server.
    Serve,
    /// First-run wizard: create config, generate keys, print your DNS
    /// records, and optionally wait until they verify.
    Setup {
        /// Poll DNS until every required record verifies (or timeout).
        #[arg(long)]
        verify: bool,
        /// Verification timeout in seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Create or restore backups. (M6)
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Administer a running installation.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Diagnose DNS, reverse DNS, TLS, and outbound connectivity.
    Doctor,
    /// Safe self-update: verify binary, test migrations, atomic swap.
    Update {
        /// Path to new binary.
        binary: std::path::PathBuf,
        /// Expected BLAKE3 hash of binary.
        #[arg(long)]
        hash: String,
        /// Dry-run: test migrations without swapping binary.
        #[arg(long)]
        dry_run: bool,
    },
    /// Configuration helpers.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Create a backup snapshot.
    Create {
        /// Output directory for backup archive (default: data_dir/backups).
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Restore a backup snapshot.
    Restore {
        /// Path to backup archive (tar.zst file).
        archive: std::path::PathBuf,
        /// Target data directory to restore into (default: config's data_dir).
        #[arg(long)]
        target: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Create a user account.
    CreateAccount {
        /// Primary address, e.g. alice@example.com
        email: String,
        /// Display name for outgoing mail.
        #[arg(long)]
        name: Option<String>,
    },
    /// List accounts.
    Accounts,
    /// List an account's inbox, newest first.
    Inbox {
        /// The account's address.
        email: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show a role mailbox other than the inbox (e.g. sent, screener).
        #[arg(long, default_value = "inbox")]
        mailbox: String,
    },
    /// Print a stored message (raw RFC 5322).
    Show {
        /// The email id (from `admin inbox`).
        email_id: String,
    },
    /// Send a message from a local account.
    Send {
        /// Sending account address (must exist locally).
        from: String,
        /// Recipient address(es).
        to: Vec<String>,
        #[arg(long)]
        subject: String,
        /// Body text; reads stdin when omitted.
        #[arg(long)]
        body: Option<String>,
        /// Run a delivery worker until this message reaches a terminal state
        /// (use when `serve` is not running).
        #[arg(long)]
        wait: bool,
    },
    /// Show pending outbound deliveries.
    Queue,
    /// Create an API bearer token for an account (shown once).
    Token {
        /// The account's address.
        email: String,
        /// A label for this token (which device/app uses it).
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Disable an account (blocks login and inbound mail, reversible).
    DisableAccount {
        /// The account's address.
        email: String,
    },
    /// Re-enable a disabled account.
    EnableAccount {
        /// The account's address.
        email: String,
    },
    /// Permanently delete an account and all its data (irreversible).
    DeleteAccount {
        /// The account's address.
        email: String,
        /// Confirm deletion (required safety flag).
        #[arg(long)]
        confirm: bool,
    },
    /// Create an email alias for an account.
    CreateAlias {
        /// The account email.
        account: String,
        /// The alias email address (e.g., alice+shopping@example.com).
        alias: String,
        /// Optional label for the alias (e.g., "shopping").
        #[arg(long)]
        label: Option<String>,
        /// Expiration in days (None = permanent).
        #[arg(long)]
        expires_in_days: Option<u32>,
    },
    /// List aliases for an account.
    ListAliases {
        /// The account email.
        email: String,
    },
    /// Deactivate an alias.
    DeactivateAlias {
        /// The alias email to deactivate.
        alias: String,
    },
    /// Print the DKIM DNS record to publish for this domain.
    DkimRecord,
    /// Show the AI activity feed for an account.
    AiActivity {
        email: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Undo an AI action (see `admin ai-activity`).
    Undo { email: String, action_id: String },
    /// Create a calendar for an account.
    CreateCalendar {
        /// The account's address.
        email: String,
        /// Calendar display name.
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    /// Create a public "schedule a meeting" page (prints its URL).
    CreateSchedulingPage {
        /// The account's address.
        email: String,
        /// The calendar bookings land on (see `admin create-calendar`).
        calendar_id: String,
        /// Public URL path segment; defaults to the address's localpart.
        #[arg(long)]
        slug: Option<String>,
        #[arg(long)]
        title: Option<String>,
        /// IANA timezone the availability windows are expressed in.
        #[arg(long, default_value = "UTC")]
        timezone: String,
        /// Meeting length in minutes.
        #[arg(long, default_value_t = 30)]
        duration: u32,
    },
    /// List an account's scheduling pages with their public URLs.
    SchedulingPages {
        /// The account's address.
        email: String,
    },
    /// List bookings made through an account's scheduling pages.
    Bookings {
        /// The account's address.
        email: String,
    },
    /// Create an event on a calendar (see `admin create-calendar`).
    CreateEvent {
        /// The account's address (must own the calendar).
        email: String,
        /// The calendar id.
        calendar_id: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        description: Option<String>,
        /// Start as a unix timestamp; defaults to one hour from now.
        #[arg(long)]
        start: Option<i64>,
        /// End as a unix timestamp; defaults to start + 1 hour.
        #[arg(long)]
        end: Option<i64>,
    },
    /// Register an OIDC/OAuth client application. Prints the client id and (for
    /// confidential clients) the secret exactly once.
    CreateOauthClient {
        /// Human-readable application name (shown on the consent screen).
        name: String,
        /// Allowed redirect URI. Repeat for several; each must be absolute
        /// http(s) with no fragment.
        #[arg(long = "redirect-uri", required = true)]
        redirect_uri: Vec<String>,
        /// Register as a public client (no secret; PKCE only). Native/SPA apps.
        #[arg(long)]
        public: bool,
    },
    /// List registered OAuth clients.
    OauthClients,
    /// Disable an OAuth client and revoke every token it issued (irreversible).
    RevokeOauthClient {
        /// The client id (from `admin oauth-clients`).
        client_id: String,
    },
    /// List the OAuth clients an account has consented to, and their scopes.
    OauthGrants {
        /// The account's address.
        email: String,
    },
    /// Revoke an account's consent for a client and kill its live tokens.
    RevokeOauthGrant {
        /// The account's address.
        email: String,
        /// The client id (from `admin oauth-grants`).
        client_id: String,
    },
    /// Mint a short-lived token and print the URL for enrolling a login passkey.
    EnrollPasskey {
        /// The account's address.
        email: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print a commented example config file.
    Example,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Config {
            command: ConfigCommand::Example,
        } => {
            print!("{}", Config::example());
            Ok(())
        }
        Command::Setup { verify, timeout } => setup(cli.config, verify, timeout),
        Command::Backup { command } => run(cli.config, move |config| backup(config, command)),
        Command::Doctor => run(cli.config, doctor),
        Command::Update {
            binary,
            hash,
            dry_run,
        } => run(cli.config, move |config| {
            update(config, binary, hash, dry_run)
        }),
        Command::Serve => run(cli.config, serve),
        Command::Admin { command } => run(cli.config, move |config| admin(config, command)),
    }
}

fn prompt_yes_no(question: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    loop {
        print!("{question} [y/n]: ");
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("reading input")?;
        match answer.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {}
        }
    }
}

async fn setup_acme(config: &Config) -> anyhow::Result<()> {
    use owney_acme::{AcmeClient, AcmeConfig, CertPaths, CloudflareProvider, Route53Provider};

    println!("\nLet's Encrypt HTTPS Setup");
    println!("=========================\n");

    let email = prompt("Let's Encrypt admin email")?;
    let provider_choice = prompt_default("DNS provider (cloudflare/route53)", "cloudflare")?;

    let dns_provider: Box<dyn owney_acme::DnsProvider> = if provider_choice == "cloudflare" {
        let api_token = prompt("Cloudflare API Token (from Profile → API Tokens)")?;
        let zone_id = prompt("Cloudflare Zone ID (from domain overview page)")?;
        Box::new(CloudflareProvider::new(api_token, zone_id))
    } else if provider_choice == "route53" {
        let zone_id = prompt("AWS Route53 Zone ID (from Route53 console)")?;
        println!(
            "Make sure AWS credentials are set in environment: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
        );
        Box::new(
            Route53Provider::new(zone_id)
                .await
                .context("creating Route53 provider")?,
        )
    } else {
        anyhow::bail!("unsupported DNS provider: {provider_choice}");
    };

    let use_staging =
        prompt_yes_no("Use Let's Encrypt staging (for testing, unlimited rate limits)?")?;

    let cert_paths = CertPaths::in_dir(&config.storage.data_dir);

    println!("\nRequesting certificate for {}...", config.server.hostname);
    println!("This may take 30-60 seconds as we wait for DNS propagation.\n");

    let acme_config = if use_staging {
        AcmeConfig::staging_new(vec![config.server.hostname.clone()], email, provider_choice)
    } else {
        AcmeConfig::new(vec![config.server.hostname.clone()], email, provider_choice)
    };

    let client = AcmeClient::new(acme_config, dns_provider);
    client
        .request_certificate(&cert_paths)
        .await
        .context("requesting certificate")?;

    println!("\n✓ Certificate provisioned successfully!");
    println!("  Cert: {}", cert_paths.cert.display());
    println!("  Key:  {}", cert_paths.key.display());
    println!("\nNext: `owneyd serve` will use HTTPS on port 443");

    Ok(())
}

/// First-run wizard. Creates the config file when absent (interactive), then
/// generates keys and prints the DNS record set.
fn setup(config_path: PathBuf, verify: bool, timeout: u64) -> anyhow::Result<()> {
    if !config_path.exists() {
        println!(
            "No config at {} — let's create one.\n",
            config_path.display()
        );
        let domain = prompt("Mail domain (the part after @, e.g. example.com)")?;
        let hostname = prompt_default(
            "This server's hostname (what MX points to)",
            &format!("mail.{domain}"),
        )?;
        let default_data = if cfg!(target_os = "macos") {
            format!(
                "{}/mailserver-data",
                std::env::var("HOME").unwrap_or_default()
            )
        } else {
            "/var/lib/mailserver".to_owned()
        };
        let data_dir = prompt_default("Data directory (back this up!)", &default_data)?;

        let contents = Config::example()
            .replace("example.com", &domain)
            .replace(&format!("mail.{domain}"), &hostname)
            .replace("/var/lib/mailserver", &data_dir);
        // Sanity check before writing.
        toml::from_str::<Config>(&contents).context("generated config did not validate")?;
        std::fs::write(&config_path, &contents)
            .with_context(|| format!("writing {}", config_path.display()))?;
        println!("\nWrote {}.\n", config_path.display());
    }

    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting async runtime")?
        .block_on(async move {
            let dkim = owney_delivery::DkimKeys::load_or_generate(
                &config.storage.data_dir,
                &config.server.domain,
            )
            .context("generating DKIM keys")?;

            let records = owney_setup::expected_records(
                &config.server.domain,
                &config.server.hostname,
                dkim.dns_record(),
            );

            println!("Publish these DNS records for {}:\n", config.server.domain);
            for record in &records {
                let tag = if record.required {
                    "required"
                } else {
                    "recommended"
                };
                println!("# {} ({tag})", record.purpose);
                println!("{}\n", record.zone_line());
            }
            println!(
                "Then: `owneyd setup --verify` waits for them, and \
                 `owneyd doctor` checks everything else.\n"
            );

            if verify {
                verify_records(&records, timeout).await?;
            }

            // Offer to set up ACME/Let's Encrypt
            println!("\n--- HTTPS Setup ---");
            let setup_https = prompt_yes_no("Set up HTTPS with Let's Encrypt?")?;
            if setup_https {
                setup_acme(&config).await?;
            } else {
                println!("⚠ Warning: HTTPS not configured. Set up manually or use a reverse proxy with TLS.");
            }

            Ok(())
        })
}

async fn verify_records(records: &[owney_setup::DnsRecord], timeout: u64) -> anyhow::Result<()> {
    let checker =
        owney_setup::check::Checker::new().map_err(|err| anyhow::anyhow!("dns resolver: {err}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    let mut pending: Vec<owney_setup::DnsRecord> =
        records.iter().filter(|r| r.required).cloned().collect();

    println!("Waiting for DNS (checking every 10s, timeout {timeout}s)...");
    loop {
        let outcomes = checker.check_all(&pending).await;
        let mut still = Vec::new();
        for outcome in outcomes {
            if outcome.is_ok() {
                println!("  ✓ {} {}", outcome.record.rtype, outcome.record.name);
            } else {
                still.push(outcome.record);
            }
        }
        pending = still;
        if pending.is_empty() {
            println!("\nAll required records verified. Your domain is ready.");
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            for record in &pending {
                println!("  ✗ {} {} — still not visible", record.rtype, record.name);
            }
            anyhow::bail!(
                "{} record(s) not verified in time (DNS can take a while to propagate — \
                 run `owneyd setup --verify` again)",
                pending.len()
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

async fn doctor(config: Config) -> anyhow::Result<()> {
    let checker =
        owney_setup::check::Checker::new().map_err(|err| anyhow::anyhow!("dns resolver: {err}"))?;
    let dkim =
        owney_delivery::DkimKeys::load_or_generate(&config.storage.data_dir, &config.server.domain)
            .context("loading DKIM keys")?;
    let records = owney_setup::expected_records(
        &config.server.domain,
        &config.server.hostname,
        dkim.dns_record(),
    );

    let mut failures = 0usize;

    println!("DNS records:");
    for outcome in checker.check_all(&records).await {
        use owney_setup::check::CheckStatus;
        let (mark, detail) = match &outcome.status {
            CheckStatus::Ok => ("✓", String::new()),
            CheckStatus::Skipped => ("~", "not published (recommended)".to_owned()),
            CheckStatus::Missing => ("✗", "missing".to_owned()),
            CheckStatus::Mismatch { found } => ("✗", format!("found: {found}")),
        };
        if !outcome.is_ok() && outcome.record.required {
            failures += 1;
        }
        println!(
            "  {mark} {} {}  {detail}",
            outcome.record.rtype, outcome.record.name
        );
    }

    println!("\nReverse DNS (FCrDNS):");
    let (ok, detail) = checker.check_fcrdns(&config.server.hostname).await;
    println!("  {} {detail}", if ok { "✓" } else { "✗" });
    if !ok {
        failures += 1;
    }

    println!("\nOutbound port 25:");
    let (ok, detail) = checker.check_outbound_25().await;
    // Blocked port 25 is only fatal without a smarthost.
    let fatal = !ok && config.delivery.smarthost.is_none();
    println!(
        "  {} {detail}",
        if ok {
            "✓"
        } else if fatal {
            "✗"
        } else {
            "~"
        }
    );
    if fatal {
        failures += 1;
    }

    println!("\nTLS:");
    match &config.tls {
        Some(tls) => match load_tls_acceptor(tls) {
            Ok(_) => println!("  ✓ certificate and key load ({})", tls.cert_path.display()),
            Err(err) => {
                failures += 1;
                println!("  ✗ {err:#}");
            }
        },
        None => println!("  ~ no [tls] section — STARTTLS disabled"),
    }

    if failures > 0 {
        anyhow::bail!("{failures} check(s) failed");
    }
    println!("\nAll checks passed.");
    Ok(())
}

fn prompt(question: &str) -> anyhow::Result<String> {
    use std::io::Write;
    loop {
        print!("{question}: ");
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("reading input")?;
        let answer = answer.trim().to_lowercase();
        if !answer.is_empty() {
            return Ok(answer);
        }
    }
}

fn prompt_default(question: &str, default: &str) -> anyhow::Result<String> {
    use std::io::Write;
    print!("{question} [{default}]: ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading input")?;
    let answer = answer.trim();
    Ok(if answer.is_empty() {
        default.to_owned()
    } else {
        answer.to_lowercase()
    })
}

/// Load config, init tracing, and hand off to an async entry point.
fn run<F, Fut>(config_path: PathBuf, entry: F) -> anyhow::Result<()>
where
    F: FnOnce(Config) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let config = Config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.log.filter.clone().into()),
        )
        .init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting async runtime")?
        .block_on(entry(config))
}

async fn serve(config: Config) -> anyhow::Result<()> {
    tracing::info!(
        domain = %config.server.domain,
        hostname = %config.server.hostname,
        data_dir = %config.storage.data_dir.display(),
        "starting mailserver"
    );

    let events = EventBus::default();
    let storage = Arc::new(
        Storage::open(&config.storage.data_dir, events.clone()).context("opening storage")?,
    );

    // Debug-log every event on the bus; real consumers (JMAP push, AI workers)
    // subscribe the same way in later milestones.
    let mut bus_rx = events.subscribe();
    tokio::spawn(async move {
        loop {
            match bus_rx.recv().await {
                Ok(event) => tracing::debug!(?event, "event"),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "event logger lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Inbound SMTP listeners.
    let spam_scanner: Box<dyn owney_spam::SpamScanner> = if config.spam.enabled {
        Box::new(owney_spam::HeuristicScanner::new(
            config.spam.dnsbl_zones.clone(),
        ))
    } else {
        // Stub scanner that always returns clean verdict
        Box::new(owney_spam::HeuristicScanner::new(Vec::new()))
    };

    let core = Arc::new(ServerCore {
        storage: storage.clone(),
        authenticator: Arc::new(owney_authn::Authenticator::new(
            config.server.hostname.clone(),
        )),
        spam_scanner,
        events: events.clone(),
        domain: config.server.domain.clone(),
        hostname: config.server.hostname.clone(),
        spam_config: config.spam.clone(),
    });
    let mut params = owney_smtp_in::SmtpParams::from_config(&config);
    if let Some(tls) = &config.tls {
        params = params.with_tls(load_tls_acceptor(tls).context("loading TLS certificates")?);
        tracing::info!(cert = %tls.cert_path.display(), "STARTTLS enabled");
    } else {
        tracing::warn!("no [tls] section — STARTTLS disabled; run `setup` (M2) or add cert paths");
    }
    let params = Arc::new(params);
    let mut listeners = Vec::new();
    for addr in &config.smtp.listen {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding smtp listener on {addr}"))?;
        listeners.push(tokio::spawn(owney_smtp_in::server::run_listener(
            listener,
            params.clone(),
            core.clone(),
        )));
    }

    // Outbound delivery worker.
    let delivery = Arc::new(build_delivery(&config, storage.clone(), events.clone())?);
    let worker = owney_delivery::spawn_worker(
        storage.clone(),
        events.clone(),
        delivery.router.clone(),
        delivery.params.clone(),
        delivery.wake.clone(),
    );

    // HTTP API (JMAP).
    let public_url = if config.api.public_url.is_empty() {
        format!("https://{}", config.server.hostname)
    } else {
        config.api.public_url.clone()
    };
    let mut dispatcher = jmap_core::Dispatcher::new("0");
    owney_jmap_mail::register(&mut dispatcher);
    dispatcher.add_capability(
        "urn:ietf:params:jmap:websocket",
        owney_api::push::websocket_capability(&public_url),
    );
    let federation_public_url = public_url.clone();
    let federation_config = owney_api::fed_sig::FederationConfig::from_env();

    // OIDC provider: built only when enabled. Loads/generates the RS256 signing
    // key under the data dir, then spawns the ceremony-state sweeper.
    let oidc = if config.oidc.enabled {
        let signing_key =
            owney_api::oidc::OidcSigningKey::load_or_generate(&config.storage.data_dir)
                .context("loading OIDC signing key")?;
        let oidc_state = Arc::new(
            owney_api::oidc::OidcState::new(config.oidc.clone(), public_url.clone(), signing_key)
                .context("building OIDC state")?,
        );
        owney_api::oidc::OidcState::spawn_sweeper(oidc_state.clone());
        tracing::info!(issuer = %public_url, "OIDC provider enabled");
        Some(oidc_state)
    } else {
        None
    };

    let api_state = Arc::new(owney_api::ApiState {
        dispatcher,
        storage: storage.clone(),
        events: events.clone(),
        submitter: Some(delivery.clone() as Arc<dyn owney_delivery::Submitter>),
        public_url,
        federation: federation_config.clone(),
        oidc,
    });
    let api_listener = tokio::net::TcpListener::bind(&config.api.listen)
        .await
        .with_context(|| format!("binding api listener on {}", config.api.listen))?;
    let api_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(
            api_listener,
            // ConnectInfo feeds the public scheduling endpoints' per-IP
            // rate limiting.
            owney_api::router(api_state)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        {
            tracing::error!(%err, "api server exited");
        }
    });

    // Calendar federation workers (only when federation is enabled): a periodic
    // reconciliation pull, an outbox drain for realtime push, and a bus
    // subscriber that fans change notifications out to subscribed peers.
    if federation_config.enabled {
        // OWNEY_FEDERATION_SYNC_INTERVAL_SECS overrides the reconciliation
        // pull interval (default 300s) — used by the local lab for fast sync.
        let mut sync_config = owney_api::background_worker::SyncWorkerConfig::default();
        if let Some(secs) = std::env::var("OWNEY_FEDERATION_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
        {
            sync_config.interval_secs = secs;
        }
        let sync_worker = owney_api::background_worker::SyncWorker::new(
            storage.clone(),
            federation_public_url.clone(),
            federation_config.clone(),
            sync_config,
        );
        tokio::spawn(async move { sync_worker.run().await });

        let notify_worker = owney_api::fed_worker::NotifyWorker::new(
            storage.clone(),
            federation_public_url.clone(),
            federation_config.clone(),
        );
        tokio::spawn(async move { notify_worker.run().await });

        let notify_storage = storage.clone();
        let mut bus = events.subscribe();
        tokio::spawn(async move {
            use owney_events::Event;
            while let Ok(event) = bus.recv().await {
                if let Event::StateChange { account_id, .. } = &*event {
                    // A change for this account may touch federated calendars;
                    // enqueue notifications for each of the account's calendars.
                    if let Ok(calendars) = notify_storage.list_calendars(*account_id).await {
                        for cal in calendars {
                            let _ = owney_api::fed_worker::notify_calendar_changed(
                                &notify_storage,
                                cal.id,
                            )
                            .await;
                        }
                    }
                }
            }
        });
    }

    // Enrichment worker: always spawned. With AI disabled it still runs the
    // deterministic, metadata-only detectors (unsubscribe, calendar invite)
    // so server attributes get produced; only mail-moving and model-backed
    // skills are gated on `ai.enabled`.
    let ai_worker = {
        let (provider, ai_config) = if config.ai.enabled {
            (
                build_ai_provider(&config),
                owney_ai::worker::AiConfig::default(),
            )
        } else {
            (None, owney_ai::worker::AiConfig::deterministic_only())
        };
        owney_ai::worker::spawn_worker(storage.clone(), events.clone(), provider, ai_config)
    };

    // Health check daemon.
    let doctor_worker = owney_doctor::spawn_checker(
        Arc::new(config.clone()),
        events.clone(),
        storage.clone(),
        std::time::Duration::from_secs(60),
    );

    // Certificate renewal worker.
    let renewal_worker = owney_api::renewal::spawn_renewal_worker(config.clone());

    tracing::info!(
        smtp_listeners = config.smtp.listen.len(),
        api = %config.api.listen,
        ai = config.ai.enabled,
        acme = config.acme.is_some() && config.acme.as_ref().map(|a| a.enabled).unwrap_or(false),
        "ready — accepting SMTP, delivering outbound, serving JMAP"
    );

    tokio::signal::ctrl_c()
        .await
        .context("waiting for shutdown signal")?;
    tracing::info!("shutting down");
    for task in &listeners {
        task.abort();
    }
    api_task.abort();
    worker.abort();
    doctor_worker.abort();
    renewal_worker.abort();
    ai_worker.abort();
    drop(core);
    drop(delivery);
    // Dropping the last Storage reference joins the writer thread and
    // checkpoints the WAL.
    drop(storage);
    Ok(())
}

/// Build the configured AI provider, or None (deterministic skills only).
fn build_ai_provider(config: &Config) -> Option<Arc<dyn owney_ai::AiProvider>> {
    match config.ai.provider.as_str() {
        "claude" => match std::env::var(&config.ai.api_key_env) {
            Ok(key) if !key.is_empty() => Some(Arc::new(owney_ai::ClaudeProvider::new(
                key,
                config.ai.model.clone(),
            ))),
            _ => {
                tracing::warn!(
                    env = %config.ai.api_key_env,
                    "no API key — AI runs deterministic skills only \
                     (screener, unsubscribe detection)"
                );
                None
            }
        },
        "openai-compat" => {
            let key = std::env::var(&config.ai.api_key_env)
                .ok()
                .filter(|k| !k.is_empty());
            Some(Arc::new(owney_ai::OpenAiCompatProvider::new(
                config.ai.base_url.clone(),
                key,
                config.ai.model.clone(),
            )))
        }
        _ => None,
    }
}

/// One construction path for the delivery service, shared by `serve` and the
/// admin CLI.
fn build_delivery(
    config: &Config,
    storage: Arc<Storage>,
    events: EventBus,
) -> anyhow::Result<owney_delivery::DeliveryService<owney_delivery::AnyRouter>> {
    let dkim =
        owney_delivery::DkimKeys::load_or_generate(&config.storage.data_dir, &config.server.domain)
            .context("loading DKIM keys")?;

    let router = match &config.delivery.smarthost {
        Some(smarthost) => {
            let (host, port) = smarthost
                .rsplit_once(':')
                .with_context(|| format!("smarthost {smarthost} must be host:port"))?;
            owney_delivery::AnyRouter::Static(owney_delivery::StaticRouter {
                relay: owney_delivery::Relay {
                    host: host.to_owned(),
                    port: port.parse().context("smarthost port")?,
                },
            })
        }
        None => owney_delivery::AnyRouter::Mx(Box::new(
            owney_delivery::MxRouter::new().context("dns resolver")?,
        )),
    };

    Ok(owney_delivery::DeliveryService {
        storage,
        events,
        dkim,
        router: Arc::new(router),
        params: owney_delivery::DeliveryParams {
            hostname: config.server.hostname.clone(),
            poll_interval: std::time::Duration::from_secs(config.delivery.poll_interval_secs),
            allow_invalid_certs: config.delivery.allow_invalid_certs,
        },
        wake: Arc::new(tokio::sync::Notify::new()),
    })
}

fn load_tls_acceptor(
    tls: &owney_core::config::TlsConfig,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(&tls.cert_path)
            .with_context(|| format!("opening {}", tls.cert_path.display()))?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("parsing certificate chain")?;
    anyhow::ensure!(
        !certs.is_empty(),
        "{} contains no certificates",
        tls.cert_path.display()
    );

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(&tls.key_path)
            .with_context(|| format!("opening {}", tls.key_path.display()))?,
    ))
    .context("parsing private key")?
    .with_context(|| format!("{} contains no private key", tls.key_path.display()))?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS config")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

async fn admin(config: Config, command: AdminCommand) -> anyhow::Result<()> {
    let events = EventBus::default();
    let storage = Arc::new(
        Storage::open(&config.storage.data_dir, events.clone()).context("opening storage")?,
    );

    let result = match command {
        AdminCommand::CreateAccount { email, name } => {
            anyhow::ensure!(
                email.ends_with(&format!("@{}", config.server.domain)),
                "{email} is not under this server's domain ({})",
                config.server.domain
            );
            let account = storage
                .create_account(&email, name.as_deref())
                .await
                .context("creating account")?;
            let cert = owney_pgp::own_cert(&storage, account.id)
                .await
                .map_err(|err| anyhow::anyhow!("generating PGP key: {err}"))?;
            println!("created account {} ({})", account.email, account.id);
            println!("PGP key: {}", cert.fingerprint());
            Ok(())
        }
        AdminCommand::Accounts => {
            let accounts = storage.accounts().await.context("listing accounts")?;
            if accounts.is_empty() {
                println!("no accounts yet — create one with `owneyd admin create-account`");
            }
            for account in accounts {
                println!(
                    "{}  {}  {}",
                    account.id,
                    account.email,
                    account.display_name.as_deref().unwrap_or("-")
                );
            }
            Ok(())
        }
        AdminCommand::Inbox {
            email,
            limit,
            mailbox,
        } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let messages = storage
                .list_mailbox(account.id, &mailbox, limit)
                .await
                .context("listing mailbox")?;
            if messages.is_empty() {
                println!("{mailbox} is empty");
            }
            for message in messages {
                let auth = message
                    .auth_results
                    .as_deref()
                    .and_then(|json| serde_json::from_str::<owney_authn::AuthVerdict>(json).ok())
                    .map(|verdict| format!("[spf={} dmarc={}]", verdict.spf, verdict.dmarc))
                    .unwrap_or_default();
                println!(
                    "{}  {}  {:<30}  {}  {}",
                    message.id,
                    owney_core::time::rfc2822_utc(message.received_at),
                    message.from_addr.as_deref().unwrap_or("-"),
                    message.subject.as_deref().unwrap_or("(no subject)"),
                    auth,
                );
            }
            Ok(())
        }
        AdminCommand::Show { email_id } => {
            let email_id = email_id.parse().map_err(|_| {
                anyhow::anyhow!("{email_id} is not a valid email id (see `admin inbox`)")
            })?;
            match storage
                .email_raw(email_id)
                .await
                .context("loading message")?
            {
                Some(raw) => {
                    use std::io::Write;
                    std::io::stdout()
                        .write_all(&raw)
                        .context("writing message")?;
                    Ok(())
                }
                None => anyhow::bail!("no message with id {email_id}"),
            }
        }
        AdminCommand::Send {
            from,
            to,
            subject,
            body,
            wait,
        } => {
            anyhow::ensure!(!to.is_empty(), "at least one recipient required");
            let account = storage
                .account_by_email(&from)
                .await
                .context("looking up account")?
                .with_context(|| format!("no local account {from}"))?;

            let body = match body {
                Some(body) => body,
                None => {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buf)
                        .context("reading body")?;
                    buf
                }
            };

            let delivery = build_delivery(&config, storage.clone(), events.clone())?;
            let raw = compose(&config.server.hostname, &account, &to, &subject, &body);
            let queued = delivery
                .submit(account.id, &account.email, &to, raw)
                .await
                .context("submitting message")?;
            println!("queued {} delivery(ies), stored in Sent", queued.len());

            if wait {
                let worker = owney_delivery::spawn_worker(
                    storage.clone(),
                    events.clone(),
                    delivery.router.clone(),
                    owney_delivery::DeliveryParams {
                        poll_interval: std::time::Duration::from_millis(250),
                        ..delivery.params.clone()
                    },
                    delivery.wake.clone(),
                );
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
                let mut pending: Vec<uuid::Uuid> = queued.clone();
                while !pending.is_empty() && std::time::Instant::now() < deadline {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    let mut still = Vec::new();
                    for id in pending {
                        match storage.queue_status(id).await.context("queue status")? {
                            Some((status, attempts, error))
                                if status != "queued" && status != "sending" =>
                            {
                                println!(
                                    "{id}: {status} (attempts: {attempts}{})",
                                    error
                                        .map(|e| format!(", last error: {e}"))
                                        .unwrap_or_default()
                                );
                            }
                            _ => still.push(id),
                        }
                    }
                    pending = still;
                }
                worker.abort();
                if !pending.is_empty() {
                    println!(
                        "{} delivery(ies) still retrying — the queue is durable; \
                         they resume when `serve` runs",
                        pending.len()
                    );
                }
            }
            Ok(())
        }
        AdminCommand::Queue => {
            let rows = storage.queue_overview().await.context("reading queue")?;
            if rows.is_empty() {
                println!("queue is empty");
            }
            for (id, recipient, status, attempts, next_attempt, last_error) in rows {
                println!(
                    "{id}  {recipient:<30}  {status:<8}  attempts={attempts}  next={}  {}",
                    owney_core::time::rfc2822_utc(next_attempt),
                    last_error.unwrap_or_default(),
                );
            }
            Ok(())
        }
        AdminCommand::Token { email, name } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let token = storage
                .create_token(account.id, &name)
                .await
                .context("creating token")?;
            println!("{token}");
            eprintln!("(store this now — it is not shown again)");
            Ok(())
        }
        AdminCommand::AiActivity { email, limit } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let actions = storage
                .ai_actions(account.id, limit)
                .await
                .context("listing")?;
            if actions.is_empty() {
                println!("no AI activity yet");
            }
            for action in actions {
                println!(
                    "{}  {}  [{}{}] {}",
                    action.id,
                    owney_core::time::rfc2822_utc(action.created_at),
                    action.skill,
                    if action.undone { ", undone" } else { "" },
                    action.description,
                );
            }
            Ok(())
        }
        AdminCommand::Undo { email, action_id } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let action_id = action_id.parse().context("bad action id")?;
            owney_ai::undo_action(&storage, account.id, action_id)
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            println!("undone");
            Ok(())
        }
        AdminCommand::CreateCalendar {
            email,
            name,
            description,
        } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let calendar = storage
                .create_calendar(account.id, name, description)
                .await
                .context("creating calendar")?;
            println!("created calendar {} ({})", calendar.name, calendar.id);
            Ok(())
        }
        AdminCommand::CreateSchedulingPage {
            email,
            calendar_id,
            slug,
            title,
            timezone,
            duration,
        } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let calendar_id = calendar_id.parse().context("bad calendar id")?;
            let localpart = email.split('@').next().unwrap_or("me");
            let display = account
                .display_name
                .clone()
                .unwrap_or_else(|| email.clone());
            let page = storage
                .create_scheduling_page(
                    account.id,
                    owney_storage::NewSchedulingPage {
                        slug: slug.unwrap_or_else(|| {
                            localpart
                                .to_lowercase()
                                .chars()
                                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                                .collect()
                        }),
                        title: title.unwrap_or_else(|| format!("Meet with {display}")),
                        description: None,
                        calendar_id,
                        timezone,
                        availability: owney_storage::Availability::default_business_hours(),
                        durations_mins: vec![duration],
                        buffer_before_mins: 0,
                        buffer_after_mins: 0,
                        min_notice_mins: 0,
                        max_per_day: None,
                        valid_from: None,
                        valid_until: None,
                    },
                )
                .await
                .context("creating scheduling page")?;
            let base = if config.api.public_url.is_empty() {
                format!("https://{}", config.server.hostname)
            } else {
                config.api.public_url.clone()
            };
            println!("created scheduling page {} ({})", page.slug, page.id);
            println!("{}/schedule/{}", base.trim_end_matches('/'), page.slug);
            Ok(())
        }
        AdminCommand::SchedulingPages { email } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let base = if config.api.public_url.is_empty() {
                format!("https://{}", config.server.hostname)
            } else {
                config.api.public_url.clone()
            };
            for page in storage
                .list_scheduling_pages(account.id)
                .await
                .context("listing pages")?
            {
                println!(
                    "{}  {}  [{}]  {}/schedule/{}",
                    page.id,
                    page.title,
                    page.status.as_str(),
                    base.trim_end_matches('/'),
                    page.slug,
                );
            }
            Ok(())
        }
        AdminCommand::Bookings { email } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let bookings = storage
                .list_bookings(account.id, None)
                .await
                .context("listing bookings")?;
            if bookings.is_empty() {
                println!("no bookings yet");
            }
            for b in bookings {
                println!(
                    "{}  {}  {} <{}>  [{}]",
                    b.id,
                    owney_core::time::iso8601_utc(b.start),
                    b.visitor_name,
                    b.visitor_email,
                    b.status,
                );
            }
            Ok(())
        }
        AdminCommand::CreateEvent {
            email,
            calendar_id,
            title,
            description,
            start,
            end,
        } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let calendar_id = calendar_id.parse().context("bad calendar id")?;
            // Ownership check: only the calendar's owner may add events here.
            storage
                .get_calendar(account.id, calendar_id)
                .await
                .context("looking up calendar")?
                .with_context(|| format!("account {email} has no calendar {calendar_id}"))?;
            let start = start.unwrap_or_else(|| unix_now() + 3600);
            let end = end.unwrap_or(start + 3600);
            anyhow::ensure!(end > start, "event must end after it starts");
            let event = storage
                .create_calendar_event(calendar_id, title, description, start, end, None)
                .await
                .context("creating event")?;
            println!("created event {} ({})", event.title, event.id);
            Ok(())
        }
        AdminCommand::CreateOauthClient {
            name,
            redirect_uri,
            public,
        } => {
            let (client, secret) = storage
                .create_oauth_client(&name, &redirect_uri, public)
                .await
                .context("creating oauth client")?;
            println!("client_id: {}", client.id);
            println!("name:      {}", client.name);
            println!(
                "type:      {}",
                if client.public {
                    "public (PKCE only)"
                } else {
                    "confidential"
                }
            );
            for uri in &client.redirect_uris {
                println!("redirect:  {uri}");
            }
            match secret {
                Some(secret) => {
                    println!("client_secret: {secret}");
                    eprintln!("(store the secret now — it is not shown again)");
                }
                None => eprintln!("(public client: no secret; the app must use PKCE)"),
            }
            Ok(())
        }
        AdminCommand::OauthClients => {
            let clients = storage
                .list_oauth_clients()
                .await
                .context("listing oauth clients")?;
            if clients.is_empty() {
                println!("no oauth clients — create one with `admin create-oauth-client`");
            }
            for client in clients {
                println!(
                    "{}  {}  {}{}",
                    client.id,
                    if client.public {
                        "public      "
                    } else {
                        "confidential"
                    },
                    client.name,
                    if client.disabled { "  [disabled]" } else { "" },
                );
            }
            Ok(())
        }
        AdminCommand::RevokeOauthClient { client_id } => {
            let id = client_id.parse().context("bad client id")?;
            storage
                .disable_oauth_client(id)
                .await
                .context("revoking oauth client")?;
            println!("revoked client {client_id}; all its tokens are now invalid");
            Ok(())
        }
        AdminCommand::OauthGrants { email } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let grants = storage
                .list_oauth_grants(account.id)
                .await
                .context("listing oauth grants")?;
            if grants.is_empty() {
                println!("{email} has not authorized any oauth clients");
            }
            for grant in grants {
                println!("{}  {}", grant.client_id, grant.scopes.join(" "));
            }
            Ok(())
        }
        AdminCommand::RevokeOauthGrant { email, client_id } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            let id = client_id.parse().context("bad client id")?;
            storage
                .revoke_oauth_grant(account.id, id)
                .await
                .context("revoking oauth grant")?;
            println!("revoked {email}'s consent for client {client_id}");
            Ok(())
        }
        AdminCommand::EnrollPasskey { email } => {
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            if !config.oidc.enabled {
                eprintln!(
                    "note: [oidc] enabled = false — the enroll page will 404 until OIDC is on"
                );
            }
            let token = storage
                .create_token(account.id, "passkey enrollment")
                .await
                .context("creating token")?;
            let public_url = if config.api.public_url.is_empty() {
                format!("https://{}", config.server.hostname)
            } else {
                config.api.public_url.clone()
            };
            println!("Open {public_url}/oidc/enroll and paste this token:");
            println!("{token}");
            eprintln!("(single account token — it is not shown again)");
            Ok(())
        }
        AdminCommand::DisableAccount { email } => {
            anyhow::ensure!(
                email.ends_with(&format!("@{}", config.server.domain)),
                "{email} is not under this server's domain ({})",
                config.server.domain
            );
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no active account {email}"))?;
            storage
                .disable_account(account.id)
                .await
                .context("disabling account")?;
            println!("disabled account {}", account.email);
            Ok(())
        }
        AdminCommand::EnableAccount { email } => {
            anyhow::ensure!(
                email.ends_with(&format!("@{}", config.server.domain)),
                "{email} is not under this server's domain ({})",
                config.server.domain
            );
            let account = storage
                .account_by_email_any_state(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            storage
                .enable_account(account.id)
                .await
                .context("enabling account")?;
            println!("enabled account {}", account.email);
            Ok(())
        }
        AdminCommand::DeleteAccount { email, confirm } => {
            anyhow::ensure!(
                confirm,
                "deletion requires --confirm flag (this is irreversible)"
            );
            anyhow::ensure!(
                email.ends_with(&format!("@{}", config.server.domain)),
                "{email} is not under this server's domain ({})",
                config.server.domain
            );
            let account = storage
                .account_by_email_any_state(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;
            storage
                .delete_account(account.id)
                .await
                .context("deleting account")?;
            println!(
                "permanently deleted account {} and all associated data",
                account.email
            );
            Ok(())
        }
        AdminCommand::CreateAlias {
            account,
            alias,
            label,
            expires_in_days,
        } => {
            anyhow::ensure!(
                account.ends_with(&format!("@{}", config.server.domain)),
                "{account} is not under this server's domain ({})",
                config.server.domain
            );
            anyhow::ensure!(
                alias.ends_with(&format!("@{}", config.server.domain)),
                "{alias} is not under this server's domain ({})",
                config.server.domain
            );
            let acc = storage
                .account_by_email(&account)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {account}"))?;

            let expires_at = expires_in_days.map(|days| unix_now() + (days as i64 * 86400));

            let alias_record = storage
                .create_alias(acc.id, &alias, label.as_deref(), expires_at)
                .await
                .context("creating alias")?;

            let expires_str = if let Some(ts) = alias_record.expires_at {
                format!(" (expires: {})", owney_core::time::rfc2822_utc(ts))
            } else {
                " (permanent)".to_string()
            };
            println!("created alias {}{}", alias_record.alias_email, expires_str);
            Ok(())
        }
        AdminCommand::ListAliases { email } => {
            anyhow::ensure!(
                email.ends_with(&format!("@{}", config.server.domain)),
                "{email} is not under this server's domain ({})",
                config.server.domain
            );
            let account = storage
                .account_by_email(&email)
                .await
                .context("looking up account")?
                .with_context(|| format!("no account {email}"))?;

            let aliases = storage
                .list_aliases_for_account(account.id)
                .await
                .context("listing aliases")?;

            if aliases.is_empty() {
                println!("no active aliases for {}", account.email);
            } else {
                println!("aliases for {}:", account.email);
                for alias in aliases {
                    let expires_str = if let Some(ts) = alias.expires_at {
                        format!(" (expires: {})", owney_core::time::rfc2822_utc(ts))
                    } else {
                        " (permanent)".to_string()
                    };
                    let label_str = alias
                        .label
                        .as_ref()
                        .map(|l| format!(" [{}]", l))
                        .unwrap_or_default();
                    println!("  {}{}{}", alias.alias_email, label_str, expires_str);
                }
            }
            Ok(())
        }
        AdminCommand::DeactivateAlias { alias } => {
            anyhow::ensure!(
                alias.ends_with(&format!("@{}", config.server.domain)),
                "{alias} is not under this server's domain ({})",
                config.server.domain
            );

            // Find the alias by email to get its ID
            let alias_id = storage
                .find_alias_id(&alias)
                .await
                .context("looking up alias")?
                .with_context(|| format!("no alias {}", alias))?;

            storage
                .deactivate_alias(&alias_id)
                .await
                .context("deactivating alias")?;
            println!("deactivated alias {}", alias);
            Ok(())
        }
        AdminCommand::DkimRecord => {
            let dkim = owney_delivery::DkimKeys::load_or_generate(
                &config.storage.data_dir,
                &config.server.domain,
            )
            .context("loading DKIM keys")?;
            let (name, value) = dkim.dns_record();
            println!("Publish this TXT record:\n\n{name}. IN TXT \"{value}\"");
            Ok(())
        }
    };

    drop(storage);
    result
}

/// Compose a simple text/plain RFC 5322 message for `admin send`.
fn compose(
    hostname: &str,
    account: &owney_storage::Account,
    to: &[String],
    subject: &str,
    body: &str,
) -> Vec<u8> {
    let from = match &account.display_name {
        Some(name) => format!("{name} <{}>", account.email),
        None => format!("<{}>", account.email),
    };
    let body = body.replace('\n', "\r\n");
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\n\
         Message-ID: <{id}@{hostname}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n{body}",
        to = to.join(", "),
        date = owney_core::time::rfc2822_utc(unix_now()),
        id = uuid::Uuid::now_v7(),
    )
    .into_bytes()
}

async fn backup(config: Config, command: BackupCommand) -> anyhow::Result<()> {
    match command {
        BackupCommand::Create { output } => {
            let default_output = config.storage.data_dir.join("backups");
            let output_dir = output.as_ref().unwrap_or(&default_output);
            std::fs::create_dir_all(output_dir).context("creating output directory")?;

            let archive_path = owney_backup::create_backup(&config, output_dir)
                .await
                .context("creating backup")?;

            println!("✓ Backup created: {}", archive_path.display());
            println!(
                "  To restore: owneyd backup restore {}",
                archive_path.display()
            );
            Ok(())
        }
        BackupCommand::Restore { archive, target } => {
            let target_dir = target.unwrap_or(config.storage.data_dir.clone());
            anyhow::ensure!(
                !target_dir.exists() || std::fs::read_dir(&target_dir)?.next().is_none(),
                "target directory must be empty or non-existent"
            );
            std::fs::create_dir_all(&target_dir).context("creating target directory")?;

            // Restore master key first (user must provide it)
            let master_key_src = config.storage.data_dir.join(owney_storage::MASTER_KEY_FILE);
            if master_key_src.exists() {
                let master_key_dst = target_dir.join(owney_storage::MASTER_KEY_FILE);
                std::fs::copy(&master_key_src, &master_key_dst)
                    .context("copying master key to target")?;
                println!("  Master key preserved");
            } else {
                println!("⚠ Warning: no master key found; you may need to provide one manually");
            }

            let manifest = owney_backup::restore_backup(&archive, &target_dir)
                .await
                .context("restoring backup")?;

            println!("✓ Backup restored: version {}", manifest.version);
            println!("  Data directory: {}", target_dir.display());
            println!(
                "  Master key hash: {} (verify matches backup)",
                manifest.master_key_hash
            );
            Ok(())
        }
    }
}

async fn update(
    config: Config,
    new_binary: std::path::PathBuf,
    expected_hash: String,
    dry_run: bool,
) -> anyhow::Result<()> {
    // Get the current binary path (ourselves)
    let current_binary = std::env::current_exe().context("determining current binary path")?;

    println!("Mailserver Update");
    println!("================");
    println!("Current binary: {}", current_binary.display());
    println!("New binary: {}", new_binary.display());
    println!("Expected hash: {}", expected_hash);
    println!();

    // Perform update (or dry-run)
    let report =
        owney_update::perform_update(&config, &new_binary, &expected_hash, &current_binary)
            .await
            .context("update failed")?;

    if dry_run {
        println!("✓ Dry-run successful");
        println!(
            "  Migrations: {}",
            if report.migrations_ok { "OK" } else { "FAILED" }
        );
        println!("  Binary would be swapped (not done in dry-run mode)");
        return Ok(());
    }

    println!("✓ Update successful");
    println!("  New binary is now in place");
    println!("  IMPORTANT: You must restart the server for the update to take effect");
    println!("  Suggested: systemctl restart owneyd");
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
