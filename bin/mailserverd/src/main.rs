//! The single deployable binary.

mod handler;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use ms_core::Config;
use ms_events::EventBus;
use ms_storage::Storage;

use crate::handler::ServerCore;

#[derive(Debug, Parser)]
#[command(
    name = "mailserverd",
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
    Backup,
    /// Administer a running installation.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Diagnose DNS, reverse DNS, TLS, and outbound connectivity.
    Doctor,
    /// Configuration helpers.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
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
        Command::Backup => anyhow::bail!("`backup` arrives in milestone M6"),
        Command::Doctor => run(cli.config, doctor),
        Command::Serve => run(cli.config, serve),
        Command::Admin { command } => run(cli.config, move |config| admin(config, command)),
    }
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
            let dkim = ms_delivery::DkimKeys::load_or_generate(
                &config.storage.data_dir,
                &config.server.domain,
            )
            .context("generating DKIM keys")?;

            let records = ms_setup::expected_records(
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
                "Then: `mailserverd setup --verify` waits for them, and \
                 `mailserverd doctor` checks everything else.\n"
            );

            if verify {
                verify_records(&records, timeout).await?;
            }
            Ok(())
        })
}

async fn verify_records(records: &[ms_setup::DnsRecord], timeout: u64) -> anyhow::Result<()> {
    let checker =
        ms_setup::check::Checker::new().map_err(|err| anyhow::anyhow!("dns resolver: {err}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    let mut pending: Vec<ms_setup::DnsRecord> =
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
                 run `mailserverd setup --verify` again)",
                pending.len()
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

async fn doctor(config: Config) -> anyhow::Result<()> {
    let checker =
        ms_setup::check::Checker::new().map_err(|err| anyhow::anyhow!("dns resolver: {err}"))?;
    let dkim =
        ms_delivery::DkimKeys::load_or_generate(&config.storage.data_dir, &config.server.domain)
            .context("loading DKIM keys")?;
    let records = ms_setup::expected_records(
        &config.server.domain,
        &config.server.hostname,
        dkim.dns_record(),
    );

    let mut failures = 0usize;

    println!("DNS records:");
    for outcome in checker.check_all(&records).await {
        use ms_setup::check::CheckStatus;
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
    let core = Arc::new(ServerCore {
        storage: storage.clone(),
        authenticator: Arc::new(ms_authn::Authenticator::new(config.server.hostname.clone())),
        events: events.clone(),
        domain: config.server.domain.clone(),
        hostname: config.server.hostname.clone(),
    });
    let mut params = ms_smtp_in::SmtpParams::from_config(&config);
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
        listeners.push(tokio::spawn(ms_smtp_in::server::run_listener(
            listener,
            params.clone(),
            core.clone(),
        )));
    }

    // Outbound delivery worker.
    let delivery = Arc::new(build_delivery(&config, storage.clone(), events.clone())?);
    let worker = ms_delivery::spawn_worker(
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
    ms_jmap_mail::register(&mut dispatcher);
    dispatcher.add_capability(
        "urn:ietf:params:jmap:websocket",
        ms_api::push::websocket_capability(&public_url),
    );
    let api_state = Arc::new(ms_api::ApiState {
        dispatcher,
        storage: storage.clone(),
        events: events.clone(),
        submitter: Some(delivery.clone() as Arc<dyn ms_core::Submitter>),
        public_url,
    });
    let api_listener = tokio::net::TcpListener::bind(&config.api.listen)
        .await
        .with_context(|| format!("binding api listener on {}", config.api.listen))?;
    let api_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(api_listener, ms_api::router(api_state)).await {
            tracing::error!(%err, "api server exited");
        }
    });

    // AI enrichment worker.
    let ai_worker = if config.ai.enabled {
        let provider = build_ai_provider(&config);
        Some(ms_ai::worker::spawn_worker(
            storage.clone(),
            events.clone(),
            provider,
            ms_ai::worker::AiConfig::default(),
        ))
    } else {
        None
    };

    tracing::info!(
        smtp_listeners = config.smtp.listen.len(),
        api = %config.api.listen,
        ai = config.ai.enabled,
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
    if let Some(ai_worker) = &ai_worker {
        ai_worker.abort();
    }
    drop(core);
    drop(delivery);
    // Dropping the last Storage reference joins the writer thread and
    // checkpoints the WAL.
    drop(storage);
    Ok(())
}

/// Build the configured AI provider, or None (deterministic skills only).
fn build_ai_provider(config: &Config) -> Option<Arc<dyn ms_ai::AiProvider>> {
    match config.ai.provider.as_str() {
        "claude" => match std::env::var(&config.ai.api_key_env) {
            Ok(key) if !key.is_empty() => Some(Arc::new(ms_ai::ClaudeProvider::new(
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
            Some(Arc::new(ms_ai::OpenAiCompatProvider::new(
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
) -> anyhow::Result<ms_delivery::DeliveryService<ms_delivery::AnyRouter>> {
    let dkim =
        ms_delivery::DkimKeys::load_or_generate(&config.storage.data_dir, &config.server.domain)
            .context("loading DKIM keys")?;

    let router = match &config.delivery.smarthost {
        Some(smarthost) => {
            let (host, port) = smarthost
                .rsplit_once(':')
                .with_context(|| format!("smarthost {smarthost} must be host:port"))?;
            ms_delivery::AnyRouter::Static(ms_delivery::StaticRouter {
                relay: ms_delivery::Relay {
                    host: host.to_owned(),
                    port: port.parse().context("smarthost port")?,
                },
            })
        }
        None => ms_delivery::AnyRouter::Mx(Box::new(
            ms_delivery::MxRouter::new().context("dns resolver")?,
        )),
    };

    Ok(ms_delivery::DeliveryService {
        storage,
        events,
        dkim,
        router: Arc::new(router),
        params: ms_delivery::DeliveryParams {
            hostname: config.server.hostname.clone(),
            poll_interval: std::time::Duration::from_secs(config.delivery.poll_interval_secs),
            allow_invalid_certs: config.delivery.allow_invalid_certs,
        },
        wake: Arc::new(tokio::sync::Notify::new()),
    })
}

fn load_tls_acceptor(
    tls: &ms_core::config::TlsConfig,
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
            let cert = ms_pgp::own_cert(&storage, account.id)
                .await
                .map_err(|err| anyhow::anyhow!("generating PGP key: {err}"))?;
            println!("created account {} ({})", account.email, account.id);
            println!("PGP key: {}", cert.fingerprint());
            Ok(())
        }
        AdminCommand::Accounts => {
            let accounts = storage.accounts().await.context("listing accounts")?;
            if accounts.is_empty() {
                println!("no accounts yet — create one with `mailserverd admin create-account`");
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
                    .and_then(|json| serde_json::from_str::<ms_authn::AuthVerdict>(json).ok())
                    .map(|verdict| format!("[spf={} dmarc={}]", verdict.spf, verdict.dmarc))
                    .unwrap_or_default();
                println!(
                    "{}  {}  {:<30}  {}  {}",
                    message.id,
                    ms_core::time::rfc2822_utc(message.received_at),
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
                let worker = ms_delivery::spawn_worker(
                    storage.clone(),
                    events.clone(),
                    delivery.router.clone(),
                    ms_delivery::DeliveryParams {
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
                    ms_core::time::rfc2822_utc(next_attempt),
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
                    ms_core::time::rfc2822_utc(action.created_at),
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
            ms_ai::undo_action(&storage, account.id, action_id)
                .await
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            println!("undone");
            Ok(())
        }
        AdminCommand::DkimRecord => {
            let dkim = ms_delivery::DkimKeys::load_or_generate(
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
    account: &ms_storage::Account,
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
        date = ms_core::time::rfc2822_utc(unix_now()),
        id = uuid::Uuid::now_v7(),
    )
    .into_bytes()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
