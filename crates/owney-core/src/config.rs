//! Server configuration, loaded from a single TOML file.
//!
//! Only what M0 needs. Sections for SMTP, API, AI, and PGP arrive with their
//! milestones — additions must always be backward-compatible (serde defaults),
//! because "easy to update" means an old config file always keeps working.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub smtp: SmtpConfig,
    /// Optional until the M2 setup wizard provisions ACME automatically.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub ai: AiSection,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AiSection {
    /// Master switch. Deterministic skills (screener, unsubscribe detection)
    /// need no model or key.
    pub enabled: bool,
    /// "claude", "openai-compat", or "none" (deterministic skills only).
    pub provider: String,
    /// Model name for the provider.
    pub model: String,
    /// Base URL for openai-compat providers (Ollama, vLLM, gateways).
    pub base_url: String,
    /// Environment variable holding the API key.
    pub api_key_env: String,
}

impl Default for AiSection {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: "claude".to_owned(),
            model: "claude-haiku-4-5-20251001".to_owned(),
            base_url: "http://127.0.0.1:11434".to_owned(),
            api_key_env: "ANTHROPIC_API_KEY".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApiConfig {
    /// Socket address for the HTTP API (JMAP + REST + MCP). Put a TLS
    /// terminator in front, or bind localhost and tunnel, until the built-in
    /// HTTPS listener lands.
    pub listen: String,
    /// Public base URL clients use; defaults to `https://<hostname>` when empty.
    pub public_url: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8380".to_owned(),
            public_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeliveryConfig {
    /// Route ALL outbound mail through this relay ("host:port") instead of
    /// MX lookups — for providers whose IPs can't send on port 25 directly.
    pub smarthost: Option<String>,
    /// Accept invalid TLS certificates on outbound connections. Dev only.
    pub allow_invalid_certs: bool,
    /// Queue poll interval in seconds when idle.
    pub poll_interval_secs: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            smarthost: None,
            allow_invalid_certs: false,
            poll_interval_secs: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert_path: PathBuf,
    /// PEM private key (PKCS#8 or RSA).
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// The mail domain this server is authoritative for (the part after `@`).
    pub domain: String,
    /// This machine's FQDN, used in SMTP banners, HELO, and TLS certificates.
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Root directory for the database, blob store, and key material.
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SmtpConfig {
    /// Socket addresses the inbound SMTP (MX) listener binds.
    pub listen: Vec<String>,
    /// Hard cap on message size in bytes, advertised via the SIZE extension.
    pub max_message_size: u64,
    /// Maximum recipients per message.
    pub max_recipients: usize,
    /// Maximum number of command-syntax errors per connection before
    /// we drop the session with `421`. Default 10 matches Postfix's
    /// `smtpd_hard_error_limit` of 10 — typical mail clients issue <5
    /// in the worst case, so the headroom is for deliberate probing.
    #[serde(default = "default_smtp_max_errors")]
    pub max_errors: usize,
    /// Per-read idle timeout. Bytes for `read_timeout` after a connection
    /// open or after the start of DATA cause the session to be dropped
    /// with `421`. Default 5 minutes, configurable for noisy networks.
    #[serde(default = "default_smtp_read_timeout")]
    pub read_timeout_secs: u64,
}

fn default_smtp_max_errors() -> usize {
    10
}
fn default_smtp_read_timeout() -> u64 {
    300
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:25".to_owned()],
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            max_errors: default_smtp_max_errors(),
            read_timeout_secs: default_smtp_read_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// A `tracing_subscriber::EnvFilter` directive, e.g. `info` or `owney_smtp_in=debug,info`.
    pub filter: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            filter: "info".to_owned(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: Config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Conservative DNS-name check. Accepts what most operators expect:
    /// lowercase letters / digits / hyphens, dotted labels, no whitespace,
    /// no trailing dot, no leading dot, no empty labels, total length ≤ 253.
    /// This is *not* a full RFC 1123 / 5890 parser — IDN (`xn--` punycode)
    /// and the internationalized local-part are out of scope — but it's
    /// good enough to catch typos at startup before they bite at SMTP time.
    fn validate(&self) -> Result<(), ConfigError> {
        for (field, value) in [
            ("server.domain", &self.server.domain),
            ("server.hostname", &self.server.hostname),
        ] {
            validate_dns_name(field, value)?;
        }
        Ok(())
    }

    /// A commented example config, printed by `mailserverd config example`.
    pub fn example() -> &'static str {
        r#"# mailserver configuration

[server]
# The mail domain this server handles (the part after the @).
domain = "example.com"
# This machine's fully-qualified hostname (what your MX record points to).
hostname = "mail.example.com"

[storage]
# Where the database, blobs, and key material live. Back this directory up.
data_dir = "/var/lib/mailserver"

[smtp]
# Inbound SMTP (MX) listeners.
 listen = ["0.0.0.0:25"]
# Maximum message size in bytes (advertised via the SIZE extension).
max_message_size = 26214400
# Maximum recipients per message.
max_recipients = 100
# Per-connection syntax-error budget before 421-drop. Default 10.
max_errors = 10
# Per-read idle timeout in seconds. Default 300.
read_timeout_secs = 300

# Optional until `setup` provisions certificates automatically (M2):
# [tls]
# cert_path = "/etc/mailserver/tls/fullchain.pem"
# key_path = "/etc/mailserver/tls/privkey.pem"

[delivery]
# Uncomment to route all outbound mail through a relay instead of direct MX
# delivery (needed on providers that block port 25):
# smarthost = "smtp.relay.example:587"
# Queue poll interval in seconds when idle.
poll_interval_secs = 15

[api]
# HTTP API (JMAP). Bind localhost and put TLS in front for now.
listen = "127.0.0.1:8380"
# Public base URL; defaults to https://<server.hostname> when empty.
public_url = ""

[ai]
# The AI layer. Screening and unsubscribe detection are deterministic and
# always available; categorization and summaries need a provider.
enabled = true
# "claude" (default; reads the key from api_key_env), "openai-compat"
# (Ollama/vLLM at base_url), or "none".
provider = "claude"
model = "claude-haiku-4-5-20251001"
base_url = "http://127.0.0.1:11434"
api_key_env = "ANTHROPIC_API_KEY"

[log]
# Log filter, e.g. "info" or "owney_smtp_in=debug,info".
filter = "info"
"#
    }
}

/// Conservative DNS-name validator. Not a full RFC 1123 / 5890 parser.
fn validate_dns_name(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > 253 {
        return Err(ConfigError::Invalid {
            field,
            reason: format!("{value:?} is not a valid DNS name"),
        });
    }
    if value.starts_with('.') || value.ends_with('.') {
        return Err(ConfigError::Invalid {
            field,
            reason: format!("{value:?} has leading or trailing dot"),
        });
    }
    for label in value.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ConfigError::Invalid {
                field,
                reason: format!("{value:?} has an empty or overlong label"),
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ConfigError::Invalid {
                field,
                reason: format!("{value:?} has a label starting or ending with '-'"),
            });
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ConfigError::Invalid {
                field,
                reason: format!("{value:?} contains non-DNS characters"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses_and_validates() {
        let config: Config = toml::from_str(Config::example()).expect("example must parse");
        config.validate().expect("example must validate");
        assert_eq!(config.server.domain, "example.com");
        assert_eq!(config.log.filter, "info");
    }

    #[test]
    fn missing_log_section_defaults() {
        let config: Config = toml::from_str(
            r#"
            [server]
            domain = "example.com"
            hostname = "mail.example.com"
            [storage]
            data_dir = "/tmp/x"
            "#,
        )
        .expect("parses");
        assert_eq!(config.log.filter, "info");
    }

    #[test]
    fn bad_domain_rejected() {
        let config: Config = toml::from_str(
            r#"
            [server]
            domain = "not a domain"
            hostname = "mail.example.com"
            [storage]
            data_dir = "/tmp/x"
            "#,
        )
        .expect("parses");
        assert!(config.validate().is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        let result = toml::from_str::<Config>(
            r#"
            [server]
            domain = "example.com"
            hostname = "mail.example.com"
            typo_field = true
            [storage]
            data_dir = "/tmp/x"
            "#,
        );
        assert!(
            result.is_err(),
            "typos in config must be errors, not silently ignored"
        );
    }

    #[test]
    fn dns_name_validator_rejects_garbage() {
        for bad in [
            "",              // empty
            ".",             // leading dot
            "example.",      // trailing dot
            ".example.com",  // leading dot
            "ex..ample.com", // empty label
            "example-.com",  // label ends with '-'
            "-example.com",  // label starts with '-'
            "exa mple.com",  // whitespace
            &"a".repeat(64), // overlong label (64 chars)
            "exömple.com",   // non-ASCII
        ] {
            let err = validate_dns_name("server.domain", bad)
                .expect_err(&format!("{bad:?} must be rejected"));
            assert!(matches!(err, ConfigError::Invalid { .. }));
        }
    }

    #[test]
    fn dns_name_validator_accepts_normal_names() {
        for ok in [
            "example.com",
            "mail.example.com",
            "host1.internal.lan",
            "_dmarc.example.com", // underscore is allowed (RFC 2782 SRV)
        ] {
            validate_dns_name("server.domain", ok)
                .unwrap_or_else(|e| panic!("{ok:?} accepted: {e:?}"));
        }
    }

    #[test]
    fn config_load_missing_file_yields_read_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nope.toml");
        let err = Config::load(&path).expect_err("missing file must error");
        assert!(matches!(err, ConfigError::Read { .. }), "got: {err:?}");
    }

    #[test]
    fn config_load_parse_error_yields_parse_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, b"[server\ndomain = ").expect("write");
        let err = Config::load(&path).expect_err("broken toml must error");
        assert!(matches!(err, ConfigError::Parse { .. }), "got: {err:?}");
    }

    #[test]
    fn config_load_validate_error_yields_invalid_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.toml");
        std::fs::write(
            &path,
            br#"
            [server]
            domain = "bad domain with spaces"
            hostname = "mail.example.com"
            [storage]
            data_dir = "/tmp/x"
            [smtp]
            listen = ["0.0.0.0:25"]
            "#,
        )
        .expect("write");
        let err = Config::load(&path).expect_err("invalid config must error");
        assert!(matches!(err, ConfigError::Invalid { .. }), "got: {err:?}");
    }

    #[test]
    fn config_load_deny_unknown_fields_on_optional_sections() {
        // A typo in `[ai]` (currently `Option<AiConfig>`) must surface,
        // because `AiConfig` carries `deny_unknown_fields`.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("typo.toml");
        std::fs::write(
            &path,
            br#"
            [server]
            domain = "example.com"
            hostname = "mail.example.com"
            [storage]
            data_dir = "/tmp/x"
            [smtp]
            listen = ["0.0.0.0:25"]
            [ai]
            provide = "claude"
            [log]
            "#,
        )
        .expect("write");
        let err = Config::load(&path).expect_err("typo must error");
        assert!(matches!(err, ConfigError::Parse { .. }), "got: {err:?}");
    }
}
