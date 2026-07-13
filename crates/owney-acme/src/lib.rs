//! ACME client for automated HTTPS provisioning via Let's Encrypt.
//! Handles certificate requests, DNS-01 challenges, and renewal.

pub mod acme;
pub mod dns;
pub mod error;
pub mod provider;

pub use acme::AcmeClient;
pub use dns::DnsProvider;
pub use error::AcmeError;
pub use provider::{CloudflareProvider, Route53Provider};

use std::path::PathBuf;

/// Configuration for ACME certificate provisioning.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// Domains to certificate (primary + SANs).
    pub domains: Vec<String>,
    /// Email for Let's Encrypt registration.
    pub email: String,
    /// DNS provider to use for DNS-01 challenges.
    pub dns_provider: String,
    /// Production Let's Encrypt directory URL. Set to staging for testing.
    pub directory_url: String,
}

impl AcmeConfig {
    /// Production Let's Encrypt directory.
    pub fn production() -> &'static str {
        "https://acme-v02.api.letsencrypt.org/directory"
    }

    /// Staging Let's Encrypt directory (for testing, unlimited rate limits).
    pub fn staging() -> &'static str {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    }

    /// Creates a production config.
    pub fn new(domains: Vec<String>, email: String, dns_provider: String) -> Self {
        Self {
            domains,
            email,
            dns_provider,
            directory_url: Self::production().to_string(),
        }
    }

    /// Creates a staging config (for testing).
    pub fn staging_new(domains: Vec<String>, email: String, dns_provider: String) -> Self {
        Self {
            domains,
            email,
            dns_provider,
            directory_url: Self::staging().to_string(),
        }
    }
}

/// Paths to certificate and key files.
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CertPaths {
    /// Creates paths in a data directory.
    pub fn in_dir(data_dir: &PathBuf) -> Self {
        let tls_dir = data_dir.join("tls");
        Self {
            cert: tls_dir.join("cert.pem"),
            key: tls_dir.join("key.pem"),
        }
    }
}
