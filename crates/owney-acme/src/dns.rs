use crate::error::AcmeError;

/// DNS provider for DNS-01 challenge handling.
#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create a DNS TXT record for ACME challenge.
    async fn create_challenge_record(
        &self,
        domain: &str,
        challenge_value: &str,
    ) -> Result<(), AcmeError>;

    /// Delete a DNS TXT record after ACME validation.
    async fn delete_challenge_record(
        &self,
        domain: &str,
        challenge_value: &str,
    ) -> Result<(), AcmeError>;

    /// Wait for DNS propagation (polling for the record).
    async fn wait_for_propagation(
        &self,
        domain: &str,
        challenge_value: &str,
        timeout_secs: u64,
    ) -> Result<(), AcmeError>;
}

/// Challenge record metadata.
#[derive(Debug, Clone)]
pub struct ChallengeRecord {
    pub fqdn: String,
    pub value: String,
}

impl ChallengeRecord {
    /// Constructs the ACME challenge FQDN from a domain.
    pub fn fqdn(domain: &str) -> String {
        format!("_acme-challenge.{domain}")
    }

    pub fn new(domain: &str, value: String) -> Self {
        Self {
            fqdn: Self::fqdn(domain),
            value,
        }
    }
}
