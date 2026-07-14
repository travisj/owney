use crate::dns::DnsProvider;
use crate::error::AcmeError;
use crate::{AcmeConfig, CertPaths};
use acme2::{
    AccountBuilder, AuthorizationStatus, ChallengeStatus, Csr, DirectoryBuilder, OrderBuilder,
    OrderStatus,
};
use chrono::Utc;
use rcgen::generate_simple_self_signed;
use std::fs;
use std::path::Path;
use std::time::Duration;
use x509_parser::prelude::*;

/// How often to poll the ACME server while waiting for state changes.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum number of polls before giving up on a pending object.
const POLL_ATTEMPTS: usize = 60;

/// ACME client for Let's Encrypt certificate provisioning.
pub struct AcmeClient {
    config: AcmeConfig,
    dns_provider: Box<dyn DnsProvider>,
}

impl std::fmt::Debug for AcmeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AcmeClient {
    /// Creates a new ACME client.
    pub fn new(config: AcmeConfig, dns_provider: Box<dyn DnsProvider>) -> Self {
        Self {
            config,
            dns_provider,
        }
    }

    /// Requests a new certificate from Let's Encrypt.
    /// This handles the full ACME flow: order, challenges, validation, and issuance.
    pub async fn request_certificate(&self, cert_paths: &CertPaths) -> Result<(), AcmeError> {
        tracing::info!(
            domains = ?self.config.domains,
            directory = %self.config.directory_url,
            "requesting certificate from ACME server"
        );

        // Fetch the ACME directory.
        let directory = DirectoryBuilder::new(self.config.directory_url.clone())
            .build()
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Directory fetch failed: {e}")))?;

        // Account registration with Let's Encrypt.
        let mut account_builder = AccountBuilder::new(directory);
        account_builder
            .contact(vec![format!("mailto:{}", self.config.email)])
            .terms_of_service_agreed(true);
        let account = account_builder
            .build()
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Account registration failed: {e}")))?;

        // Order a certificate for all configured domains.
        let mut order_builder = OrderBuilder::new(account);
        for domain in &self.config.domains {
            order_builder.add_dns_identifier(domain.clone());
        }
        let order = order_builder
            .build()
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Order creation failed: {e}")))?;

        // Process DNS-01 challenges for each pending authorization.
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Fetching authorizations failed: {e}")))?;

        for authorization in authorizations {
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }

            let domain = authorization.identifier.value.clone();

            let challenge = authorization
                .get_challenge("dns-01")
                .ok_or_else(|| AcmeError::AcmeRequest("No DNS-01 challenge found".to_string()))?;

            // The DNS-01 TXT record value is the base64url-encoded SHA-256
            // digest of the key authorization.
            let validation_value = challenge
                .key_authorization_encoded()
                .map_err(|e| {
                    AcmeError::AcmeRequest(format!("Key authorization computation failed: {e}"))
                })?
                .ok_or_else(|| {
                    AcmeError::AcmeRequest("Challenge is missing its token".to_string())
                })?;

            tracing::info!(domain = %domain, "creating DNS challenge record");

            // Create DNS record via provider.
            self.dns_provider
                .create_challenge_record(&domain, &validation_value)
                .await?;

            // Wait for DNS propagation.
            self.dns_provider
                .wait_for_propagation(&domain, &validation_value, 60)
                .await?;

            // Tell ACME server to validate the challenge, then wait for it
            // to leave the pending/processing states.
            let challenge = challenge.validate().await.map_err(|e| {
                AcmeError::ChallengeValidation(format!("Challenge validation failed: {e}"))
            })?;
            let challenge = challenge
                .wait_done(POLL_INTERVAL, POLL_ATTEMPTS)
                .await
                .map_err(|e| {
                    AcmeError::ChallengeValidation(format!("Challenge polling failed: {e}"))
                })?;
            if challenge.status != ChallengeStatus::Valid {
                return Err(AcmeError::ChallengeValidation(format!(
                    "Challenge for {domain} ended in state {:?}",
                    challenge.status
                )));
            }

            let authorization = authorization
                .wait_done(POLL_INTERVAL, POLL_ATTEMPTS)
                .await
                .map_err(|e| {
                    AcmeError::ChallengeValidation(format!("Authorization polling failed: {e}"))
                })?;
            if authorization.status != AuthorizationStatus::Valid {
                return Err(AcmeError::ChallengeValidation(format!(
                    "Authorization for {domain} ended in state {:?}",
                    authorization.status
                )));
            }

            tracing::info!(domain = %domain, "challenge validated");

            // Clean up DNS record.
            if let Err(e) = self
                .dns_provider
                .delete_challenge_record(&domain, &validation_value)
                .await
            {
                tracing::warn!(
                    domain = %domain,
                    error = %e,
                    "failed to clean up DNS record (this is non-fatal)"
                );
            }
        }

        // Wait for the order to become ready for finalization.
        let order = order
            .wait_ready(POLL_INTERVAL, POLL_ATTEMPTS)
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Order polling failed: {e}")))?;
        if order.status != OrderStatus::Ready {
            return Err(AcmeError::AcmeRequest(format!(
                "Unexpected order state after challenges: {:?}",
                order.status
            )));
        }

        // Generate the certificate private key and finalize the order. acme2
        // builds the CSR automatically from the order's identifiers.
        tracing::info!("finalizing order");
        let private_key = acme2::gen_rsa_private_key(2048)
            .map_err(|e| AcmeError::Certificate(format!("Key generation failed: {e}")))?;
        let order = order
            .finalize(Csr::Automatic(private_key.clone()))
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Finalization failed: {e}")))?;

        // Poll for certificate issuance.
        let order = order
            .wait_done(POLL_INTERVAL, POLL_ATTEMPTS)
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Certificate issuance failed: {e}")))?;
        if order.status != OrderStatus::Valid {
            return Err(AcmeError::AcmeRequest(format!(
                "Order ended in state {:?}",
                order.status
            )));
        }

        let certificates = order
            .certificate()
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Certificate download failed: {e}")))?
            .ok_or_else(|| {
                AcmeError::AcmeRequest("ACME server did not provide a certificate".to_string())
            })?;

        tracing::info!("certificate issued, saving to disk");

        // Save the full chain and the private key as PEM.
        let mut chain_pem = Vec::new();
        for certificate in &certificates {
            let pem = certificate.to_pem().map_err(|e| {
                AcmeError::Certificate(format!("Certificate PEM encoding failed: {e}"))
            })?;
            chain_pem.extend_from_slice(&pem);
        }
        let key_pem = private_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| AcmeError::Certificate(format!("Key PEM encoding failed: {e}")))?;

        Self::save_certificate(&cert_paths.cert, &chain_pem).await?;
        Self::save_key(&cert_paths.key, &key_pem).await?;

        tracing::info!(
            cert_path = %cert_paths.cert.display(),
            key_path = %cert_paths.key.display(),
            "certificate and key saved"
        );

        Ok(())
    }

    /// Checks if the certificate needs renewal (within 30 days of expiry).
    pub fn needs_renewal(cert_paths: &CertPaths) -> Result<bool, AcmeError> {
        let cert_pem = fs::read_to_string(&cert_paths.cert)?;
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| AcmeError::Certificate(format!("Certificate parse failed: {e}")))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| AcmeError::Certificate(format!("Certificate parse failed: {e}")))?;

        let now = Utc::now().timestamp();
        let expiry = cert.validity().not_after.timestamp();
        let days_until_expiry = (expiry - now) / 86400;

        Ok(days_until_expiry < 30)
    }

    /// Generates a self-signed certificate for development/testing.
    pub async fn self_signed(
        domains: Vec<String>,
        cert_paths: &CertPaths,
    ) -> Result<(), AcmeError> {
        tracing::info!(domains = ?domains, "generating self-signed certificate");

        let certified_key = generate_simple_self_signed(domains)
            .map_err(|e| AcmeError::Certificate(format!("Self-signed generation failed: {e}")))?;

        let cert_pem = certified_key.cert.pem();
        let key_pem = certified_key.signing_key.serialize_pem();

        Self::save_certificate(&cert_paths.cert, cert_pem.as_bytes()).await?;
        Self::save_key(&cert_paths.key, key_pem.as_bytes()).await?;

        tracing::info!(
            cert_path = %cert_paths.cert.display(),
            key_path = %cert_paths.key.display(),
            "self-signed certificate saved"
        );

        Ok(())
    }

    async fn save_certificate(path: &Path, cert_pem: &[u8]) -> Result<(), AcmeError> {
        fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))?;
        fs::write(path, cert_pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    async fn save_key(path: &Path, key_pem: &[u8]) -> Result<(), AcmeError> {
        fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))?;
        fs::write(path, key_pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
