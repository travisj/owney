use crate::dns::DnsProvider;
use crate::error::AcmeError;
use crate::{AcmeConfig, CertPaths};
use chrono::Utc;
use rcgen::{generate_simple_self_signed_cert, Certificate, CertificateParams, KeyPair};
use std::fs;
use std::path::Path;
use x509_parser::prelude::*;

/// ACME client for Let's Encrypt certificate provisioning.
pub struct AcmeClient {
    config: AcmeConfig,
    dns_provider: Box<dyn DnsProvider>,
}

impl AcmeClient {
    /// Creates a new ACME client.
    pub fn new(config: AcmeConfig, dns_provider: Box<dyn DnsProvider>) -> Self {
        Self { config, dns_provider }
    }

    /// Requests a new certificate from Let's Encrypt.
    /// This handles the full ACME flow: order, challenges, validation, and issuance.
    pub async fn request_certificate(&self, cert_paths: &CertPaths) -> Result<(), AcmeError> {
        tracing::info!(
            domains = ?self.config.domains,
            directory = %self.config.directory_url,
            "requesting certificate from ACME server"
        );

        // Create the ACME client.
        let client = acme2::Client::new(
            self.config.directory_url.parse()
                .map_err(|e| AcmeError::AcmeRequest(format!("Invalid directory URL: {e}")))?,
            acme2::CallbackCache::new(),
        );

        // Account registration with Let's Encrypt.
        let account = client
            .account()
            .contacts(vec![format!("mailto:{}", self.config.email)])
            .agree_to_tos()
            .register()
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Account registration failed: {e}")))?;

        // Order a certificate for all configured domains.
        let mut order = account
            .new_order(&NewOrder::new_from_slice(&self.config.domains))
            .await
            .map_err(|e| AcmeError::AcmeRequest(format!("Order creation failed: {e}")))?;

        let state = order
            .state()
            .clone();
        match state {
            acme2::OrderStatus::Pending { authorizations } => {
                // Process DNS-01 challenges for each domain.
                for auth_url in authorizations {
                    let authorization = order
                        .authorization(&auth_url)
                        .await
                        .map_err(|e| AcmeError::AcmeRequest(format!("Authorization failed: {e}")))?;

                    let domain = authorization
                        .identifier()
                        .value();

                    let challenge = authorization
                        .dns_01()
                        .ok_or_else(|| AcmeError::AcmeRequest("No DNS-01 challenge found".to_string()))?;

                    let validation_value = challenge
                        .validation()
                        .ok_or_else(|| AcmeError::AcmeRequest("No validation value".to_string()))?
                        .to_string();

                    tracing::info!(
                        domain = %domain,
                        "creating DNS challenge record"
                    );

                    // Create DNS record via provider.
                    self.dns_provider
                        .create_challenge_record(domain, &validation_value)
                        .await?;

                    // Wait for DNS propagation.
                    self.dns_provider
                        .wait_for_propagation(domain, &validation_value, 60)
                        .await?;

                    // Tell ACME server to validate the challenge.
                    let proof = challenge
                        .validate()
                        .await
                        .map_err(|e| AcmeError::ChallengeValidation(format!("Challenge validation failed: {e}")))?;

                    tracing::info!(
                        domain = %domain,
                        "challenge validated"
                    );

                    // Clean up DNS record.
                    if let Err(e) = self.dns_provider
                        .delete_challenge_record(domain, &validation_value)
                        .await
                    {
                        tracing::warn!(
                            domain = %domain,
                            error = %e,
                            "failed to clean up DNS record (this is non-fatal)"
                        );
                    }
                }
            }
            _ => {
                return Err(AcmeError::AcmeRequest(format!(
                    "Unexpected order state: {:?}",
                    state
                )));
            }
        }

        // Generate a certificate signing request (CSR).
        tracing::info!("generating certificate signing request");
        let keypair = KeyPair::generate(&rcgen::PKCS_RSA2048)
            .map_err(|e| AcmeError::Certificate(format!("Key generation failed: {e}")))?;
        let mut params = CertificateParams::new(self.config.domains.clone());
        params.key_pair = Some(keypair);
        let cert = Certificate::from_params(params)
            .map_err(|e| AcmeError::Certificate(format!("CSR generation failed: {e}")))?;

        let csr_pem = cert
            .serialize_request_pem()
            .map_err(|e| AcmeError::Certificate(format!("CSR serialization failed: {e}")))?;

        // Request finalization.
        let order_state = order
            .state()
            .clone();
        match order_state {
            acme2::OrderStatus::Ready => {
                tracing::info!("finalizing order");
                let finalize = order
                    .finalize(csr_pem.as_bytes())
                    .await
                    .map_err(|e| AcmeError::AcmeRequest(format!("Finalization failed: {e}")))?;

                // Poll for certificate issuance.
                let certificate = finalize
                    .wait_for_certificate()
                    .await
                    .map_err(|e| AcmeError::AcmeRequest(format!("Certificate issuance failed: {e}")))?;

                tracing::info!("certificate issued, saving to disk");

                // Save certificate and key.
                Self::save_certificate(&cert_paths.cert, &certificate.certificate())
                    .await?;
                Self::save_key(&cert_paths.key, cert.serialize_private_key_pem().as_bytes())
                    .await?;

                tracing::info!(
                    cert_path = %cert_paths.cert.display(),
                    key_path = %cert_paths.key.display(),
                    "certificate and key saved"
                );

                Ok(())
            }
            _ => Err(AcmeError::AcmeRequest(format!(
                "Unexpected order state after challenge: {:?}",
                order_state
            ))),
        }
    }

    /// Checks if the certificate needs renewal (within 30 days of expiry).
    pub fn needs_renewal(cert_paths: &CertPaths) -> Result<bool, AcmeError> {
        let cert_pem = fs::read_to_string(&cert_paths.cert)?;
        let (_, cert) = parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| AcmeError::Certificate(format!("Certificate parse failed: {e}")))?;

        let now = Utc::now().timestamp();
        let expiry = cert
            .tbs_certificate
            .validity()
            .not_after
            .timestamp();
        let days_until_expiry = (expiry - now) / 86400;

        Ok(days_until_expiry < 30)
    }

    /// Generates a self-signed certificate for development/testing.
    pub async fn self_signed(
        domains: Vec<String>,
        cert_paths: &CertPaths,
    ) -> Result<(), AcmeError> {
        tracing::info!(domains = ?domains, "generating self-signed certificate");

        let cert = generate_simple_self_signed_cert(
            domains,
        )
        .map_err(|e| AcmeError::Certificate(format!("Self-signed generation failed: {e}")))?;

        let cert_pem = cert.serialize_pem()
            .map_err(|e| AcmeError::Certificate(format!("Certificate serialization failed: {e}")))?;
        let key_pem = cert.serialize_private_key_pem();

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

use acme2::NewOrder;
