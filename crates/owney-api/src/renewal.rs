use owney_acme::{AcmeClient, AcmeConfig, CertPaths, CloudflareProvider, Route53Provider};
use owney_core::Config;
use std::time::Duration;

/// Spawns a certificate renewal worker that checks daily and renews if needed.
pub fn spawn_renewal_worker(config: Config) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let acme_config = match &config.acme {
            Some(acme) if acme.enabled => acme,
            _ => {
                tracing::debug!("ACME not configured, skipping renewal worker");
                return;
            }
        };

        let cert_paths = CertPaths::in_dir(&config.storage.data_dir);

        loop {
            // Check every 24 hours
            tokio::time::sleep(Duration::from_secs(86400)).await;

            match check_and_renew(&config, acme_config, &cert_paths).await {
                Ok(renewed) => {
                    if renewed {
                        tracing::info!("certificate renewed successfully");
                    } else {
                        tracing::debug!("certificate does not need renewal yet");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "certificate renewal check failed");
                    // Continue to try again tomorrow
                }
            }
        }
    })
}

async fn check_and_renew(
    config: &Config,
    acme_config: &owney_core::config::AcmeConfigSection,
    cert_paths: &CertPaths,
) -> anyhow::Result<bool> {
    // Check if certificate needs renewal
    if !AcmeClient::needs_renewal(cert_paths)? {
        return Ok(false);
    }

    tracing::info!("certificate expiring soon, requesting renewal");

    // Build DNS provider
    let dns_provider: Box<dyn owney_acme::DnsProvider> = if acme_config.dns_provider == "cloudflare"
    {
        let api_token = acme_config
            .cloudflare_api_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("cloudflare_api_token not configured"))?
            .clone();
        let zone_id = acme_config
            .cloudflare_zone_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("cloudflare_zone_id not configured"))?
            .clone();
        Box::new(CloudflareProvider::new(api_token, zone_id))
    } else if acme_config.dns_provider == "route53" {
        let zone_id = acme_config
            .route53_zone_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("route53_zone_id not configured"))?
            .clone();
        Box::new(Route53Provider::new(zone_id).await?)
    } else {
        anyhow::bail!("unknown DNS provider: {}", acme_config.dns_provider);
    };

    // Build ACME config
    let mut domains = vec![config.server.hostname.clone()];

    let acme_cfg = if acme_config.staging {
        AcmeConfig::staging_new(domains, acme_config.email.clone(), acme_config.dns_provider.clone())
    } else {
        AcmeConfig::new(domains, acme_config.email.clone(), acme_config.dns_provider.clone())
    };

    // Request new certificate
    let client = AcmeClient::new(acme_cfg, dns_provider);
    client.request_certificate(cert_paths).await?;

    Ok(true)
}
