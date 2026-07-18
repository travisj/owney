use crate::dns::{ChallengeRecord, DnsProvider};
use crate::error::AcmeError;
use std::time::Duration;

/// Cloudflare DNS provider for DNS-01 challenges.
pub struct CloudflareProvider {
    api_token: String,
    zone_id: String,
}

impl std::fmt::Debug for CloudflareProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareProvider")
            .field("zone_id", &self.zone_id)
            .finish_non_exhaustive()
    }
}

impl CloudflareProvider {
    /// Creates a new Cloudflare provider.
    /// api_token: Your Cloudflare API token (global or zone-scoped).
    /// zone_id: The zone ID for your domain (from Cloudflare dashboard).
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self { api_token, zone_id }
    }

    fn challenge_fqdn(&self, domain: &str) -> String {
        ChallengeRecord::fqdn(domain)
    }
}

#[async_trait::async_trait]
impl DnsProvider for CloudflareProvider {
    async fn create_challenge_record(
        &self,
        domain: &str,
        challenge_value: &str,
    ) -> Result<(), AcmeError> {
        let fqdn = self.challenge_fqdn(domain);

        let client = reqwest::Client::new();
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let body = serde_json::json!({
            "type": "TXT",
            "name": fqdn,
            "content": challenge_value,
            "ttl": 120,
        });

        let response = client
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AcmeError::DnsProvider(format!("Cloudflare request failed: {e}")))?;

        let result: serde_json::Value = response.json().await.map_err(|e| {
            AcmeError::DnsProvider(format!("Failed to parse Cloudflare response: {e}"))
        })?;

        if !result["success"].as_bool().unwrap_or(false) {
            let errors = result["errors"]
                .as_array()
                .map(|e| format!("{:?}", e))
                .unwrap_or_default();
            return Err(AcmeError::DnsProvider(format!(
                "Cloudflare error: {:?}",
                errors
            )));
        }

        tracing::info!(domain = %domain, fqdn = %fqdn, "created DNS challenge record");
        Ok(())
    }

    async fn delete_challenge_record(
        &self,
        domain: &str,
        _challenge_value: &str,
    ) -> Result<(), AcmeError> {
        let fqdn = self.challenge_fqdn(domain);

        let client = reqwest::Client::new();
        let list_url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            self.zone_id, fqdn
        );

        let response = client
            .get(&list_url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| AcmeError::DnsProvider(format!("Cloudflare request failed: {e}")))?;

        let result: serde_json::Value = response.json().await.map_err(|e| {
            AcmeError::DnsProvider(format!("Failed to parse Cloudflare response: {e}"))
        })?;

        let records = result["result"]
            .as_array()
            .ok_or_else(|| AcmeError::DnsProvider("No records found".to_string()))?;

        for record in records {
            if let Some(record_id) = record["id"].as_str() {
                let delete_url = format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    self.zone_id, record_id
                );

                client
                    .delete(&delete_url)
                    .bearer_auth(&self.api_token)
                    .send()
                    .await
                    .map_err(|e| {
                        AcmeError::DnsProvider(format!("Cloudflare delete failed: {e}"))
                    })?;
            }
        }

        tracing::info!(domain = %domain, fqdn = %fqdn, "deleted DNS challenge record");
        Ok(())
    }

    async fn wait_for_propagation(
        &self,
        domain: &str,
        challenge_value: &str,
        timeout_secs: u64,
    ) -> Result<(), AcmeError> {
        let fqdn = self.challenge_fqdn(domain);
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            if std::time::Instant::now() >= deadline {
                return Err(AcmeError::DnsTimeout);
            }

            let client = reqwest::Client::new();
            let query_url = format!(
                "https://dns.google/resolve?name={}&type=TXT",
                urlencoding::encode(&fqdn)
            );

            if let Ok(response) = client.get(&query_url).send().await
                && let Ok(data) = response.json::<serde_json::Value>().await
                && let Some(answers) = data["Answer"].as_array()
            {
                for answer in answers {
                    if let Some(data_field) = answer["data"].as_str() {
                        let trimmed = data_field.trim_matches('"');
                        if trimmed == challenge_value {
                            tracing::info!(
                                domain = %domain,
                                fqdn = %fqdn,
                                "DNS propagation confirmed"
                            );
                            return Ok(());
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

/// AWS Route53 DNS provider for DNS-01 challenges.
#[derive(Debug)]
pub struct Route53Provider {
    zone_id: String,
    client: aws_sdk_route53::Client,
}

impl Route53Provider {
    /// Creates a new Route53 provider.
    /// zone_id: The Route53 hosted zone ID for your domain.
    /// Credentials are loaded from AWS SDK (env vars, instance metadata, etc).
    pub async fn new(zone_id: String) -> Result<Self, AcmeError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_route53::Client::new(&config);

        Ok(Self { zone_id, client })
    }

    fn challenge_fqdn(&self, domain: &str) -> String {
        ChallengeRecord::fqdn(domain)
    }
}

#[async_trait::async_trait]
impl DnsProvider for Route53Provider {
    async fn create_challenge_record(
        &self,
        domain: &str,
        challenge_value: &str,
    ) -> Result<(), AcmeError> {
        let fqdn = self.challenge_fqdn(domain);
        let fqdn_with_dot = format!("{}.", fqdn);

        let resource_record = aws_sdk_route53::types::ResourceRecord::builder()
            .value(format!("\"{}\"", challenge_value))
            .build()
            .map_err(|e| AcmeError::DnsProvider(format!("Failed to build Route53 record: {e}")))?;

        let record_set = aws_sdk_route53::types::ResourceRecordSet::builder()
            .name(&fqdn_with_dot)
            .r#type(aws_sdk_route53::types::RrType::Txt)
            .ttl(120)
            .resource_records(resource_record)
            .build()
            .map_err(|e| {
                AcmeError::DnsProvider(format!("Failed to build Route53 record set: {e}"))
            })?;

        let change = aws_sdk_route53::types::Change::builder()
            .action(aws_sdk_route53::types::ChangeAction::Create)
            .resource_record_set(record_set)
            .build()
            .map_err(|e| AcmeError::DnsProvider(format!("Failed to build Route53 change: {e}")))?;

        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.zone_id)
            .change_batch(
                aws_sdk_route53::types::ChangeBatch::builder()
                    .changes(change)
                    .build()
                    .map_err(|e| {
                        AcmeError::DnsProvider(format!("Failed to build Route53 batch: {e}"))
                    })?,
            )
            .send()
            .await
            .map_err(|e| AcmeError::DnsProvider(format!("Route53 request failed: {e}")))?;

        tracing::info!(domain = %domain, fqdn = %fqdn, "created DNS challenge record via Route53");
        Ok(())
    }

    async fn delete_challenge_record(
        &self,
        domain: &str,
        challenge_value: &str,
    ) -> Result<(), AcmeError> {
        let fqdn = self.challenge_fqdn(domain);
        let fqdn_with_dot = format!("{}.", fqdn);

        let resource_record = aws_sdk_route53::types::ResourceRecord::builder()
            .value(format!("\"{}\"", challenge_value))
            .build()
            .map_err(|e| AcmeError::DnsProvider(format!("Failed to build Route53 record: {e}")))?;

        let record_set = aws_sdk_route53::types::ResourceRecordSet::builder()
            .name(&fqdn_with_dot)
            .r#type(aws_sdk_route53::types::RrType::Txt)
            .ttl(120)
            .resource_records(resource_record)
            .build()
            .map_err(|e| {
                AcmeError::DnsProvider(format!("Failed to build Route53 record set: {e}"))
            })?;

        let change = aws_sdk_route53::types::Change::builder()
            .action(aws_sdk_route53::types::ChangeAction::Delete)
            .resource_record_set(record_set)
            .build()
            .map_err(|e| AcmeError::DnsProvider(format!("Failed to build Route53 change: {e}")))?;

        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.zone_id)
            .change_batch(
                aws_sdk_route53::types::ChangeBatch::builder()
                    .changes(change)
                    .build()
                    .map_err(|e| {
                        AcmeError::DnsProvider(format!("Failed to build Route53 batch: {e}"))
                    })?,
            )
            .send()
            .await
            .map_err(|e| AcmeError::DnsProvider(format!("Route53 request failed: {e}")))?;

        tracing::info!(domain = %domain, fqdn = %fqdn, "deleted DNS challenge record via Route53");
        Ok(())
    }

    async fn wait_for_propagation(
        &self,
        domain: &str,
        challenge_value: &str,
        timeout_secs: u64,
    ) -> Result<(), AcmeError> {
        let fqdn = self.challenge_fqdn(domain);
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            if std::time::Instant::now() >= deadline {
                return Err(AcmeError::DnsTimeout);
            }

            let client = reqwest::Client::new();
            let query_url = format!(
                "https://dns.google/resolve?name={}&type=TXT",
                urlencoding::encode(&fqdn)
            );

            if let Ok(response) = client.get(&query_url).send().await
                && let Ok(data) = response.json::<serde_json::Value>().await
                && let Some(answers) = data["Answer"].as_array()
            {
                for answer in answers {
                    if let Some(data_field) = answer["data"].as_str() {
                        let trimmed = data_field.trim_matches('"');
                        if trimmed == challenge_value {
                            tracing::info!(
                                domain = %domain,
                                fqdn = %fqdn,
                                "DNS propagation confirmed via Route53"
                            );
                            return Ok(());
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
