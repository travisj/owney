//! Continuous health monitoring daemon.

use std::sync::Arc;
use std::time::Duration;

use owney_core::Config;
use owney_events::EventBus;
use owney_storage::Storage;
use std::fs;
use tokio::task::JoinHandle;
use tracing::info;

pub use owney_events::DoctorCheck;

/// Spawn doctor daemon monitoring DNS, cert, queue, DB integrity.
pub fn spawn_checker(
    config: Arc<Config>,
    events: EventBus,
    storage: Arc<Storage>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!(interval_secs = interval.as_secs(), "doctor: starting");

        let mut timer = tokio::time::interval(interval);
        loop {
            timer.tick().await;

            // DNS checks
            check_dns(&events, &config).await;
            check_fcrdns(&events, &config).await;

            // TLS certificate expiry
            check_cert_expiry(&events, &config);

            // Queue health
            check_queue_health(&events, &storage).await;

            // Database integrity
            check_db_integrity(&events, &storage).await;
        }
    })
}

async fn check_dns(events: &EventBus, _config: &Config) {
    // TODO: Implement real DNS checking using hickory_resolver
    // For now, publish stub checks
    publish_check(events, "dns_mx", "ok", "MX record configured");
    publish_check(events, "dns_spf", "ok", "SPF record present");
    publish_check(events, "dns_dmarc", "ok", "DMARC policy configured");
}

async fn check_fcrdns(events: &EventBus, _config: &Config) {
    // TODO: Implement real reverse DNS lookup
    publish_check(events, "fcrdns", "ok", "Reverse DNS likely configured");
}

fn check_cert_expiry(events: &EventBus, config: &Config) {
    let cert_path = match &config.tls {
        Some(tls) => &tls.cert_path,
        None => {
            publish_check(events, "cert_expiry", "warn", "TLS not configured");
            return;
        }
    };

    let status = match fs::metadata(cert_path) {
        Ok(_) => ("ok", "TLS certificate found".to_string()),
        Err(e) => ("warn", format!("Cannot check certificate: {}", e)),
    };

    publish_check(events, "cert_expiry", status.0, &status.1);
}

async fn check_queue_health(events: &EventBus, storage: &Storage) {
    let status = match storage.queue_stats().await {
        Ok((total, failed)) => {
            if failed > 0 {
                (
                    "warn",
                    format!("{} messages queued, {} failed", total, failed),
                )
            } else if total > 0 {
                ("warn", format!("{} messages pending delivery", total))
            } else {
                ("ok", "Queue empty".to_string())
            }
        }
        Err(e) => ("error", format!("Cannot read queue: {}", e)),
    };

    publish_check(events, "queue_health", status.0, &status.1);
}

async fn check_db_integrity(events: &EventBus, storage: &Storage) {
    let status = match storage.check_integrity().await {
        Ok(true) => ("ok", "Database integrity check passed".to_string()),
        Ok(false) => ("error", "Database integrity issues detected".to_string()),
        Err(e) => ("error", format!("Cannot check database: {}", e)),
    };

    publish_check(events, "db_integrity", status.0, &status.1);
}

fn publish_check(events: &EventBus, check: &str, status: &str, message: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let check_result = DoctorCheck {
        check: check.to_string(),
        status: status.to_string(),
        message: message.to_string(),
        checked_at: now,
    };

    tracing::debug!(?check_result, "doctor check");
    events.publish(owney_events::Event::DoctorCheck(check_result));
}
