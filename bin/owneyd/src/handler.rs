//! Glue between the protocol crates and storage: the server's mail policy.

use std::sync::Arc;

use owney_authn::{AuthInput, Authenticator};
use owney_events::EventBus;
use owney_smtp_in::{DeliverError, InboundMail, MailHandler, RcptVerdict};
use owney_storage::Storage;

pub struct ServerCore {
    pub storage: Arc<Storage>,
    pub authenticator: Arc<Authenticator>,
    pub events: EventBus,
    /// The domain we accept mail for.
    pub domain: String,
    /// Our hostname (authserv-id in Authentication-Results).
    pub hostname: String,
}

impl MailHandler for ServerCore {
    async fn rcpt(&self, address: &str) -> RcptVerdict {
        let address = address.trim().to_lowercase();
        let Some((_, domain)) = address.rsplit_once('@') else {
            return RcptVerdict::UnknownUser;
        };
        if domain != self.domain {
            return RcptVerdict::NotLocal;
        }
        match self.storage.account_by_email(&address).await {
            Ok(Some(_)) => RcptVerdict::Accept,
            Ok(None) => RcptVerdict::UnknownUser,
            Err(err) => {
                tracing::error!(%err, %address, "recipient lookup failed");
                RcptVerdict::TryAgainLater
            }
        }
    }

    async fn deliver(&self, mail: InboundMail) -> Result<(), DeliverError> {
        // Verify SPF/DKIM/DMARC/ARC/FCrDNS. Verdicts are evidence, not policy:
        // in M1 nothing is rejected on them (screening arrives in M5).
        let verdict = self
            .authenticator
            .verify(AuthInput {
                remote_ip: mail.remote,
                helo: &mail.helo,
                mail_from: &mail.mail_from,
                raw: &mail.raw,
            })
            .await;
        let verdict_json = serde_json::to_string(&verdict).ok();

        // Record our verdict in the message itself (RFC 8601).
        let mut raw = format!(
            "Authentication-Results: {}\r\n",
            verdict.authentication_results(&self.hostname)
        )
        .into_bytes();
        raw.extend_from_slice(&mail.raw);

        for recipient in &mail.recipients {
            let account = self
                .storage
                .account_by_email(recipient)
                .await
                .map_err(|err| DeliverError(err.to_string()))?
                .ok_or_else(|| DeliverError(format!("{recipient} vanished after RCPT")))?;

            // Harvest Autocrypt keys; transparently decrypt encrypted-to-us.
            let pgp = owney_pgp::pipeline::inbound(&self.storage, account.id, raw.clone())
                .await
                .map_err(|err| DeliverError(format!("pgp: {err}")))?;
            for address in &pgp.key_changes {
                self.events.publish(owney_events::Event::Security {
                    account_id: Some(account.id),
                    kind: owney_events::SecurityEventKind::Other,
                    detail: format!("PGP key changed for {address}"),
                });
                tracing::warn!(%address, account = %account.email, "peer PGP key changed");
            }

            let ingested = self
                .storage
                .ingest_email(account.id, pgp.raw, "inbox", verdict_json.clone())
                .await
                .map_err(|err| DeliverError(err.to_string()))?;
            if let Some(status) = &pgp.pgp_status {
                self.storage
                    .set_pgp_status(ingested.id, status)
                    .await
                    .map_err(|err| DeliverError(err.to_string()))?;
            }

            tracing::info!(
                email_id = %ingested.id,
                account = %account.email,
                from = %mail.mail_from,
                encrypted = pgp.pgp_status.is_some(),
                auth = %verdict.summary(),
                "message delivered"
            );
        }
        Ok(())
    }
}
