//! Glue between the protocol crates and storage: the server's mail policy.

use std::sync::Arc;

use owney_authn::{AuthInput, Authenticator};
use owney_events::EventBus;
use owney_smtp_in::{DeliverError, InboundMail, MailHandler, RcptVerdict};
use owney_storage::Storage;
use owney_spam::{SpamInput, SpamScanner};

pub struct ServerCore {
    pub storage: Arc<Storage>,
    pub authenticator: Arc<Authenticator>,
    pub spam_scanner: Box<dyn SpamScanner>,
    pub events: EventBus,
    /// The domain we accept mail for.
    pub domain: String,
    /// Our hostname (authserv-id in Authentication-Results).
    pub hostname: String,
    /// Spam filtering config
    pub spam_config: owney_core::config::SpamConfig,
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
        match self.storage.resolve_recipient(&address).await {
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

        // Spam filtering: check message before routing to recipients
        let spam_verdict = if self.spam_config.enabled {
            self.spam_scanner.scan(&self.storage, SpamInput {
                remote_ip: mail.remote,
                raw: &mail.raw,
                account_id: owney_core::AccountId::new(), // Temp default; will use actual account per-recipient
            }).await
        } else {
            owney_spam::SpamVerdict::default()
        };

        // Check for permanent spam rejection
        if spam_verdict.score >= self.spam_config.reject_threshold {
            tracing::warn!(score = spam_verdict.score, rules = ?spam_verdict.matched_rules, "message rejected by spam filter");
            return Err(DeliverError::Permanent(format!("message rejected: spam score {:.2}", spam_verdict.score)));
        }

        let spam_verdict_json = serde_json::to_string(&spam_verdict).ok();

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
                .resolve_recipient(recipient)
                .await
                .map_err(|err| DeliverError::Temporary(err.to_string()))?
                .ok_or_else(|| DeliverError::Temporary(format!("{recipient} vanished after RCPT")))?;

            // Harvest Autocrypt keys; transparently decrypt encrypted-to-us.
            let pgp = owney_pgp::pipeline::inbound(&self.storage, account.id, raw.clone())
                .await
                .map_err(|err| DeliverError::Temporary(format!("pgp: {err}")))?;
            for address in &pgp.key_changes {
                self.events.publish(owney_events::Event::Security {
                    account_id: Some(account.id),
                    kind: owney_events::SecurityEventKind::Other,
                    detail: format!("PGP key changed for {address}"),
                });
                tracing::warn!(%address, account = %account.email, "peer PGP key changed");
            }

            // Route to Junk if spam quarantine threshold exceeded, otherwise inbox
            let mailbox = if spam_verdict.score >= self.spam_config.quarantine_threshold {
                "junk"
            } else {
                "inbox"
            };

            // Determine chat mode based on recipient's preferences
            let recipient_chat_pref = self
                .storage
                .get_chat_preference(account.id, &mail.mail_from)
                .await
                .unwrap_or(owney_storage::ChatMode::RespectSender);
            let chat_mode = match recipient_chat_pref {
                owney_storage::ChatMode::AutoChat => true,
                owney_storage::ChatMode::NeverChat => false,
                owney_storage::ChatMode::RespectSender => {
                    // For now, always false (sender can't mark as chat in SMTP).
                    // Will be true when JMAP submission includes chatMode flag.
                    false
                }
            };

            let ingested = self
                .storage
                .ingest_email_with_chat(account.id, pgp.raw, mailbox, verdict_json.clone(), chat_mode)
                .await
                .map_err(|err| DeliverError::Temporary(err.to_string()))?;

            // Store spam verdict
            if let Some(spam_json) = &spam_verdict_json {
                let _ = self.storage.set_spam_verdict(&ingested.id.to_string(), spam_json).await;
            }

            if let Some(status) = &pgp.pgp_status {
                self.storage
                    .set_pgp_status(ingested.id, status)
                    .await
                    .map_err(|err| DeliverError::Temporary(err.to_string()))?;
            }

            tracing::info!(
                email_id = %ingested.id,
                account = %account.email,
                from = %mail.mail_from,
                encrypted = pgp.pgp_status.is_some(),
                auth = %verdict.summary(),
                spam_score = spam_verdict.score,
                mailbox = mailbox,
                chat_mode = chat_mode,
                "message delivered"
            );
        }
        Ok(())
    }
}
