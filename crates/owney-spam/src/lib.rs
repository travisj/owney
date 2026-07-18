//! In-process spam filtering: DNSBL checks, heuristic rules, and per-account Bayes classifier.
//!
//! This module provides a pluggable SpamScanner trait for integration into the SMTP delivery
//! pipeline. The default HeuristicScanner combines three techniques:
//! - DNSBL (configurable blocklist zones, e.g., zen.spamhaus.org)
//! - Heuristic rules (missing Date/Message-ID, ALL-CAPS subjects, etc.)
//! - Per-account Naive Bayes classifier (trained by moving emails to/from Junk mailbox)

pub mod bayes;
pub mod dnsbl;
pub mod rules;

use owney_core::AccountId;
use owney_storage::Storage;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A spam scanning verdict for one message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamVerdict {
    /// Spam score (0.0 = definitely ham, 1.0 = definitely spam).
    pub score: f32,
    /// Rules that matched and contributed to the score.
    pub matched_rules: Vec<String>,
    /// DNSBL zones that had hits.
    pub dnsbl_hits: Vec<String>,
    /// Bayes classifier probability (if training data exists for this account).
    pub bayes_prob: Option<f32>,
}

impl Default for SpamVerdict {
    fn default() -> Self {
        Self {
            score: 0.0,
            matched_rules: Vec::new(),
            dnsbl_hits: Vec::new(),
            bayes_prob: None,
        }
    }
}

/// Input to the spam scanner.
#[derive(Debug)]
pub struct SpamInput<'a> {
    /// Remote IP address (for DNSBL checks).
    pub remote_ip: IpAddr,
    /// Raw RFC 5322 message.
    pub raw: &'a [u8],
    /// Owner account ID (for per-account Bayes).
    pub account_id: AccountId,
}

/// Pluggable spam scanner trait.
/// Implementations must be fail-open: never return an Err; return SpamVerdict::default() on timeouts/errors.
#[async_trait::async_trait]
pub trait SpamScanner: Send + Sync {
    /// Scan a message and return a verdict. Never errors — fail-open on timeouts or resource errors.
    async fn scan(&self, storage: &Storage, input: SpamInput<'_>) -> SpamVerdict;
}

/// Heuristic spam scanner combining DNSBL, rules, and Bayes.
#[derive(Debug)]
pub struct HeuristicScanner {
    /// DNSBL zones to check (e.g., ["zen.spamhaus.org"]).
    pub zones: Vec<String>,
}

#[async_trait::async_trait]
impl SpamScanner for HeuristicScanner {
    async fn scan(&self, storage: &Storage, input: SpamInput<'_>) -> SpamVerdict {
        let mut verdict = SpamVerdict::default();

        // DNSBL check
        if let Ok(hits) = dnsbl::check_ip(&self.zones, input.remote_ip).await {
            verdict.dnsbl_hits = hits.clone();
            if !hits.is_empty() {
                verdict.score += 0.3; // 30% for DNSBL hit
                verdict
                    .matched_rules
                    .push(format!("DNSBL hit: {}", hits.join(", ")));
            }
        }

        // Heuristic rules check
        let rule_verdict = rules::check_message(input.raw);
        verdict.score += rule_verdict.score * 0.5; // Weight heuristics at 50%
        verdict.matched_rules.extend(rule_verdict.matched_rules);

        // Bayes classifier (if training data exists)
        if let Ok(Some(bayes_prob)) = bayes::classify(storage, input.account_id, input.raw).await {
            verdict.bayes_prob = Some(bayes_prob);
            verdict.score = (verdict.score * 0.3) + (bayes_prob * 0.7); // 70% weight for Bayes
            if bayes_prob > 0.8 {
                verdict
                    .matched_rules
                    .push(format!("Bayes: {:.1}% spam", bayes_prob * 100.0));
            }
        }

        // Clamp score to [0, 1]
        verdict.score = verdict.score.clamp(0.0, 1.0);
        verdict
    }
}

impl HeuristicScanner {
    pub fn new(zones: Vec<String>) -> Self {
        Self { zones }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spam_verdict_default_is_clean() {
        let v = SpamVerdict::default();
        assert_eq!(v.score, 0.0);
        assert!(v.matched_rules.is_empty());
    }
}
