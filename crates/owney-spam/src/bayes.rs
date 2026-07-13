//! Per-account Naive Bayes spam classifier.
//!
//! Trains on emails moved to/from the Junk mailbox role. Implements classic
//! Bayes' theorem with Laplace (add-1) smoothing to avoid zero-probability issues.

use std::collections::HashMap;
use owney_core::AccountId;
use owney_storage::Storage;

/// Classify a message as ham or spam using Naive Bayes.
/// Returns P(spam | tokens) if training data exists, None if not trained yet.
pub async fn classify(storage: &Storage, account_id: AccountId, raw: &[u8]) -> Result<Option<f32>, String> {
    let tokens = tokenize(raw);
    if tokens.is_empty() {
        return Ok(None);
    }

    match storage.get_spam_token_counts(account_id, &tokens).await {
        Ok(counts) => {
            if counts.is_empty() {
                return Ok(None); // No training data yet
            }
            Ok(Some(bayes_probability(&counts, &tokens)))
        }
        Err(_) => Ok(None), // No training data, return neutral
    }
}

/// Tokenize a message into words (split on non-alphanumeric, lowercased, min 3 chars).
pub fn tokenize(raw: &[u8]) -> Vec<String> {
    let msg = String::from_utf8_lossy(raw);
    msg.split(|c: char| !c.is_alphanumeric())
        .map(|w| w.to_lowercase())
        .filter(|w| w.len() >= 3 && w.len() < 100)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

/// Token counts: { token -> (spam_count, ham_count) }
type TokenCounts = HashMap<String, (u32, u32)>;

/// Compute P(spam | tokens) using Naive Bayes with Laplace smoothing.
fn bayes_probability(counts: &TokenCounts, tokens: &[String]) -> f32 {
    const SMOOTHING: f32 = 1.0; // Laplace smoothing
    const PRIOR_SPAM: f32 = 0.5; // Prior P(spam), non-informative

    let mut log_spam_ratio = 0.0f32;

    for token in tokens {
        let (spam_count, ham_count) = counts.get(token).copied().unwrap_or((0, 0));

        // P(token | spam) with Laplace smoothing
        let total_spam = counts.values().map(|(s, _)| s).sum::<u32>() as f32 + SMOOTHING * 2.0;
        let p_token_given_spam = (spam_count as f32 + SMOOTHING) / total_spam;

        // P(token | ham) with Laplace smoothing
        let total_ham = counts.values().map(|(_, h)| h).sum::<u32>() as f32 + SMOOTHING * 2.0;
        let p_token_given_ham = (ham_count as f32 + SMOOTHING) / total_ham;

        // Log-odds to avoid underflow
        if p_token_given_ham > 0.0 {
            log_spam_ratio += (p_token_given_spam / p_token_given_ham).max(1e-10).ln();
        }
    }

    // Convert log-odds back to probability: P(spam | tokens) = 1 / (1 + exp(-log_ratio))
    let probability = 1.0 / (1.0 + (-log_spam_ratio).exp());
    probability.max(0.0).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_splits_on_non_alphanumeric() {
        let msg = b"Hello, world! This is a test.";
        let tokens = tokenize(msg);
        assert!(tokens.contains(&"hello".to_string()));
        assert!(tokens.contains(&"world".to_string()));
        assert!(!tokens.contains(&"".to_string()));
    }

    #[test]
    fn bayes_with_no_data_returns_neutral() {
        let counts: TokenCounts = HashMap::new();
        let tokens = vec!["test".to_string()];
        let prob = bayes_probability(&counts, &tokens);
        assert!((prob - 0.5).abs() < 0.01); // Should be near 0.5 (neutral)
    }

    #[test]
    fn bayes_with_spam_tokens_returns_high_score() {
        let mut counts = HashMap::new();
        counts.insert("viagra".to_string(), (100, 1));
        counts.insert("test".to_string(), (10, 10));
        let tokens = vec!["viagra".to_string()];
        let prob = bayes_probability(&counts, &tokens);
        assert!(prob > 0.7); // Should be high for spam-heavy tokens
    }
}
