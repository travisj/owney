//! Temporary storage for WebAuthn challenges and pairing codes with TTL support.
//!
//! Uses in-memory HashMap with expiration tracking. This is simple and suitable
//! for single-server deployments. For multi-server setups, swap out for Redis.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A challenge or pairing code with expiration.
#[derive(Debug, Clone)]
struct ChallengeEntry {
    data: Vec<u8>,
    expires_at: DateTime<Utc>,
}

/// In-memory challenge store with TTL expiration.
#[derive(Debug, Clone)]
pub struct ChallengeStore {
    entries: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
}

impl ChallengeStore {
    /// Create a new challenge store.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store opaque data under a fresh random id with an explicit TTL, returning
    /// the id. Used by the OIDC flows to park WebAuthn ceremony state and
    /// authorization codes for exactly as long as each step allows.
    pub async fn store_with_ttl(&self, data: Vec<u8>, ttl: std::time::Duration) -> String {
        let session_id = Uuid::now_v7().to_string();
        let ttl = Duration::from_std(ttl).unwrap_or_else(|_| Duration::minutes(10));
        let expires_at = Utc::now() + ttl;
        self.entries
            .write()
            .await
            .insert(session_id.clone(), ChallengeEntry { data, expires_at });
        session_id
    }

    /// Store opaque data under a caller-chosen key with an explicit TTL. Used
    /// for OIDC authorization codes, where the key *is* the secret handed to the
    /// client and looked up again at the token endpoint.
    pub async fn store_keyed(&self, key: String, data: Vec<u8>, ttl: std::time::Duration) {
        let ttl = Duration::from_std(ttl).unwrap_or_else(|_| Duration::minutes(10));
        let expires_at = Utc::now() + ttl;
        self.entries
            .write()
            .await
            .insert(key, ChallengeEntry { data, expires_at });
    }

    /// Store a challenge with a 10-minute TTL.
    pub async fn store_challenge(&self, challenge: Vec<u8>) -> Result<String, String> {
        let session_id = Uuid::now_v7().to_string();
        let expires_at = Utc::now() + Duration::minutes(10);

        self.entries.write().await.insert(
            session_id.clone(),
            ChallengeEntry {
                data: challenge,
                expires_at,
            },
        );

        Ok(session_id)
    }

    /// Non-consuming read of a stored entry, returning `None` if it is missing
    /// or expired (expired entries are evicted). Used for multi-step OIDC flows
    /// where the parked authorization request must survive several requests
    /// before it is finally consumed at code-mint time.
    pub async fn peek(&self, id: &str) -> Option<Vec<u8>> {
        let mut entries = self.entries.write().await;
        match entries.get(id) {
            Some(entry) if Utc::now() <= entry.expires_at => Some(entry.data.clone()),
            Some(_) => {
                entries.remove(id);
                None
            }
            None => None,
        }
    }

    /// Retrieve and consume a challenge.
    pub async fn retrieve_challenge(&self, session_id: &str) -> Result<Vec<u8>, String> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.remove(session_id) {
            // Check expiration
            if Utc::now() > entry.expires_at {
                return Err("Challenge expired".to_string());
            }
            Ok(entry.data)
        } else {
            Err("Challenge not found".to_string())
        }
    }

    /// Store a pairing code with a 2-minute TTL.
    pub async fn store_pairing_code(&self, code: String) -> Result<String, String> {
        let code_id = Uuid::now_v7().to_string();
        let expires_at = Utc::now() + Duration::minutes(2);

        self.entries.write().await.insert(
            code_id.clone(),
            ChallengeEntry {
                data: code.into_bytes(),
                expires_at,
            },
        );

        Ok(code_id)
    }

    /// Retrieve and consume a pairing code.
    pub async fn retrieve_pairing_code(&self, code_id: &str) -> Result<String, String> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.remove(code_id) {
            // Check expiration
            if Utc::now() > entry.expires_at {
                return Err("Pairing code expired".to_string());
            }
            String::from_utf8(entry.data).map_err(|_| "Invalid pairing code".to_string())
        } else {
            Err("Pairing code not found".to_string())
        }
    }

    /// Clean up expired entries (can be called periodically).
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        self.entries
            .write()
            .await
            .retain(|_, entry| entry.expires_at > now);
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Session token manager.
#[derive(Debug, Clone)]
pub struct SessionTokenManager {
    tokens: Arc<RwLock<HashMap<String, SessionTokenEntry>>>,
}

#[derive(Debug, Clone)]
struct SessionTokenEntry {
    account_id: String,
    expires_at: DateTime<Utc>,
}

impl SessionTokenManager {
    /// Create a new session token manager.
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new session token with 24-hour TTL.
    pub async fn generate_token(&self, account_id: String) -> Result<String, String> {
        use rand::Rng;
        use sha2::{Digest, Sha256};

        // Scope the ThreadRng so it is not held across the await below
        // (ThreadRng is !Send and would make the future !Send).
        let random_bytes: [u8; 32] = {
            let mut rng = rand::thread_rng();
            rng.r#gen()
        };

        let mut hasher = Sha256::new();
        hasher.update(&random_bytes);
        hasher.update(account_id.as_bytes());
        hasher.update(Utc::now().timestamp().to_string());

        let token = format!("owk_{}", hex::encode(hasher.finalize()));
        let expires_at = Utc::now() + Duration::hours(24);

        self.tokens.write().await.insert(
            token.clone(),
            SessionTokenEntry {
                account_id,
                expires_at,
            },
        );

        Ok(token)
    }

    /// Validate a session token and return the account_id if valid.
    pub async fn validate_token(&self, token: &str) -> Result<String, String> {
        let entries = self.tokens.read().await;

        if let Some(entry) = entries.get(token) {
            if Utc::now() > entry.expires_at {
                drop(entries);
                self.tokens.write().await.remove(token);
                Err("Token expired".to_string())
            } else {
                Ok(entry.account_id.clone())
            }
        } else {
            Err("Invalid token".to_string())
        }
    }

    /// Revoke a session token.
    pub async fn revoke_token(&self, token: &str) -> Result<(), String> {
        self.tokens
            .write()
            .await
            .remove(token)
            .ok_or_else(|| "Token not found".to_string())?;
        Ok(())
    }

    /// Clean up expired tokens (can be called periodically).
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        self.tokens
            .write()
            .await
            .retain(|_, entry| entry.expires_at > now);
    }
}

impl Default for SessionTokenManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_store() {
        let store = ChallengeStore::new();

        // Store a challenge
        let challenge = b"challenge-data".to_vec();
        let session_id = store
            .store_challenge(challenge.clone())
            .await
            .expect("store");

        // Retrieve it
        let retrieved = store
            .retrieve_challenge(&session_id)
            .await
            .expect("retrieve");
        assert_eq!(retrieved, challenge);

        // Can't retrieve again (consumed)
        let result = store.retrieve_challenge(&session_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pairing_code() {
        let store = ChallengeStore::new();

        // Store a pairing code
        let code = "ABC123DEF456".to_string();
        let code_id = store.store_pairing_code(code.clone()).await.expect("store");

        // Retrieve it
        let retrieved = store
            .retrieve_pairing_code(&code_id)
            .await
            .expect("retrieve");
        assert_eq!(retrieved, code);

        // Can't retrieve again (consumed)
        let result = store.retrieve_pairing_code(&code_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_token_manager() {
        let manager = SessionTokenManager::new();

        // Generate a token
        let token = manager
            .generate_token("account-123".to_string())
            .await
            .expect("generate");
        assert!(token.starts_with("owk_"));

        // Validate it
        let account_id = manager.validate_token(&token).await.expect("validate");
        assert_eq!(account_id, "account-123");

        // Revoke it
        manager.revoke_token(&token).await.expect("revoke");

        // Can't validate anymore
        let result = manager.validate_token(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let manager = SessionTokenManager::new();

        let result = manager.validate_token("invalid-token").await;
        assert!(result.is_err());
    }
}
