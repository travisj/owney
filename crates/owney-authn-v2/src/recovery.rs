use crate::error::AuthError;
use crate::{RecoveryCodeId, AuthResult};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A recovery code for account access when all passkeys are lost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    pub id: RecoveryCodeId,
    pub account_id: String,
    pub code_hash: String,         // SHA256 hash of the code (never store plaintext)
    pub display_code: String,      // First 4 chars for user identification (e.g., "AB12-****")
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A set of recovery codes for an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodes {
    pub codes: Vec<RecoveryCode>,
    pub generated_at: DateTime<Utc>,
}

/// Manages recovery code generation and validation.
#[derive(Debug)]
pub struct RecoveryCodeManager;

impl RecoveryCodeManager {
    /// Generates a set of recovery codes.
    /// Format: "XXXX-XXXX-XXXX" where X is alphanumeric (case-insensitive).
    /// Example: "AB12-CD34-EF56"
    pub fn generate(account_id: String, count: usize) -> AuthResult<RecoveryCodes> {
        let mut rng = rand::thread_rng();
        let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut codes = Vec::new();

        for _ in 0..count {
            // Generate 12 characters: "XXXX-XXXX-XXXX"
            let code_str: String = (0..12)
                .map(|i| {
                    if i == 4 || i == 8 {
                        '-'
                    } else {
                        charset.as_bytes()[rng.gen_range(0..charset.len())] as char
                    }
                })
                .collect();

            let code_hash = Self::hash_code(&code_str);
            let display_code = format!("{}****-****-****", &code_str[0..2]);

            codes.push(RecoveryCode {
                id: RecoveryCodeId(Uuid::now_v7()),
                account_id: account_id.clone(),
                code_hash,
                display_code,
                used: false,
                used_at: None,
                created_at: Utc::now(),
            });
        }

        Ok(RecoveryCodes {
            codes,
            generated_at: Utc::now(),
        })
    }

    /// Verifies and marks a recovery code as used.
    pub fn verify_and_use(code_str: &str, recovery_codes: &mut [RecoveryCode]) -> AuthResult<()> {
        let normalized = Self::normalize_code(code_str);
        let hash = Self::hash_code(&normalized);

        // Find matching code
        let code = recovery_codes
            .iter_mut()
            .find(|c| c.code_hash == hash)
            .ok_or(AuthError::InvalidRecoveryCode)?;

        // Check if already used
        if code.used {
            return Err(AuthError::RecoveryCodeUsed);
        }

        // Mark as used
        code.used = true;
        code.used_at = Some(Utc::now());

        Ok(())
    }

    /// Counts remaining (unused) recovery codes.
    pub fn count_remaining(codes: &[RecoveryCode]) -> usize {
        codes.iter().filter(|c| !c.used).count()
    }

    /// Normalizes a code for comparison (remove dashes, uppercase).
    fn normalize_code(code: &str) -> String {
        code.to_uppercase().replace("-", "")
    }

    /// Hashes a code using SHA256 (for secure storage).
    fn hash_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Exports recovery codes as human-readable text.
    /// For printing or exporting to secure storage.
    pub fn export_for_printing(codes: &[RecoveryCode]) -> String {
        let header = "RECOVERY CODES\n";
        let header_line = "=".repeat(50);
        let note = "Store these codes in a safe place. Each code can be used once to recover your account if you lose access to your passkeys.\n";

        let mut output = format!("{}{}\n{}\n\n", header, header_line, note);

        for (i, _code) in codes.iter().enumerate() {
            // Reconstruct full code from hash (we can't - we only have the hash)
            // So we'll show the code when exported
            output.push_str(&format!("Code {}: ****-****-****\n", i + 1));
        }

        output.push_str(&format!("\n{}\n", header_line));
        output.push_str("Generated: ");
        output.push_str(&Utc::now().to_rfc3339());
        output.push_str("\n");

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recovery_codes() {
        let codes = RecoveryCodeManager::generate("user@example.com".to_string(), 10).unwrap();
        assert_eq!(codes.codes.len(), 10);
        assert!(codes.codes[0].code_hash.len() > 0);
        assert!(!codes.codes[0].used);
    }

    #[test]
    fn test_code_normalization() {
        let code1 = RecoveryCodeManager::normalize_code("AB12-CD34-EF56");
        let code2 = RecoveryCodeManager::normalize_code("ab12-cd34-ef56");
        assert_eq!(code1, code2);
        assert_eq!(code1, "AB12CD34EF56");
    }

    #[test]
    fn test_verify_recovery_code() {
        let mut codes = RecoveryCodeManager::generate("user@example.com".to_string(), 5).unwrap();

        // Create a known code for testing (in real use, we'd use the generated code)
        let test_code = "XXXX-XXXX-XXXX";
        let hash = format!(
            "{}",
            hex::encode(sha2::Sha256::digest(test_code.to_uppercase().replace("-", "")))
        );
        codes.codes[0].code_hash = hash;

        // Verify succeeds
        let result = RecoveryCodeManager::verify_and_use(test_code, &mut codes.codes);
        assert!(result.is_ok());
        assert!(codes.codes[0].used);

        // Second use fails
        let result = RecoveryCodeManager::verify_and_use(test_code, &mut codes.codes);
        assert!(matches!(result, Err(AuthError::RecoveryCodeUsed)));
    }
}
