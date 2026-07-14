use crate::error::AuthError;
use crate::{AuthResult, RecoveryCodeId};
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
    pub code_hash: String,    // SHA256 hash of the code (never store plaintext)
    pub display_code: String, // First 4 chars for user identification (e.g., "AB12-****")
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
    ///
    /// Returns the storable [`RecoveryCodes`] (which hold only SHA-256 hashes)
    /// together with the plaintext codes formatted as `"XXXX-XXXX-XXXX"`. The
    /// plaintext is returned SEPARATELY and is never stored — the caller must
    /// present it to the user exactly once and then drop it. Persist only the
    /// [`RecoveryCodes`].
    pub fn generate(account_id: String, count: usize) -> AuthResult<(RecoveryCodes, Vec<String>)> {
        let mut rng = rand::thread_rng();
        let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut codes = Vec::new();
        let mut plaintext = Vec::new();

        for _ in 0..count {
            // 12 random alphanumeric characters, presented as "XXXX-XXXX-XXXX".
            let raw: String = (0..12)
                .map(|_| charset.as_bytes()[rng.gen_range(0..charset.len())] as char)
                .collect();
            let code_str = format!("{}-{}-{}", &raw[0..4], &raw[4..8], &raw[8..12]);

            // Hash the NORMALIZED form (dashes stripped, upper-cased) so that a
            // code typed back by the user — which verify_and_use normalizes
            // before hashing — matches. Hashing the dashed form here would make
            // every generated code impossible to redeem.
            let code_hash = Self::hash_code(&Self::normalize_code(&code_str));
            let display_code = format!("{}****-****-****", &raw[0..2]);

            codes.push(RecoveryCode {
                id: RecoveryCodeId(Uuid::now_v7()),
                account_id: account_id.clone(),
                code_hash,
                display_code,
                used: false,
                used_at: None,
                created_at: Utc::now(),
            });
            plaintext.push(code_str);
        }

        Ok((
            RecoveryCodes {
                codes,
                generated_at: Utc::now(),
            },
            plaintext,
        ))
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

    /// Renders the plaintext codes (as returned by [`generate`]) as
    /// human-readable text for the user to print or save. This must be called
    /// with the plaintext, not with [`RecoveryCode`] records — those only hold
    /// hashes and cannot reconstruct the codes.
    ///
    /// [`generate`]: RecoveryCodeManager::generate
    pub fn export_for_printing(plaintext_codes: &[String]) -> String {
        let header_line = "=".repeat(50);
        let mut output = format!(
            "RECOVERY CODES\n{header_line}\nStore these codes in a safe place. Each \
             code can be used once to recover your account if you lose access to \
             your passkeys.\n\n"
        );

        for (i, code) in plaintext_codes.iter().enumerate() {
            output.push_str(&format!("Code {}: {code}\n", i + 1));
        }

        output.push_str(&format!("\n{header_line}\n"));
        output.push_str("Generated: ");
        output.push_str(&Utc::now().to_rfc3339());
        output.push('\n');

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recovery_codes() {
        let (codes, plaintext) =
            RecoveryCodeManager::generate("user@example.com".to_string(), 10).unwrap();
        assert_eq!(codes.codes.len(), 10);
        assert_eq!(plaintext.len(), 10);
        assert!(!codes.codes[0].code_hash.is_empty());
        assert!(!codes.codes[0].used);
    }

    #[test]
    fn test_code_normalization() {
        let code1 = RecoveryCodeManager::normalize_code("AB12-CD34-EF56");
        let code2 = RecoveryCodeManager::normalize_code("ab12-cd34-ef56");
        assert_eq!(code1, code2);
        assert_eq!(code1, "AB12CD34EF56");
    }

    /// Regression test for the hash/normalize mismatch: a code exactly as
    /// returned by generate() MUST verify. Before the fix, generate() hashed
    /// the dashed string while verify_and_use() hashed the dash-stripped form,
    /// so no genuinely generated code could ever be redeemed (permanent
    /// account lockout).
    #[test]
    fn test_generated_code_round_trips() {
        let (mut codes, plaintext) =
            RecoveryCodeManager::generate("user@example.com".to_string(), 5).unwrap();

        // A freshly generated code verifies as printed...
        assert!(RecoveryCodeManager::verify_and_use(&plaintext[0], &mut codes.codes).is_ok());
        // ...and also with lower-case / stripped formatting the user might type.
        let messy = plaintext[1].to_lowercase().replace('-', "");
        assert!(RecoveryCodeManager::verify_and_use(&messy, &mut codes.codes).is_ok());
    }

    #[test]
    fn test_verify_recovery_code() {
        let (mut codes, plaintext) =
            RecoveryCodeManager::generate("user@example.com".to_string(), 5).unwrap();

        let test_code = &plaintext[0];

        // Verify succeeds
        let result = RecoveryCodeManager::verify_and_use(test_code, &mut codes.codes);
        assert!(result.is_ok());
        assert!(codes.codes[0].used);

        // Second use fails
        let result = RecoveryCodeManager::verify_and_use(test_code, &mut codes.codes);
        assert!(matches!(result, Err(AuthError::RecoveryCodeUsed)));
    }
}
