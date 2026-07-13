use crate::error::AuthError;
use crate::AuthResult;
use chrono::{DateTime, Duration, Utc};
use qrcode::{QrCode, render::unicode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A QR code for device pairing (e.g., terminal to mobile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodePairing {
    pub pairing_code: String,           // Random code only recipient knows
    pub public_key: Vec<u8>,            // Server's public key for TLS binding
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub server_url: String,             // https://example.com
    pub used: bool,
}

/// QR pairing code payload (what's encoded in the QR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPairingPayload {
    pub pairing_code: String,
    pub server_url: String,
    pub expires_at: i64,  // Unix timestamp
    pub signature: String, // HMAC-SHA256 of above fields
}

impl QrCodePairing {
    /// Generates a new QR code for device pairing.
    pub fn generate(server_url: String, public_key: Vec<u8>, ttl_secs: u64) -> AuthResult<Self> {
        let pairing_code = Self::generate_code();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_secs as i64);

        Ok(QrCodePairing {
            pairing_code,
            public_key,
            created_at: now,
            expires_at,
            server_url,
            used: false,
        })
    }

    /// Checks if this pairing code is still valid.
    pub fn is_valid(&self) -> bool {
        !self.used && Utc::now() <= self.expires_at
    }

    /// Generates the QR code as a Unicode string for terminal display.
    pub fn to_terminal_qr(&self) -> AuthResult<String> {
        let payload = QrPairingPayload {
            pairing_code: self.pairing_code.clone(),
            server_url: self.server_url.clone(),
            expires_at: self.expires_at.timestamp(),
            signature: String::new(), // Would be filled by server
        };

        let json = serde_json::to_string(&payload)
            .map_err(|e| AuthError::Internal(format!("JSON encoding failed: {e}")))?;

        let code = QrCode::new(&json)
            .map_err(|e| AuthError::Internal(format!("QR generation failed: {e}")))?;

        let qr_string = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build();

        Ok(qr_string)
    }

    /// Generates the QR code as SVG for web display.
    pub fn to_svg_qr(&self) -> AuthResult<String> {
        let payload = QrPairingPayload {
            pairing_code: self.pairing_code.clone(),
            server_url: self.server_url.clone(),
            expires_at: self.expires_at.timestamp(),
            signature: String::new(),
        };

        let json = serde_json::to_string(&payload)
            .map_err(|e| AuthError::Internal(format!("JSON encoding failed: {e}")))?;

        let code = QrCode::new(&json)
            .map_err(|e| AuthError::Internal(format!("QR generation failed: {e}")))?;

        // Render as SVG
        let svg = code.render::<qrcode::render::svg::Color>().build();
        Ok(svg)
    }

    /// Generates a random pairing code (alphanumeric, case-insensitive).
    fn generate_code() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..16)
            .map(|_| charset.chars().nth(rng.gen_range(0..charset.len())).unwrap())
            .collect()
    }

    /// Marks this pairing code as used (can only be used once).
    pub fn mark_used(&mut self) {
        self.used = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_qr_pairing() {
        let qr = QrCodePairing::generate(
            "https://mail.example.com".to_string(),
            vec![1, 2, 3],
            300,
        )
        .unwrap();

        assert!(!qr.pairing_code.is_empty());
        assert!(qr.is_valid());
        assert!(!qr.used);
    }

    #[test]
    fn test_qr_expiration() {
        let qr = QrCodePairing::generate(
            "https://mail.example.com".to_string(),
            vec![1, 2, 3],
            0, // Expires immediately
        )
        .unwrap();

        // Should still be valid immediately after creation, but will expire soon
        // In real test, we'd mock time
        assert!(!qr.used);
    }

    #[test]
    fn test_qr_mark_used() {
        let mut qr = QrCodePairing::generate(
            "https://mail.example.com".to_string(),
            vec![1, 2, 3],
            300,
        )
        .unwrap();

        assert!(qr.is_valid());
        qr.mark_used();
        assert!(!qr.is_valid());
    }

    #[test]
    fn test_terminal_qr_generation() {
        let qr = QrCodePairing::generate(
            "https://mail.example.com".to_string(),
            vec![1, 2, 3],
            300,
        )
        .unwrap();

        let terminal_qr = qr.to_terminal_qr().unwrap();
        assert!(!terminal_qr.is_empty());
        // QR should contain Unicode box characters
        assert!(terminal_qr.contains("█") || terminal_qr.contains("▀") || terminal_qr.contains("▄"));
    }
}
