//! Passwordless authentication: WebAuthn passkeys, cross-device approval, recovery codes.

pub mod approval;
pub mod error;
pub mod passkey;
pub mod qr;
pub mod recovery;

pub use error::AuthError;
pub use passkey::{AuthenticationOptions, PasskeyCredential, PasskeyManager, RegistrationOptions};

// Re-export the webauthn-rs types that API layers need to accept browser
// responses and to persist the start/finish state objects.
pub use approval::CrossDeviceApprovalManager;
pub use qr::QrCodePairing;
pub use recovery::RecoveryCodeManager;
pub use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

/// Unique identifier for a passkey credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CredentialId(pub Vec<u8>);

/// Unique identifier for a recovery code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RecoveryCodeId(pub uuid::Uuid);

/// Unique identifier for a device pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DevicePairingId(pub uuid::Uuid);

/// Unique identifier for a cross-device approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequestId(pub uuid::Uuid);

/// Configuration for passwordless authentication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PasswordlessAuthConfig {
    /// Relying Party ID (domain for WebAuthn binding). Must be eTLD+1 (e.g., "example.com", not "subdomain.example.com").
    pub rp_id: String,

    /// Display name for the relying party (shown in authenticator dialogs).
    pub rp_name: String,

    /// Origins where WebAuthn is valid (e.g., ["https://mail.example.com"]).
    pub origins: Vec<String>,

    /// Number of recovery codes to generate per account (typically 10).
    pub recovery_code_count: usize,

    /// Time-to-live for pending cross-device approval requests (seconds).
    pub approval_request_ttl: u64,

    /// Maximum number of pending approval requests per account (prevents spam).
    pub max_pending_approvals: usize,

    /// Enable cross-device approval (requires push notification service).
    pub cross_device_approval_enabled: bool,

    /// Enable magic link fallback (email-based recovery).
    pub magic_link_enabled: bool,

    /// Magic link validity (seconds).
    pub magic_link_ttl: u64,
}

impl PasswordlessAuthConfig {
    /// Creates config with defaults for `rp_id`.
    pub fn new(rp_id: String, origins: Vec<String>) -> Self {
        Self {
            rp_name: "Owney Mailserver".to_string(),
            recovery_code_count: 10,
            approval_request_ttl: 300, // 5 minutes
            max_pending_approvals: 5,
            cross_device_approval_enabled: true,
            magic_link_enabled: true,
            magic_link_ttl: 900, // 15 minutes
            rp_id,
            origins,
        }
    }
}

/// Result type for authentication operations.
pub type AuthResult<T> = Result<T, AuthError>;
