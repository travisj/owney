use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid credential ID")]
    InvalidCredentialId,

    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    #[error("Challenge mismatch")]
    ChallengeMismatch,

    #[error("Credential counter went backwards (possible cloning attack)")]
    CounterRollback,

    #[error("No matching credential found")]
    CredentialNotFound,

    #[error("Credential disabled or revoked")]
    CredentialDisabled,

    #[error("Invalid recovery code")]
    InvalidRecoveryCode,

    #[error("Recovery code already used")]
    RecoveryCodeUsed,

    #[error("No recovery codes available")]
    NoRecoveryCodes,

    #[error("Invalid approval request")]
    InvalidApprovalRequest,

    #[error("Approval request expired")]
    ApprovalRequestExpired,

    #[error("Approval request already processed")]
    ApprovalAlreadyProcessed,

    #[error("Too many pending approvals")]
    TooManyPendingApprovals,

    #[error("Device not paired")]
    DeviceNotPaired,

    #[error("Invalid pairing code")]
    InvalidPairingCode,

    #[error("Pairing code expired")]
    PairingCodeExpired,

    #[error("No passkeys enrolled")]
    NoPasskeysEnrolled,

    #[error("Database error: {0}")]
    Database(String),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("Insufficient permissions")]
    Unauthorized,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<webauthn_rs::error::WebauthnBuilder> for AuthError {
    fn from(e: webauthn_rs::error::WebauthnBuilder) -> Self {
        Self::WebAuthn(format!("{:?}", e))
    }
}

impl From<webauthn_rs::error::WebauthnError> for AuthError {
    fn from(e: webauthn_rs::error::WebauthnError) -> Self {
        Self::WebAuthn(format!("{:?}", e))
    }
}
