//! Passwordless authentication REST API (passkeys, recovery codes, cross-device
//! approval, QR pairing).
//!
//! ⚠️ NOT PRODUCTION READY — DO NOT MOUNT. `auth_routes()` is intentionally not
//! merged into the main router. Several handlers still use a literal
//! `"placeholder"` account id, do not persist what they claim to, and issue
//! session tokens that the main bearer-auth path (`authenticate` in lib.rs)
//! does not recognise. Wiring these routes up as-is would create unauthenticated
//! account-takeover paths (see docs/POSTMORTEM_2026-07-13.md, findings
//! CR-03..CR-08). Before mounting: replace every placeholder identity with an
//! authenticated account context, integrate session tokens with the storage
//! token path, make recovery/approval transitions atomic, and add end-to-end
//! HTTP tests for every flow.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use owney_authn_v2::{
    self, AuthError, AuthResult, CredentialId, PasskeyAuthentication, PasskeyManager,
    PasskeyRegistration, PasswordlessAuthConfig, PublicKeyCredential, RegisterPublicKeyCredential,
};
use owney_core::Config;
use owney_storage::Storage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::challenge_store::{ChallengeStore, SessionTokenManager};

/// Passwordless authentication state (managed globally).
#[derive(Debug)]
pub struct AuthState {
    pub passkey_manager: PasskeyManager,
    pub config: PasswordlessAuthConfig,
    pub challenge_store: ChallengeStore,
    pub session_tokens: SessionTokenManager,
    pub storage: Arc<Storage>,
}

impl AuthState {
    /// Creates a new authentication state from config.
    pub fn new(config: &Config, storage: Arc<Storage>) -> AuthResult<Self> {
        let auth_config = PasswordlessAuthConfig::new(
            config.server.hostname.clone(),
            vec![format!("https://{}", config.server.hostname)],
        );

        let passkey_manager = PasskeyManager::new(auth_config.clone())?;

        Ok(Self {
            passkey_manager,
            config: auth_config,
            challenge_store: ChallengeStore::new(),
            session_tokens: SessionTokenManager::new(),
            storage,
        })
    }
}

/// Request/Response Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationStartRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationStartResponse {
    pub options: serde_json::Value, // WebAuthn CreationChallengeResponse
    pub session_id: String,         // Temporary session ID for challenge storage
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationFinishRequest {
    pub session_id: String,
    pub device_name: String,           // "iPhone 15 Pro"
    pub credential: serde_json::Value, // PublicKeyCredential from browser
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationFinishResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuthenticationStartRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuthenticationStartResponse {
    pub options: serde_json::Value, // WebAuthn RequestChallengeResponse
    pub session_id: String,         // Temporary session ID for challenge storage
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuthenticationFinishRequest {
    pub session_id: String,
    pub credential: serde_json::Value, // PublicKeyCredential from browser
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAuthenticationFinishResponse {
    pub success: bool,
    pub session_token: String, // Bearer token for authenticated requests
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeGenerateRequest {
    pub count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeGenerateResponse {
    pub codes: Vec<String>,     // Plain codes (only shown once)
    pub display_format: String, // "XXXX-XXXX-XXXX"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeUseRequest {
    pub recovery_code: String, // User enters code here
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeUseResponse {
    pub success: bool,
    pub session_token: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestCreateRequest {
    pub request_type: String,  // "web_login", "app_login", etc.
    pub source_device: String, // "San Francisco, CA (192.0.2.1)"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestCreateResponse {
    pub request_id: String,
    pub expires_in_seconds: u64,
    pub message: String, // "Push notifications sent to enrolled devices"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestStatusResponse {
    pub status: String, // "pending", "approved", "denied", "expired"
    pub approved_by_device: Option<String>,
    pub approved_at: Option<i64>, // Unix timestamp
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestApproveRequest {
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestApproveResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodePairingResponse {
    pub qr_code: String, // SVG or Unicode string
    pub pairing_code: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodePairingConfirmRequest {
    pub pairing_code: String,
    pub device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodePairingConfirmResponse {
    pub success: bool,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    pub details: Option<String>,
}

/// Local wrapper so axum's `IntoResponse` can be implemented (the orphan
/// rule forbids implementing it directly for `owney_authn_v2::AuthError`).
#[derive(Debug)]
pub struct ApiAuthError(pub AuthError);

impl From<AuthError> for ApiAuthError {
    fn from(e: AuthError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiAuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self.0 {
            AuthError::InvalidCredentialId => (
                StatusCode::BAD_REQUEST,
                "invalid_credential_id",
                "Invalid credential format",
            ),
            AuthError::WebAuthn(_) => (
                StatusCode::BAD_REQUEST,
                "webauthn_error",
                "WebAuthn operation failed",
            ),
            AuthError::ChallengeMismatch => (
                StatusCode::BAD_REQUEST,
                "challenge_mismatch",
                "Challenge does not match",
            ),
            AuthError::CounterRollback => (
                StatusCode::UNAUTHORIZED,
                "counter_rollback",
                "Possible credential cloning detected",
            ),
            AuthError::CredentialNotFound => (
                StatusCode::NOT_FOUND,
                "credential_not_found",
                "Passkey not found",
            ),
            AuthError::InvalidRecoveryCode => (
                StatusCode::BAD_REQUEST,
                "invalid_recovery_code",
                "Recovery code is invalid",
            ),
            AuthError::RecoveryCodeUsed => (
                StatusCode::BAD_REQUEST,
                "recovery_code_used",
                "Recovery code has already been used",
            ),
            AuthError::ApprovalRequestExpired => (
                StatusCode::GONE,
                "approval_expired",
                "Approval request has expired",
            ),
            AuthError::TooManyPendingApprovals => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_pending",
                "Too many pending approval requests",
            ),
            AuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Not authorized for this operation",
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An error occurred",
            ),
        };

        // Log the full internal error server-side for diagnosis, but never
        // serialize Debug output to the client — it leaks implementation
        // details and the structure of authentication failures to attackers.
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = ?self.0, "auth internal error");
        } else {
            tracing::debug!(error = ?self.0, code, "auth error");
        }

        let error = ErrorResponse {
            error: message.to_string(),
            code: code.to_string(),
            details: None,
        };

        (status, Json(error)).into_response()
    }
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Registration state persisted in the challenge store between
/// registration start and finish.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRegistrationState {
    email: String,
    state: PasskeyRegistration,
}

/// Converts a storage-layer credential (which persists the webauthn-rs
/// `Passkey` as serde_json bytes in `public_key`) into the domain type.
fn storage_cred_to_authn(
    cred: &owney_storage::PasskeyCredential,
) -> Result<owney_authn_v2::PasskeyCredential, ApiAuthError> {
    let passkey = owney_authn_v2::PasskeyCredential::passkey_from_bytes(&cred.public_key)?;
    Ok(owney_authn_v2::PasskeyCredential {
        id: CredentialId(cred.id.clone()),
        account_id: cred.account_id.clone(),
        device_name: cred.device_name.clone(),
        passkey,
        counter: cred.counter,
        backup_eligible: cred.backup_eligible,
        backup_state: cred.backup_state,
        created_at: cred.created_at,
        last_used_at: cred.last_used_at,
        disabled: cred.disabled,
    })
}

pub async fn passkey_registration_start(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<PasskeyRegistrationStartRequest>,
) -> Result<Json<PasskeyRegistrationStartResponse>, ApiAuthError> {
    // Validate email format
    if !req.email.contains('@') {
        return Err(AuthError::Config("Invalid email address".to_string()).into());
    }

    // Normalize email to lowercase
    let email = req.email.to_lowercase();

    // Generate registration challenge
    let reg_opts = state
        .passkey_manager
        .start_registration(&email, &email, None)?;

    // Store the serialized registration state (challenge + verification data)
    let stored = StoredRegistrationState {
        email: email.clone(),
        state: reg_opts.state,
    };
    let state_bytes = serde_json::to_vec(&stored)
        .map_err(|e| AuthError::Internal(format!("State serialization failed: {e}")))?;
    let session_id = state
        .challenge_store
        .store_challenge(state_bytes)
        .await
        .map_err(AuthError::Config)?;

    tracing::info!(email = %email, session_id = %session_id, "passkey registration started");

    Ok(Json(PasskeyRegistrationStartResponse {
        options: serde_json::to_value(reg_opts.options)
            .map_err(|e| AuthError::WebAuthn(e.to_string()))?,
        session_id,
    }))
}

pub async fn passkey_registration_finish(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<PasskeyRegistrationFinishRequest>,
) -> Result<Json<PasskeyRegistrationFinishResponse>, ApiAuthError> {
    // Retrieve serialized registration state from storage
    let state_bytes = state
        .challenge_store
        .retrieve_challenge(&req.session_id)
        .await
        .map_err(|_| AuthError::ChallengeMismatch)?;
    let stored: StoredRegistrationState =
        serde_json::from_slice(&state_bytes).map_err(|_| AuthError::ChallengeMismatch)?;

    // Parse client response
    let response: RegisterPublicKeyCredential = serde_json::from_value(req.credential)
        .map_err(|_| AuthError::WebAuthn("Invalid credential format".to_string()))?;

    // Verify registration and create the credential. The account is keyed by
    // the (normalized) email captured at registration start.
    let credential = state.passkey_manager.finish_registration(
        stored.email,
        req.device_name,
        &response,
        &stored.state,
    )?;

    // Create storage credential object; the whole webauthn-rs Passkey is
    // serialized into the public_key column.
    let storage_cred = owney_storage::PasskeyCredential {
        id: credential.id.0.clone(),
        account_id: credential.account_id.clone(),
        device_name: credential.device_name.clone(),
        public_key: credential.passkey_bytes()?,
        counter: credential.counter,
        backup_eligible: credential.backup_eligible,
        backup_state: credential.backup_state,
        aaguid: None,
        created_at: credential.created_at,
        last_used_at: credential.last_used_at,
        disabled: credential.disabled,
    };

    // Save to database
    state
        .storage
        .save_passkey_credential(&storage_cred)
        .await
        .map_err(|e| AuthError::Database(format!("Failed to save credential: {}", e)))?;

    tracing::info!(account_id = %credential.account_id, device_name = %credential.device_name, "passkey registered");

    Ok(Json(PasskeyRegistrationFinishResponse {
        success: true,
        message: "Passkey registered successfully".to_string(),
    }))
}

pub async fn passkey_authentication_start(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<PasskeyAuthenticationStartRequest>,
) -> Result<Json<PasskeyAuthenticationStartResponse>, ApiAuthError> {
    // Normalize email
    let email = req.email.to_lowercase();

    // Verify account exists
    let _account = state
        .storage
        .account_by_email(&email)
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .ok_or(AuthError::CredentialNotFound)?;

    // Get user's registered passkeys
    let stored_passkeys = state
        .storage
        .list_passkeys_for_account(email.clone())
        .await
        .map_err(|_| AuthError::CredentialNotFound)?;

    if stored_passkeys.is_empty() {
        return Err(AuthError::CredentialNotFound.into());
    }

    let credentials = stored_passkeys
        .iter()
        .map(storage_cred_to_authn)
        .collect::<Result<Vec<_>, _>>()?;

    // Generate authentication challenge against the user's passkeys
    let auth_opts = state.passkey_manager.start_authentication(&credentials)?;

    // Store the serialized authentication state
    let state_bytes = serde_json::to_vec(&auth_opts.state)
        .map_err(|e| AuthError::Internal(format!("State serialization failed: {e}")))?;
    let session_id = state
        .challenge_store
        .store_challenge(state_bytes)
        .await
        .map_err(AuthError::Config)?;

    tracing::info!(email = %email, session_id = %session_id, "passkey authentication started");

    Ok(Json(PasskeyAuthenticationStartResponse {
        options: serde_json::to_value(auth_opts.options)
            .map_err(|e| AuthError::WebAuthn(e.to_string()))?,
        session_id,
    }))
}

pub async fn passkey_authentication_finish(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<PasskeyAuthenticationFinishRequest>,
) -> Result<Json<PasskeyAuthenticationFinishResponse>, ApiAuthError> {
    // Retrieve serialized authentication state
    let state_bytes = state
        .challenge_store
        .retrieve_challenge(&req.session_id)
        .await
        .map_err(|_| AuthError::ChallengeMismatch)?;
    let auth_state: PasskeyAuthentication =
        serde_json::from_slice(&state_bytes).map_err(|_| AuthError::ChallengeMismatch)?;

    // Parse assertion response
    let response: PublicKeyCredential = serde_json::from_value(req.credential)
        .map_err(|_| AuthError::WebAuthn("Invalid assertion format".to_string()))?;

    // Get credential from storage
    let cred_id: Vec<u8> = response.raw_id.as_ref().to_vec();
    let stored_cred = state
        .storage
        .get_passkey_credential(&cred_id)
        .await
        .map_err(|_| AuthError::CredentialNotFound)?
        .ok_or(AuthError::CredentialNotFound)?;

    // Verify authentication (this updates counter, backup flags, last_used_at)
    let mut auth_cred = storage_cred_to_authn(&stored_cred)?;
    state
        .passkey_manager
        .finish_authentication(&response, &auth_state, &mut auth_cred)?;

    // Update counter and last_used_at in storage
    state
        .storage
        .update_passkey_counter(&cred_id, auth_cred.counter)
        .await
        .map_err(|e| AuthError::Database(format!("Failed to update credential: {}", e)))?;

    // Generate session token
    let session_token = state
        .session_tokens
        .generate_token(stored_cred.account_id.clone())
        .await
        .map_err(AuthError::Config)?;

    tracing::info!(account_id = %stored_cred.account_id, "passkey authentication successful");

    Ok(Json(PasskeyAuthenticationFinishResponse {
        success: true,
        session_token,
        user_id: stored_cred.account_id,
    }))
}

pub async fn recovery_code_generate(
    State(_state): State<Arc<AuthState>>,
    Json(req): Json<RecoveryCodeGenerateRequest>,
) -> Result<Json<RecoveryCodeGenerateResponse>, ApiAuthError> {
    // For now, we accept an account_id via a custom header or body parameter
    // In a real implementation, this would be extracted from an authenticated session
    // This is a placeholder - you should integrate with your auth middleware

    let count = req.count.unwrap_or(10);
    if count == 0 || count > 100 {
        return Err(AuthError::Config("Count must be between 1 and 100".to_string()).into());
    }

    // Generate recovery codes
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    let mut codes = Vec::new();
    let mut display_codes = Vec::new();

    for _ in 0..count {
        // Generate random code: XXXX-XXXX-XXXX format
        let random = Uuid::new_v4();
        let code_str = random.to_string()[..19].to_uppercase(); // e.g., "XXXXXXXX-XXXX-XXXX"
        display_codes.push(code_str.clone());

        // Hash the code
        let mut hasher = Sha256::new();
        hasher.update(&code_str);
        let hash = hex::encode(hasher.finalize());

        codes.push(owney_storage::RecoveryCode {
            id: Uuid::new_v4().to_string(),
            account_id: "placeholder".to_string(), // Would come from auth context
            code_hash: hash,
            display_code: code_str,
            used: false,
            used_at: None,
            created_at: chrono::Utc::now(),
        });
    }

    // Note: In production, you'd extract account_id from auth context and save codes
    // storage.save_recovery_codes(account_id, &codes).await?;

    tracing::info!(count = codes.len(), "recovery codes generated");

    Ok(Json(RecoveryCodeGenerateResponse {
        codes: display_codes,
        display_format: "XXXX-XXXX-XXXX".to_string(),
    }))
}

pub async fn recovery_code_use(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<RecoveryCodeUseRequest>,
) -> Result<Json<RecoveryCodeUseResponse>, ApiAuthError> {
    use sha2::{Digest, Sha256};

    // Normalize code (remove dashes, uppercase)
    let code = req.recovery_code.replace("-", "").to_uppercase();

    // Hash the recovery code
    let mut hasher = Sha256::new();
    hasher.update(&code);
    let code_hash = hex::encode(hasher.finalize());

    // Look up code in database
    let recovery_code = state
        .storage
        .get_recovery_code_by_hash(&code_hash)
        .await
        .map_err(|_| AuthError::InvalidRecoveryCode)?
        .ok_or(AuthError::InvalidRecoveryCode)?;

    if recovery_code.used {
        return Err(AuthError::RecoveryCodeUsed.into());
    }

    // Mark code as used
    state
        .storage
        .mark_recovery_code_used(&recovery_code.id)
        .await
        .map_err(|e| AuthError::WebAuthn(format!("Failed to mark code used: {}", e)))?;

    // Generate session token
    let session_token = state
        .session_tokens
        .generate_token(recovery_code.account_id.clone())
        .await
        .map_err(AuthError::Config)?;

    tracing::info!(account_id = %recovery_code.account_id, "recovery code used for authentication");

    Ok(Json(RecoveryCodeUseResponse {
        success: true,
        session_token: Some(session_token),
        message: "Recovery code accepted. Account recovered successfully.".to_string(),
    }))
}

pub async fn approval_request_create(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<ApprovalRequestCreateRequest>,
) -> Result<Json<ApprovalRequestCreateResponse>, ApiAuthError> {
    use rand::Rng;
    use uuid::Uuid;

    // This would normally get account_id from auth context
    // For now it's a placeholder
    let account_id = "placeholder".to_string();

    // Verify account exists
    // let account = state.storage.account(account_id.parse()?).await?
    //     .ok_or(AuthError::Unauthorized)?;

    // Get enrolled devices for the account
    let devices = state
        .storage
        .list_devices_for_account(account_id.clone())
        .await
        .map_err(|_| AuthError::Unauthorized)?;

    if devices.is_empty() {
        return Err(AuthError::TooManyPendingApprovals.into()); // No devices enrolled
    }

    // Generate approval request. Scope the ThreadRng so it is not held
    // across the awaits below (ThreadRng is !Send).
    let request_id = Uuid::now_v7().to_string();
    let challenge_bytes: [u8; 32] = {
        let mut rng = rand::thread_rng();
        rng.r#gen()
    };
    let challenge = hex::encode(challenge_bytes);

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::minutes(10);

    let approval_req = owney_storage::ApprovalRequest {
        id: request_id.clone(),
        account_id: account_id.clone(),
        source_device: req.source_device,
        request_type: req.request_type,
        challenge: challenge.clone(),
        created_at: now,
        expires_at,
        status: "pending".to_string(),
        approved_by_device: None,
        approved_at: None,
    };

    // Save request
    state
        .storage
        .save_approval_request(&approval_req)
        .await
        .map_err(|e| AuthError::WebAuthn(format!("Failed to create request: {}", e)))?;

    // Send push notifications to devices with push tokens
    for device in devices.iter().filter(|d| d.push_token.is_some()) {
        // TODO: Send push notification via FCM/APNS
        // push::send_approval_notification(
        //     device.push_token.as_ref().unwrap(),
        //     &request_id,
        //     &approval_req.source_device,
        // ).await;
        tracing::info!(device_id = %device.id, "sending approval push notification");
    }

    tracing::info!(account_id = %account_id, request_id = %request_id, "approval request created");

    Ok(Json(ApprovalRequestCreateResponse {
        request_id,
        expires_in_seconds: 600, // 10 minutes
        message: format!(
            "Approval request sent to {} enrolled devices",
            devices.len()
        ),
    }))
}

pub async fn approval_request_status(
    State(state): State<Arc<AuthState>>,
    Path(request_id): Path<String>,
) -> Result<Json<ApprovalRequestStatusResponse>, ApiAuthError> {
    let request = state
        .storage
        .get_approval_request(&request_id)
        .await
        .map_err(|_| AuthError::ApprovalRequestExpired)?
        .ok_or(AuthError::ApprovalRequestExpired)?;

    // Check if expired
    if chrono::Utc::now() > request.expires_at {
        return Ok(Json(ApprovalRequestStatusResponse {
            status: "expired".to_string(),
            approved_by_device: None,
            approved_at: None,
        }));
    }

    tracing::debug!(request_id = %request_id, status = %request.status, "approval request status checked");

    Ok(Json(ApprovalRequestStatusResponse {
        status: request.status,
        approved_by_device: request.approved_by_device,
        approved_at: request.approved_at.map(|t| t.timestamp()),
    }))
}

pub async fn approval_request_approve(
    State(state): State<Arc<AuthState>>,
    Path(request_id): Path<String>,
    Json(req): Json<ApprovalRequestApproveRequest>,
) -> Result<Json<ApprovalRequestApproveResponse>, ApiAuthError> {
    // Get the approval request
    let approval_req = state
        .storage
        .get_approval_request(&request_id)
        .await
        .map_err(|_| AuthError::ApprovalRequestExpired)?
        .ok_or(AuthError::ApprovalRequestExpired)?;

    // Check if expired
    if chrono::Utc::now() > approval_req.expires_at {
        return Err(AuthError::ApprovalRequestExpired.into());
    }

    // Verify device is enrolled and belongs to same account
    let device = state
        .storage
        .get_device_pairing(&req.device_id)
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .ok_or(AuthError::Unauthorized)?;

    if device.account_id != approval_req.account_id {
        return Err(AuthError::Unauthorized.into());
    }

    if !device.can_approve {
        return Err(AuthError::Unauthorized.into());
    }

    // Mark as approved
    state
        .storage
        .update_approval_request_status(&request_id, "approved", Some(&req.device_id))
        .await
        .map_err(|e| AuthError::WebAuthn(format!("Failed to approve: {}", e)))?;

    // Update device last_used_at
    state
        .storage
        .update_device_last_used(&req.device_id)
        .await
        .map_err(|e| AuthError::WebAuthn(format!("Failed to update device: {}", e)))?;

    tracing::info!(request_id = %request_id, device_id = %req.device_id, "approval request approved");

    Ok(Json(ApprovalRequestApproveResponse {
        success: true,
        message: "Approval request approved successfully".to_string(),
    }))
}

pub async fn qr_code_pairing(
    State(state): State<Arc<AuthState>>,
) -> Result<Json<QrCodePairingResponse>, ApiAuthError> {
    use uuid::Uuid;

    // Generate pairing code (alphanumeric, 8 chars)
    let pairing_code = Uuid::new_v4().to_string()[..8].to_uppercase().to_string();

    // Store pairing code in challenge store
    let code_id = state
        .challenge_store
        .store_pairing_code(pairing_code.clone())
        .await
        .map_err(AuthError::Config)?;

    // Generate QR code (simplified - contains code_id for retrieval)
    // In production, this would encode the full pairing URL
    let qr_content = format!("owney://pair/{}/{}", code_id, pairing_code);
    let qr_code = generate_qr_code_unicode(&qr_content);

    tracing::info!(code_id = %code_id, "QR pairing code generated");

    Ok(Json(QrCodePairingResponse {
        qr_code,
        pairing_code,
        expires_in_seconds: 120, // 2 minutes
    }))
}

pub async fn qr_code_pairing_confirm(
    State(state): State<Arc<AuthState>>,
    Json(req): Json<QrCodePairingConfirmRequest>,
) -> Result<Json<QrCodePairingConfirmResponse>, ApiAuthError> {
    use uuid::Uuid;

    // Verify pairing code exists and hasn't expired
    // Note: We can't directly validate against the stored code, but we can
    // check if it can be retrieved without error. For now, we'll generate
    // a new device ID and store it.

    // This would normally come from auth context
    let account_id = "placeholder".to_string();

    // Generate device ID
    let device_id = Uuid::now_v7().to_string();

    // In a real implementation, you would:
    // 1. Derive public key from the pairing handshake
    // 2. Verify the device's certificate
    // 3. Store the device securely

    let device = owney_storage::DevicePairing {
        id: device_id.clone(),
        account_id,
        device_name: req.device_name,
        device_type: "unknown".to_string(), // Would be detected from device
        public_key: vec![],                 // Would be from pairing handshake
        can_approve: true,
        push_token: None, // Would be provided by device
        paired_at: chrono::Utc::now(),
        last_used_at: None,
        disabled: false,
    };

    // Save device
    state
        .storage
        .save_device_pairing(&device)
        .await
        .map_err(|e| AuthError::WebAuthn(format!("Failed to save device: {}", e)))?;

    tracing::info!(device_id = %device_id, "device paired via QR code");

    Ok(Json(QrCodePairingConfirmResponse {
        success: true,
        device_id,
    }))
}

// ============================================================================
// Utilities
// ============================================================================

/// Generate a simple Unicode QR code representation.
/// In production, use a proper QR library like `qrcode`.
fn generate_qr_code_unicode(data: &str) -> String {
    // Simplified: just return the data as-is for now
    // A real implementation would use the `qrcode` crate to generate SVG or Unicode
    format!("QR Code ({})", data)
}

// ============================================================================
// Router Setup
// ============================================================================

pub fn auth_routes() -> Router<Arc<AuthState>> {
    Router::new()
        .route(
            "/auth/passkey/register/start",
            post(passkey_registration_start),
        )
        .route(
            "/auth/passkey/register/finish",
            post(passkey_registration_finish),
        )
        .route(
            "/auth/passkey/authenticate/start",
            post(passkey_authentication_start),
        )
        .route(
            "/auth/passkey/authenticate/finish",
            post(passkey_authentication_finish),
        )
        .route("/auth/recovery/generate", post(recovery_code_generate))
        .route("/auth/recovery/use", post(recovery_code_use))
        .route("/auth/approval/create", post(approval_request_create))
        .route("/auth/approval/{request_id}", get(approval_request_status))
        .route(
            "/auth/approval/{request_id}/approve",
            post(approval_request_approve),
        )
        .route("/auth/pairing/qr", get(qr_code_pairing))
        .route("/auth/pairing/confirm", post(qr_code_pairing_confirm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_store() {
        let _store = crate::challenge_store::ChallengeStore::new();
        // Tests are in challenge_store module
    }

    #[test]
    fn test_recovery_code_normalization() {
        let code = "XXXX-XXXX-XXXX";
        let normalized = code.replace("-", "").to_uppercase();
        assert_eq!(normalized, "XXXXXXXXXXXX");
    }

    #[test]
    fn test_error_response_conversion() {
        let err: ApiAuthError = AuthError::ChallengeMismatch.into();
        let response: Response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_qr_code_generation() {
        let qr = generate_qr_code_unicode("test-data");
        assert!(qr.contains("test-data"));
    }
}
