use crate::error::AuthError;
use crate::{AuthResult, CredentialId, PasswordlessAuthConfig};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::WebauthnBuilder;
use webauthn_rs::prelude::*;

/// A registered passkey credential.
///
/// The full webauthn-rs [`Passkey`] is carried here (it is serde-serialisable);
/// the storage layer persists it as serde_json bytes in the `public_key`
/// column rather than raw COSE key bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: CredentialId,
    pub account_id: String,
    pub device_name: String, // "iPhone", "MacBook Pro", etc.
    /// The complete webauthn-rs passkey (public key, counter, policy, ...).
    pub passkey: Passkey,
    pub counter: u32,          // FIDO2 counter (prevents cloning)
    pub backup_eligible: bool, // Can be backed up to cloud
    pub backup_state: bool,    // Currently backed up
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub disabled: bool,
}

impl PasskeyCredential {
    /// Serialises the inner [`Passkey`] for persistence in the storage
    /// layer's `public_key` column.
    pub fn passkey_bytes(&self) -> AuthResult<Vec<u8>> {
        serde_json::to_vec(&self.passkey)
            .map_err(|e| AuthError::Internal(format!("Passkey serialization failed: {e}")))
    }

    /// Reconstructs the inner [`Passkey`] from persisted bytes.
    pub fn passkey_from_bytes(bytes: &[u8]) -> AuthResult<Passkey> {
        serde_json::from_slice(bytes)
            .map_err(|e| AuthError::Internal(format!("Passkey deserialization failed: {e}")))
    }
}

/// WebAuthn registration challenge, plus the server-side state that must be
/// stored (e.g. in the challenge store) between start and finish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptions {
    /// Send this to the browser (`navigator.credentials.create`).
    pub options: CreationChallengeResponse,
    /// Server-side registration state; persist between start/finish.
    pub state: PasskeyRegistration,
    /// The user handle generated for this registration.
    pub user_id: Uuid,
}

/// WebAuthn authentication challenge, plus the server-side state that must be
/// stored between start and finish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    /// Send this to the browser (`navigator.credentials.get`).
    pub options: RequestChallengeResponse,
    /// Server-side authentication state; persist between start/finish.
    pub state: PasskeyAuthentication,
}

/// Manages passkey operations (registration, authentication, credential storage).
#[derive(Debug)]
pub struct PasskeyManager {
    webauthn: Webauthn,
}

impl PasskeyManager {
    /// Creates a new PasskeyManager with the given configuration.
    pub fn new(config: PasswordlessAuthConfig) -> AuthResult<Self> {
        let origins: Vec<Url> = config
            .origins
            .iter()
            .filter_map(|origin| Url::parse(origin).ok())
            .collect();

        let Some((first_origin, other_origins)) = origins.split_first() else {
            return Err(AuthError::Config("No valid origins configured".to_string()));
        };

        let mut builder = WebauthnBuilder::new(&config.rp_id, first_origin)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?
            .rp_name(&config.rp_name);
        for origin in other_origins {
            builder = builder.append_allowed_origin(origin);
        }
        let webauthn = builder
            .build()
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        Ok(Self { webauthn })
    }

    /// Generates a registration challenge for enrolling a new passkey.
    ///
    /// `exclude_credentials` should list the credential IDs already
    /// registered for this user, to prevent double-enrolment.
    pub fn start_registration(
        &self,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> AuthResult<RegistrationOptions> {
        let user_id = Uuid::now_v7();

        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_id, user_name, user_display_name, exclude_credentials)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        Ok(RegistrationOptions {
            options,
            state,
            user_id,
        })
    }

    /// Verifies a registration response and returns the credential to be stored.
    ///
    /// `state` must be the [`PasskeyRegistration`] returned from
    /// [`start_registration`](Self::start_registration) for this session.
    pub fn finish_registration(
        &self,
        account_id: String,
        device_name: String,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> AuthResult<PasskeyCredential> {
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, state)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        let cred_id = CredentialId(passkey.cred_id().as_ref().to_vec());

        Ok(PasskeyCredential {
            id: cred_id,
            account_id,
            device_name,
            passkey,
            counter: 0,
            // Backup flags are refreshed from each AuthenticationResult.
            backup_eligible: false,
            backup_state: false,
            created_at: Utc::now(),
            last_used_at: None,
            disabled: false,
        })
    }

    /// Generates an authentication challenge for a passkey login.
    ///
    /// `credentials` are the user's registered (enabled) passkeys.
    pub fn start_authentication(
        &self,
        credentials: &[PasskeyCredential],
    ) -> AuthResult<AuthenticationOptions> {
        let passkeys: Vec<Passkey> = credentials
            .iter()
            .filter(|c| !c.disabled)
            .map(|c| c.passkey.clone())
            .collect();
        if passkeys.is_empty() {
            return Err(AuthError::NoPasskeysEnrolled);
        }

        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        Ok(AuthenticationOptions { options, state })
    }

    /// Verifies an authentication response and updates the credential in
    /// place (counter, backup flags, last-used time). The caller must persist
    /// the updated credential.
    ///
    /// `state` must be the [`PasskeyAuthentication`] returned from
    /// [`start_authentication`](Self::start_authentication) for this session.
    pub fn finish_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &PasskeyAuthentication,
        credential: &mut PasskeyCredential,
    ) -> AuthResult<AuthenticationResult> {
        if credential.disabled {
            return Err(AuthError::CredentialDisabled);
        }

        // webauthn-rs verifies the signature, challenge, origin and counter
        // (a counter regression fails verification internally).
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(response, state)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        if auth_result.cred_id() != credential.passkey.cred_id() {
            return Err(AuthError::CredentialNotFound);
        }

        // Update the stored passkey with the new counter / backup state.
        credential.passkey.update_credential(&auth_result);
        credential.counter = auth_result.counter();
        credential.backup_eligible = auth_result.backup_eligible();
        credential.backup_state = auth_result.backup_state();
        credential.last_used_at = Some(Utc::now());

        Ok(auth_result)
    }
}
