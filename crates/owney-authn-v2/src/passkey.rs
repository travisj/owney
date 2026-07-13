use crate::error::AuthError;
use crate::{CredentialId, PasswordlessAuthConfig, AuthResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::{prelude::*, WebauthnBuilder};

/// A registered passkey credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: CredentialId,
    pub account_id: String,
    pub device_name: String,  // "iPhone", "MacBook Pro", etc.
    pub public_key: Vec<u8>,  // COSE key encoded
    pub counter: u32,         // FIDO2 counter (prevents cloning)
    pub backup_eligible: bool, // Can be backed up to cloud
    pub backup_state: bool,    // Currently backed up
    pub aaguid: Vec<u8>,      // Authenticator AAGUID
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub disabled: bool,
}

/// WebAuthn registration challenge and options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub options: CreationChallengeResponse,
    pub challenge_bytes: Vec<u8>,
    pub user_id: Vec<u8>,
}

/// WebAuthn registration response from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: RegisterPublicKeyCredentialResponse,
    pub client_extension_results: AuthenticatorExtensionsClientOutputs,
    pub transports: Option<Vec<String>>,
}

/// WebAuthn authentication challenge and options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    pub options: RequestChallengeResponse,
    pub challenge_bytes: Vec<u8>,
}

/// WebAuthn authentication response from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: AuthenticatorAssertionResponse,
    pub client_extension_results: AuthenticatorExtensionsClientOutputs,
}

/// Manages passkey operations (registration, authentication, credential storage).
pub struct PasskeyManager {
    webauthn: Webauthn,
    config: PasswordlessAuthConfig,
}

impl PasskeyManager {
    /// Creates a new PasskeyManager with the given configuration.
    pub fn new(config: PasswordlessAuthConfig) -> AuthResult<Self> {
        let rp_id = config.rp_id.clone();
        let origins: Vec<Url> = config
            .origins
            .iter()
            .filter_map(|origin| Url::parse(origin).ok())
            .collect();

        if origins.is_empty() {
            return Err(AuthError::Config("No valid origins configured".to_string()));
        }

        let webauthn = WebauthnBuilder::new(&rp_id, &origins[0])
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        Ok(Self { webauthn, config })
    }

    /// Generates a registration challenge for enrolling a new passkey.
    pub fn start_registration(
        &self,
        account_id: String,
        user_email: String,
    ) -> AuthResult<RegistrationOptions> {
        let user_id = Uuid::new_v7().as_bytes().to_vec();

        let (cc_state, reg_state) = self
            .webauthn
            .start_passkey_registration(&user_id, &user_email, &user_email, None)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        let challenge_bytes = cc_state.public_key.challenge.as_ref().to_vec();

        Ok(RegistrationOptions {
            options: cc_state,
            challenge_bytes,
            user_id,
        })
    }

    /// Verifies a registration response and returns the credential to be stored.
    pub fn finish_registration(
        &self,
        account_id: String,
        device_name: String,
        response: RegistrationResponse,
        challenge_bytes: Vec<u8>,
    ) -> AuthResult<PasskeyCredential> {
        // Reconstruct the challenge from stored bytes
        let challenge = RegisterPublicKeyCredentialResponse {
            id: response.id,
            raw_id: response.raw_id.clone(),
            response: response.response,
            transports: None,
            type_: "public-key".to_string(),
        };

        // Verify the response
        let auth_result = self
            .webauthn
            .finish_passkey_registration(&challenge, &WebauthnBuilder::new(&self.config.rp_id, &self.config.origins[0]).build().map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?.start_passkey_registration(&challenge_bytes, "").map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?.1)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        // Extract credential details
        let cred_id = CredentialId(response.raw_id);
        let public_key = auth_result.cred.cred_public_key.to_vec();
        let backup_eligible = auth_result.backup_eligible;
        let backup_state = auth_result.backup_state;
        let aaguid = auth_result.cred.aaguid.to_vec();

        Ok(PasskeyCredential {
            id: cred_id,
            account_id,
            device_name,
            public_key,
            counter: 0,
            backup_eligible,
            backup_state,
            aaguid,
            created_at: Utc::now(),
            last_used_at: None,
            disabled: false,
        })
    }

    /// Generates an authentication challenge for a passkey login.
    pub fn start_authentication(&self) -> AuthResult<AuthenticationOptions> {
        let (req_state, auth_state) = self
            .webauthn
            .start_passkey_authentication(&[])
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        let challenge_bytes = req_state.public_key.challenge.as_ref().to_vec();

        Ok(AuthenticationOptions {
            options: req_state,
            challenge_bytes,
        })
    }

    /// Verifies an authentication response and validates the credential.
    pub fn finish_authentication(
        &self,
        response: AuthenticationResponse,
        credential: &mut PasskeyCredential,
        challenge_bytes: Vec<u8>,
    ) -> AuthResult<()> {
        // Reconstruct the assertion from the response
        let assertion = AuthenticatorAssertionResponse {
            client_data_json: response.response.client_data_json,
            authenticator_data: response.response.authenticator_data,
            signature: response.response.signature,
            user_handle: response.response.user_handle,
        };

        // Rebuild credential for verification
        let webauthn_credential = webauthn_rs::prelude::Credential {
            cred_public_key: webauthn_rs::prelude::CredentialPublicKey::new(
                &credential.public_key,
            )
            .map_err(|_| AuthError::InvalidCredentialId)?,
            counter: credential.counter,
            cred_id: response.raw_id.clone(),
            transports: None,
            user_verified: true,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            registration_policy: UserVerificationPolicy::Preferred,
            extensions: RegisteredExtensions::default(),
            user_id: Vec::new(),
            credential_device_type: webauthn_rs::prelude::CredentialDeviceType::SingleDevice,
            attestation_format: AttestationFormat::None,
            attestation_data: AttestationData::None,
        };

        // Verify the assertion
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(&response.raw_id.as_ref().try_into().map_err(|_| AuthError::InvalidCredentialId())?, &assertion, &webauthn_credential.cred)
            .map_err(|e| AuthError::WebAuthn(format!("{:?}", e)))?;

        // Check counter for cloning attacks
        if auth_result.counter() <= credential.counter {
            return Err(AuthError::CounterRollback);
        }

        // Update counter and last used time
        credential.counter = auth_result.counter();
        credential.last_used_at = Some(Utc::now());

        Ok(())
    }
}

impl Default for RegisterPublicKeyCredentialResponse {
    fn default() -> Self {
        Self {
            client_data_json: Vec::new(),
            attestation_object: Vec::new(),
        }
    }
}

impl Default for AuthenticatorAssertionResponse {
    fn default() -> Self {
        Self {
            client_data_json: Vec::new(),
            authenticator_data: Vec::new(),
            signature: Vec::new(),
            user_handle: None,
        }
    }
}
