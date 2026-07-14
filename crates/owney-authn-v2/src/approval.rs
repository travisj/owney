use crate::error::AuthError;
use crate::{ApprovalRequestId, AuthResult, DevicePairingId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A cross-device approval request (e.g., "approve login on web from phone").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: ApprovalRequestId,
    pub account_id: String,
    pub source_device: String, // "San Francisco, CA (IP: 192.0.2.1)"
    pub request_type: ApprovalRequestType,
    pub challenge: String, // Cryptographic challenge
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub approved_by_device: Option<DevicePairingId>,
    pub approved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalRequestType {
    WebLogin,
    DesktopLogin,
    AppLogin,
    DeviceEnrollment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// A paired device (phone, tablet, etc.) that can approve requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    pub id: DevicePairingId,
    pub account_id: String,
    pub device_name: String,     // "Alice's iPhone 15"
    pub device_type: DeviceType, // Mobile, Tablet, Desktop
    pub public_key: Vec<u8>,     // For signature verification
    pub can_approve: bool,
    pub push_token: Option<String>, // FCM token for Android, APNS for iOS
    pub paired_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Mobile,
    Tablet,
    Desktop,
    Laptop,
}

/// Manages cross-device approval requests.
#[derive(Debug)]
pub struct CrossDeviceApprovalManager;

impl CrossDeviceApprovalManager {
    /// Creates a new approval request.
    pub fn create_request(
        account_id: String,
        source_device: String,
        request_type: ApprovalRequestType,
        ttl_secs: u64,
    ) -> AuthResult<ApprovalRequest> {
        let challenge = Self::generate_challenge();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_secs as i64);

        Ok(ApprovalRequest {
            id: ApprovalRequestId(Uuid::now_v7()),
            account_id,
            source_device,
            request_type,
            challenge,
            created_at: now,
            expires_at,
            status: ApprovalStatus::Pending,
            approved_by_device: None,
            approved_at: None,
        })
    }

    /// Approves a request from a paired device.
    pub fn approve_request(
        request: &mut ApprovalRequest,
        approved_by: DevicePairingId,
    ) -> AuthResult<()> {
        // Check if already processed
        if request.status != ApprovalStatus::Pending {
            return Err(AuthError::ApprovalAlreadyProcessed);
        }

        // Check expiration
        if Utc::now() > request.expires_at {
            request.status = ApprovalStatus::Expired;
            return Err(AuthError::ApprovalRequestExpired);
        }

        // Mark as approved
        request.status = ApprovalStatus::Approved;
        request.approved_by_device = Some(approved_by);
        request.approved_at = Some(Utc::now());

        Ok(())
    }

    /// Denies an approval request.
    pub fn deny_request(request: &mut ApprovalRequest) -> AuthResult<()> {
        // Check if already processed
        if request.status != ApprovalStatus::Pending {
            return Err(AuthError::ApprovalAlreadyProcessed);
        }

        request.status = ApprovalStatus::Denied;
        Ok(())
    }

    /// Checks if a request is still valid and pending.
    pub fn is_valid(request: &ApprovalRequest) -> bool {
        request.status == ApprovalStatus::Pending && Utc::now() <= request.expires_at
    }

    /// Generates a cryptographic challenge for the approval.
    fn generate_challenge() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let challenge: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        hex::encode(challenge)
    }

    /// Gets a device-friendly description of the request.
    pub fn describe_request(request: &ApprovalRequest) -> String {
        let type_str = match request.request_type {
            ApprovalRequestType::WebLogin => "Web login",
            ApprovalRequestType::DesktopLogin => "Desktop login",
            ApprovalRequestType::AppLogin => "App login",
            ApprovalRequestType::DeviceEnrollment => "Enroll new device",
        };

        format!(
            "{} from {}\n(Valid for 5 minutes)",
            type_str, request.source_device
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_approval_request() {
        let req = CrossDeviceApprovalManager::create_request(
            "user@example.com".to_string(),
            "San Francisco (192.0.2.1)".to_string(),
            ApprovalRequestType::WebLogin,
            300,
        )
        .unwrap();

        assert_eq!(req.status, ApprovalStatus::Pending);
        assert!(CrossDeviceApprovalManager::is_valid(&req));
    }

    #[test]
    fn test_approve_request() {
        let mut req = CrossDeviceApprovalManager::create_request(
            "user@example.com".to_string(),
            "San Francisco (192.0.2.1)".to_string(),
            ApprovalRequestType::WebLogin,
            300,
        )
        .unwrap();

        let device_id = DevicePairingId(Uuid::now_v7());
        CrossDeviceApprovalManager::approve_request(&mut req, device_id).unwrap();

        assert_eq!(req.status, ApprovalStatus::Approved);
        assert_eq!(req.approved_by_device, Some(device_id));
    }

    #[test]
    fn test_cannot_approve_twice() {
        let mut req = CrossDeviceApprovalManager::create_request(
            "user@example.com".to_string(),
            "San Francisco (192.0.2.1)".to_string(),
            ApprovalRequestType::WebLogin,
            300,
        )
        .unwrap();

        let device_id = DevicePairingId(Uuid::now_v7());
        CrossDeviceApprovalManager::approve_request(&mut req, device_id).unwrap();

        // Second approval fails
        let result =
            CrossDeviceApprovalManager::approve_request(&mut req, DevicePairingId(Uuid::now_v7()));
        assert!(matches!(result, Err(AuthError::ApprovalAlreadyProcessed)));
    }
}
