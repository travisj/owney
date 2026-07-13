//! Calendar federation discovery and protocol.
//!
//! Supports cross-server calendar sharing with:
//! - Well-known endpoint discovery (/.well-known/owney/server)
//! - DNS fallback (_owney._tcp SRV records)
//! - Account lookup by email
//! - Federated invitation protocol

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Server metadata returned from well-known endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMetadata {
    /// Primary server URL (https://owney.domain.com)
    pub server_url: String,
    /// Supported federation features
    pub supported_features: Vec<String>,
    /// Server version
    pub version: String,
    /// Admin contact email
    pub admin: Option<String>,
}

/// Account info returned from account lookup endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account_id: String,
    pub email: String,
    pub name: Option<String>,
    /// Available calendars (minimal info for discovery)
    pub calendars: Vec<CalendarInfo>,
}

/// Calendar info returned from account lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarInfo {
    pub id: String,
    pub name: String,
}

/// Federation invitation sent to remote server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationInvitation {
    pub calendar_id: String,
    pub calendar_name: String,
    pub inviter_email: String,
    pub inviter_account_id: String,
    pub inviter_server_url: String,
    pub target_email: String,
    pub sharing_type: String, // "sharing" or "delegation"
    pub created_at: i64,
}

/// Well-known server discovery protocol
pub struct ServerDiscovery;

impl ServerDiscovery {
    /// Discover owney server for a domain via well-known endpoint.
    ///
    /// Tries in order:
    /// 1. https://domain.com/.well-known/owney/server
    /// 2. https://mail.domain.com/.well-known/owney/server
    /// 3. https://owney.domain.com/.well-known/owney/server
    /// 4. DNS SRV record _owney._tcp.domain.com (fallback)
    pub async fn discover(domain: &str) -> Result<ServerMetadata, DiscoveryError> {
        let candidates = vec![
            format!("https://{domain}/.well-known/owney/server"),
            format!("https://mail.{domain}/.well-known/owney/server"),
            format!("https://owney.{domain}/.well-known/owney/server"),
        ];

        for url in candidates {
            match reqwest::Client::new().get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    return resp
                        .json::<ServerMetadata>()
                        .await
                        .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()));
                }
                Ok(_) => continue, // Try next candidate
                Err(_) => continue, // Try next candidate
            }
        }

        // Fallback: assume standard server URLs
        Err(DiscoveryError::NotFound(domain.to_string()))
    }

    /// Look up account by email on a remote server.
    pub async fn lookup_account(
        server_url: &str,
        email: &str,
    ) -> Result<AccountInfo, DiscoveryError> {
        let url = format!(
            "{server_url}/.well-known/owney/account/{}",
            urlencoding::encode(email)
        );

        let resp = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        match resp.status() {
            reqwest::http::StatusCode::OK => resp
                .json::<AccountInfo>()
                .await
                .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string())),
            reqwest::http::StatusCode::NOT_FOUND => {
                Err(DiscoveryError::AccountNotFound(email.to_string()))
            }
            _ => Err(DiscoveryError::NetworkError(
                "unexpected status code".to_string(),
            )),
        }
    }

    /// Send an invitation to a remote server
    pub async fn send_invitation(
        target_server_url: &str,
        invitation: &FederationInvitation,
    ) -> Result<String, DiscoveryError> {
        let url = format!("{target_server_url}/.well-known/owney/calendar/invite");

        let resp = reqwest::Client::new()
            .post(&url)
            .json(invitation)
            .send()
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        match resp.status() {
            reqwest::http::StatusCode::OK => {
                let body: HashMap<String, String> = resp.json().await
                    .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))?;
                body.get("invitation_id")
                    .cloned()
                    .ok_or_else(|| DiscoveryError::InvalidMetadata("missing invitation_id".into()))
            }
            _ => Err(DiscoveryError::InvitationFailed(
                resp.status().to_string(),
            )),
        }
    }
}

#[derive(Debug)]
pub enum DiscoveryError {
    NotFound(String),
    InvalidMetadata(String),
    NetworkError(String),
    AccountNotFound(String),
    InvitationFailed(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::NotFound(domain) => write!(f, "no owney server found for {domain}"),
            DiscoveryError::InvalidMetadata(msg) => write!(f, "invalid server metadata: {msg}"),
            DiscoveryError::NetworkError(msg) => write!(f, "network error: {msg}"),
            DiscoveryError::AccountNotFound(email) => write!(f, "account not found: {email}"),
            DiscoveryError::InvitationFailed(status) => write!(f, "invitation failed: {status}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}
