//! Calendar federation discovery and protocol.
//!
//! Supports cross-server calendar sharing with:
//! - Well-known endpoint discovery (/.well-known/owney/server)
//! - DNS fallback (_owney._tcp SRV records)
//! - Account lookup by email
//! - Federated invitation protocol

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::MarshalInto;
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
    /// This server's public federation identity cert (ASCII-armored). Peers
    /// encrypt events to it and verify its request signatures against it.
    #[serde(default)]
    pub public_cert: Option<String>,
    /// Fingerprint of `public_cert`, for pinning.
    #[serde(default)]
    pub fingerprint: Option<String>,
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

/// Federation invitation sent to remote server. The receiver binds inviter
/// identity to the authenticated sending server (the signed request), so the
/// `inviter_*` fields here are advisory metadata, not trusted identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationInvitation {
    /// Shared federation handle minted by the serving (inviter) server.
    pub federation_id: String,
    /// Capability secret gating the serve/notify path for this federation.
    pub capability_secret: String,
    pub calendar_name: String,
    pub inviter_email: String,
    pub target_email: String,
    pub sharing_type: String, // "sharing" or "delegation"
    pub created_at: i64,
}

/// Well-known server discovery protocol
#[derive(Debug)]
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
                Ok(_) => continue,  // Try next candidate
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
            reqwest::StatusCode::OK => resp
                .json::<AccountInfo>()
                .await
                .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string())),
            reqwest::StatusCode::NOT_FOUND => {
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
            reqwest::StatusCode::OK => {
                let body: HashMap<String, String> = resp
                    .json()
                    .await
                    .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))?;
                body.get("invitation_id")
                    .cloned()
                    .ok_or_else(|| DiscoveryError::InvalidMetadata("missing invitation_id".into()))
            }
            _ => Err(DiscoveryError::InvitationFailed(resp.status().to_string())),
        }
    }
}

/// Candidate well-known URLs to try for a domain, in order.
pub fn server_candidates(domain: &str) -> Vec<String> {
    vec![
        format!("https://{domain}/.well-known/owney/server"),
        format!("https://mail.{domain}/.well-known/owney/server"),
        format!("https://owney.{domain}/.well-known/owney/server"),
    ]
}

/// Build a signing federation client for *this* server (loads/creates the
/// server identity cert). `public_url` is this server's own base URL.
pub async fn build_client(
    storage: &owney_storage::Storage,
    public_url: &str,
    config: &crate::fed_sig::FederationConfig,
) -> Result<crate::fed_sig::FederationClient, DiscoveryError> {
    let domain = crate::fed_sig::host_of(public_url);
    let cert = owney_pgp::server_cert(storage, &domain)
        .await
        .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))?;
    Ok(crate::fed_sig::FederationClient::new(cert, domain, config))
}

/// Discover a peer server for `domain`, fetch its public federation cert over a
/// TLS-authenticated (SSRF-guarded) request, and pin it. This is the trust
/// bootstrap. A fingerprint that differs from an existing pin is a hostile
/// key-swap and is rejected without overwriting the pin.
pub async fn discover_and_pin(
    storage: &owney_storage::Storage,
    client: &crate::fed_sig::FederationClient,
    domain: &str,
    config: &crate::fed_sig::FederationConfig,
) -> Result<owney_storage::PeerServer, DiscoveryError> {
    if !config.domain_allowed(domain) {
        return Err(DiscoveryError::NotFound(format!(
            "{domain} not allowlisted"
        )));
    }

    for url in server_candidates(domain) {
        let resp = match client.get_unsigned(&url).await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let meta: ServerMetadata = match resp.json().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let armored = meta
            .public_cert
            .ok_or_else(|| DiscoveryError::InvalidMetadata("peer has no public_cert".into()))?;
        let cert = sequoia_openpgp::Cert::from_bytes(armored.as_bytes())
            .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))?;
        let fingerprint = cert.fingerprint().to_hex();

        // Reject a key-swap without overwriting the existing pin.
        if let Some(existing) = storage
            .federation_peer(domain)
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?
            && existing.fingerprint != fingerprint
        {
            tracing::error!(
                %domain,
                old = %existing.fingerprint,
                new = %fingerprint,
                "federation peer cert fingerprint changed — refusing (possible key-swap)"
            );
            return Err(DiscoveryError::InvalidMetadata(
                "peer cert fingerprint changed".into(),
            ));
        }

        let bin = cert
            .strip_secret_key_material()
            .to_vec()
            .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))?;
        storage
            .upsert_federation_peer(domain, &meta.server_url, bin, &fingerprint)
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?;

        return storage
            .federation_peer(domain)
            .await
            .map_err(|e| DiscoveryError::NetworkError(e.to_string()))?
            .ok_or_else(|| DiscoveryError::NetworkError("pin vanished".into()));
    }

    Err(DiscoveryError::NotFound(domain.to_string()))
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
