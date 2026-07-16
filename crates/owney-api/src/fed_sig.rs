//! Signed-request layer for federation. Every federation HTTP request is
//! authenticated with a detached PGP signature by the *sending server's*
//! identity key over a rigid canonical string. The receiver verifies against
//! the pinned peer cert, enforces a timestamp window, and rejects replayed
//! nonces. There is no unauthenticated path.
//!
//! Peers are pinned out-of-band (during discovery/handshake, over a
//! TLS-authenticated fetch), never mid-request — so `verify_request` fails
//! closed for an unknown sender rather than triggering an outbound fetch.

use std::collections::HashMap;
use std::net::IpAddr;

use axum::http::{HeaderMap, StatusCode};
use base64::Engine;
use owney_pgp::ops::{sign_detached, verify_detached};
use owney_storage::Storage;
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;

/// Canonical-string format version (bump if the signed fields change).
pub const SIG_VERSION: &str = "1";
/// Accepted clock skew for request timestamps, in seconds.
pub const TIMESTAMP_SKEW_SECS: i64 = 300;
/// Header names.
pub const H_VERSION: &str = "x-owney-sig-version";
pub const H_SERVER: &str = "x-owney-server";
pub const H_TIMESTAMP: &str = "x-owney-timestamp";
pub const H_NONCE: &str = "x-owney-nonce";
pub const H_SIGNATURE: &str = "x-owney-signature";
/// Per-federation capability secret, presented on serve/notify requests. A
/// second factor beside the server signature: the signature proves *which
/// server*, the capability proves *this specific share*.
pub const H_CAPABILITY: &str = "x-owney-capability";

/// Per-instance federation configuration. Production builds this with
/// [`FederationConfig::from_env`]; tests construct it explicitly (there is no
/// global env dependency, so two servers can run in one process).
#[derive(Debug, Clone, Default)]
pub struct FederationConfig {
    /// Whether the federation endpoints are mounted at all.
    pub enabled: bool,
    /// Allow http/loopback targets (dev/test only). Production stays https-only.
    pub allow_private_ips: bool,
    /// Logical-domain → transport-base-URL overrides (dev/test only).
    pub url_overrides: HashMap<String, String>,
    /// If set, only these domains may federate.
    pub allowlist: Option<Vec<String>>,
}

impl FederationConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("OWNEY_FEDERATION_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let allow_private_ips = std::env::var("OWNEY_FEDERATION_ALLOW_PRIVATE_IPS")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        let url_overrides = parse_url_overrides();
        let allowlist = std::env::var("OWNEY_FEDERATION_ALLOWLIST")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.split(',').map(|d| d.trim().to_lowercase()).collect());
        Self {
            enabled,
            allow_private_ips,
            url_overrides,
            allowlist,
        }
    }

    /// Whether `domain` is permitted to federate under this config.
    pub fn domain_allowed(&self, domain: &str) -> bool {
        match &self.allowlist {
            Some(list) => {
                let d = domain.trim().to_lowercase();
                list.iter().any(|a| a == &d)
            }
            None => true,
        }
    }
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Build the canonical string that gets signed. Fixed field order, newline
/// joined; binds method, target, both endpoints, freshness, and body.
fn canonical_string(
    method: &str,
    path_and_query: &str,
    sender_domain: &str,
    receiver_host: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let digest = b64().encode(blake3::hash(body).as_bytes());
    format!(
        "owney-fed-v{SIG_VERSION}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path_and_query,
        sender_domain,
        receiver_host,
        timestamp,
        nonce,
        digest,
    )
}

/// A caller whose signature verified against a pinned peer cert.
#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    pub domain: String,
    pub fingerprint: String,
}

/// Why a federation request was rejected. Rendered as an HTTP status; the body
/// is deliberately terse so it can't be used as an oracle.
#[derive(Debug)]
pub enum Rejection {
    MissingSignature,
    UnknownPeer,
    BadSignature,
    StaleTimestamp,
    Replay,
    Malformed,
}

impl Rejection {
    pub fn status(&self) -> StatusCode {
        match self {
            Rejection::MissingSignature | Rejection::BadSignature | Rejection::UnknownPeer => {
                StatusCode::UNAUTHORIZED
            }
            Rejection::StaleTimestamp | Rejection::Replay | Rejection::Malformed => {
                StatusCode::BAD_REQUEST
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Rejection::MissingSignature => "missing signature",
            Rejection::UnknownPeer => "unknown peer",
            Rejection::BadSignature => "bad signature",
            Rejection::StaleTimestamp => "stale timestamp",
            Rejection::Replay => "replay",
            Rejection::Malformed => "malformed",
        }
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Host portion of a public URL, used as the `receiver_host` in the canonical
/// string so a signature can't be replayed to a different server.
pub fn host_of(public_url: &str) -> String {
    reqwest::Url::parse(public_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| public_url.to_owned())
}

/// Verify an inbound federation request. On success returns the authenticated
/// peer. Fails closed for anything missing, malformed, stale, replayed, or from
/// a peer we have not pinned. `public_url` is this server's own base URL (its
/// host is bound into the canonical string).
pub async fn verify_request(
    storage: &Storage,
    public_url: &str,
    method: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<VerifiedPeer, Rejection> {
    let version = header(headers, H_VERSION).ok_or(Rejection::MissingSignature)?;
    if version != SIG_VERSION {
        return Err(Rejection::Malformed);
    }
    let sender_domain = header(headers, H_SERVER)
        .ok_or(Rejection::MissingSignature)?
        .trim()
        .to_lowercase();
    let timestamp: i64 = header(headers, H_TIMESTAMP)
        .and_then(|t| t.parse().ok())
        .ok_or(Rejection::Malformed)?;
    let nonce = header(headers, H_NONCE).ok_or(Rejection::MissingSignature)?;
    let sig_b64 = header(headers, H_SIGNATURE).ok_or(Rejection::MissingSignature)?;
    let sig = b64().decode(sig_b64).map_err(|_| Rejection::Malformed)?;

    // Freshness first (cheap) — symmetric window, also rejects future stamps.
    if (now_secs() - timestamp).abs() > TIMESTAMP_SKEW_SECS {
        return Err(Rejection::StaleTimestamp);
    }

    // The sender must be a peer we have already pinned (out-of-band, over TLS).
    let peer = storage
        .federation_peer(&sender_domain)
        .await
        .map_err(|_| Rejection::Malformed)?
        .ok_or(Rejection::UnknownPeer)?;
    let peer_cert = Cert::from_bytes(&peer.cert).map_err(|_| Rejection::UnknownPeer)?;

    let canonical = canonical_string(
        method,
        path_and_query,
        &sender_domain,
        &host_of(public_url),
        timestamp,
        nonce,
        body,
    );
    let valid = verify_detached(&peer_cert, canonical.as_bytes(), &sig).unwrap_or(false);
    if !valid {
        return Err(Rejection::BadSignature);
    }

    // Replay: record the nonce; a duplicate within the window is a replay.
    let expires_at = now_secs() + TIMESTAMP_SKEW_SECS;
    let fresh = storage
        .check_and_record_nonce(&peer.fingerprint, nonce, expires_at)
        .await
        .map_err(|_| Rejection::Malformed)?;
    if !fresh {
        return Err(Rejection::Replay);
    }

    Ok(VerifiedPeer {
        domain: sender_domain,
        fingerprint: peer.fingerprint,
    })
}

/// Client for making *outbound* signed federation requests over a hardened HTTP
/// client (https-only, SSRF-guarded). Holds this server's signing cert.
pub struct FederationClient {
    http: reqwest::Client,
    server_cert: Cert,
    our_domain: String,
    allow_private_ips: bool,
    /// Logical-domain → transport-base-URL overrides (dev/test only), from
    /// `OWNEY_FEDERATION_URL_OVERRIDES` (e.g. `a.test=http://127.0.0.1:9000`).
    /// Requests keep signing over the logical domain; only the wire target is
    /// rewritten, so identity and signatures are unaffected.
    url_overrides: HashMap<String, String>,
}

/// Parse `OWNEY_FEDERATION_URL_OVERRIDES` ("dom=url,dom2=url2") into a map.
fn parse_url_overrides() -> HashMap<String, String> {
    std::env::var("OWNEY_FEDERATION_URL_OVERRIDES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .filter_map(|pair| pair.split_once('='))
                .map(|(d, u)| (d.trim().to_lowercase(), u.trim().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

impl std::fmt::Debug for FederationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the signing cert (secret material).
        f.debug_struct("FederationClient")
            .field("our_domain", &self.our_domain)
            .field("allow_private_ips", &self.allow_private_ips)
            .finish_non_exhaustive()
    }
}

impl FederationClient {
    pub fn new(server_cert: Cert, our_domain: String, config: &FederationConfig) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            http,
            server_cert,
            our_domain,
            allow_private_ips: config.allow_private_ips,
            url_overrides: config.url_overrides.clone(),
        }
    }

    /// Apply a transport override to `url`, keeping its path and query. Returns
    /// the URL unchanged when the host has no override.
    fn override_target(&self, url: &reqwest::Url) -> Result<reqwest::Url, FederationClientError> {
        let host = url.host_str().unwrap_or("").to_lowercase();
        match self.url_overrides.get(&host) {
            Some(base) => {
                let mut target = format!("{}{}", base.trim_end_matches('/'), url.path());
                if let Some(q) = url.query() {
                    target.push('?');
                    target.push_str(q);
                }
                reqwest::Url::parse(&target).map_err(|_| FederationClientError::BadUrl)
            }
            None => Ok(url.clone()),
        }
    }

    /// Signed GET. `receiver_host` is the peer's domain (bound into the sig).
    pub async fn get(
        &self,
        url: &str,
        receiver_host: &str,
    ) -> Result<reqwest::Response, FederationClientError> {
        self.send("GET", url, receiver_host, None, None).await
    }

    /// Signed GET that also presents a federation capability secret.
    pub async fn get_capable(
        &self,
        url: &str,
        receiver_host: &str,
        capability: &str,
    ) -> Result<reqwest::Response, FederationClientError> {
        self.send("GET", url, receiver_host, None, Some(capability))
            .await
    }

    /// Unsigned GET over the hardened (SSRF-guarded, https-only) client. Used
    /// only for the discovery bootstrap — fetching a peer's public server
    /// metadata, whose trust comes from TLS-authenticating the domain, not from
    /// a signature we could not yet verify.
    pub async fn get_unsigned(
        &self,
        url: &str,
    ) -> Result<reqwest::Response, FederationClientError> {
        let parsed = reqwest::Url::parse(url).map_err(|_| FederationClientError::BadUrl)?;
        let target = self.override_target(&parsed)?;
        guard_url(&target, self.allow_private_ips).await?;
        self.http
            .get(target)
            .send()
            .await
            .map_err(|e| FederationClientError::Network(e.to_string()))
    }

    /// Signed POST of a JSON body.
    pub async fn post_json(
        &self,
        url: &str,
        receiver_host: &str,
        body: &[u8],
    ) -> Result<reqwest::Response, FederationClientError> {
        self.send("POST", url, receiver_host, Some(body), None)
            .await
    }

    /// Signed POST that also presents a federation capability secret.
    pub async fn post_json_capable(
        &self,
        url: &str,
        receiver_host: &str,
        body: &[u8],
        capability: &str,
    ) -> Result<reqwest::Response, FederationClientError> {
        self.send("POST", url, receiver_host, Some(body), Some(capability))
            .await
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        receiver_host: &str,
        body: Option<&[u8]>,
        capability: Option<&str>,
    ) -> Result<reqwest::Response, FederationClientError> {
        let parsed = reqwest::Url::parse(url).map_err(|_| FederationClientError::BadUrl)?;
        // Sign over the logical path/query; send to the (possibly overridden)
        // transport target.
        let path_and_query = canonical_path(&parsed);
        let target = self.override_target(&parsed)?;
        guard_url(&target, self.allow_private_ips).await?;

        let body = body.unwrap_or(&[]);
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let timestamp = now_secs();
        let canonical = canonical_string(
            method,
            &path_and_query,
            &self.our_domain,
            receiver_host,
            timestamp,
            &nonce,
            body,
        );
        let sig = sign_detached(&self.server_cert, canonical.as_bytes())
            .map_err(|e| FederationClientError::Sign(e.to_string()))?;

        let mut req = match method {
            "GET" => self.http.get(target),
            "POST" => self.http.post(target).body(body.to_vec()),
            _ => return Err(FederationClientError::BadUrl),
        };
        req = req
            .header(H_VERSION, SIG_VERSION)
            .header(H_SERVER, &self.our_domain)
            .header(H_TIMESTAMP, timestamp.to_string())
            .header(H_NONCE, nonce)
            .header(H_SIGNATURE, b64().encode(&sig));
        if let Some(cap) = capability {
            req = req.header(H_CAPABILITY, cap);
        }
        if body.is_empty() {
            // no content-type
        } else {
            req = req.header("content-type", "application/json");
        }
        req.send()
            .await
            .map_err(|e| FederationClientError::Network(e.to_string()))
    }
}

/// Path + query in the exact form used in the canonical string. Query pairs are
/// sorted so signer and verifier agree regardless of map ordering.
pub fn canonical_path(url: &reqwest::Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.sort();
    let path = url.path();
    if pairs.is_empty() {
        path.to_string()
    } else {
        let q = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        format!("{path}?{q}")
    }
}

/// Canonicalize a server-side request target (`/path?query`) to the exact form
/// the client signed. Sorts the query so both sides agree.
pub fn canonical_path_str(path_and_query: &str) -> String {
    match reqwest::Url::parse(&format!("http://placeholder{path_and_query}")) {
        Ok(url) => canonical_path(&url),
        Err(_) => path_and_query.to_string(),
    }
}

/// SSRF guard: https only, no credentials, and no target that resolves to a
/// private/loopback/link-local address (unless explicitly allowed for tests).
async fn guard_url(url: &reqwest::Url, allow_private: bool) -> Result<(), FederationClientError> {
    // Production requires https. Dev/test (allow_private) may use http against
    // loopback so a two-server integration test needs no TLS.
    if url.scheme() != "https" && !(allow_private && url.scheme() == "http") {
        return Err(FederationClientError::Blocked("non-https url"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FederationClientError::Blocked("url has credentials"));
    }
    if allow_private {
        return Ok(());
    }
    let host = url.host_str().ok_or(FederationClientError::BadUrl)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| FederationClientError::Blocked("dns resolution failed"))?;
    let mut any = false;
    for addr in addrs {
        any = true;
        if is_private(addr.ip()) {
            return Err(FederationClientError::Blocked("private address"));
        }
    }
    if !any {
        return Err(FederationClientError::Blocked("no address"));
    }
    Ok(())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // Carrier-grade NAT 100.64.0.0/10.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique local fc00::/7.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: check the embedded v4.
                || v6.to_ipv4_mapped().map(|m| is_private(IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

#[derive(Debug)]
pub enum FederationClientError {
    BadUrl,
    Blocked(&'static str),
    Sign(String),
    Network(String),
}

impl std::fmt::Display for FederationClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FederationClientError::BadUrl => write!(f, "bad url"),
            FederationClientError::Blocked(why) => write!(f, "blocked: {why}"),
            FederationClientError::Sign(e) => write!(f, "sign error: {e}"),
            FederationClientError::Network(e) => write!(f, "network error: {e}"),
        }
    }
}

impl std::error::Error for FederationClientError {}

/// Constant-time byte comparison, for capability secrets. Avoids leaking match
/// length via early return.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_path_sorts_query() {
        let url = reqwest::Url::parse("https://b.test/sync/x?since=5&token=abc").unwrap();
        assert_eq!(canonical_path(&url), "/sync/x?since=5&token=abc");
        let url2 = reqwest::Url::parse("https://b.test/sync/x?token=abc&since=5").unwrap();
        assert_eq!(canonical_path(&url2), canonical_path(&url));
    }

    #[test]
    fn ssrf_guard_blocks_http_and_private() {
        // Non-https rejected regardless of host.
        let http = reqwest::Url::parse("http://example.com/x").unwrap();
        let r = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(guard_url(&http, false));
        assert!(matches!(r, Err(FederationClientError::Blocked(_))));

        // Credentials rejected.
        let creds = reqwest::Url::parse("https://user:pass@example.com/x").unwrap();
        let r = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(guard_url(&creds, false));
        assert!(matches!(r, Err(FederationClientError::Blocked(_))));
    }

    #[test]
    fn private_ip_ranges_detected() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_private(ip), "{s} should be private");
        }
        for s in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_private(ip), "{s} should be public");
        }
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreX"));
        assert!(!constant_time_eq(b"secret", b"secre"));
    }

    // ---- verify_request against a real storage boundary ------------------

    use sequoia_openpgp::serialize::MarshalInto;

    async fn storage() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = Storage::open(dir.path(), owney_events::EventBus::new(8)).expect("open");
        (dir, s)
    }

    /// Build the headers a legitimate sender `a.test` would attach.
    fn signed_headers(
        sender_cert: &Cert,
        sender_domain: &str,
        receiver_host: &str,
        method: &str,
        path: &str,
        timestamp: i64,
        nonce: &str,
        body: &[u8],
    ) -> HeaderMap {
        let canonical = canonical_string(
            method,
            path,
            sender_domain,
            receiver_host,
            timestamp,
            nonce,
            body,
        );
        let sig = sign_detached(sender_cert, canonical.as_bytes()).expect("sign");
        let mut h = HeaderMap::new();
        h.insert(H_VERSION, SIG_VERSION.parse().unwrap());
        h.insert(H_SERVER, sender_domain.parse().unwrap());
        h.insert(H_TIMESTAMP, timestamp.to_string().parse().unwrap());
        h.insert(H_NONCE, nonce.parse().unwrap());
        h.insert(H_SIGNATURE, b64().encode(&sig).parse().unwrap());
        h
    }

    async fn pin_sender(storage: &Storage, cert: &Cert, domain: &str) {
        // Pin the public cert (verify_request parses with Cert::from_bytes).
        let bin = cert
            .clone()
            .strip_secret_key_material()
            .to_vec()
            .expect("to_vec");
        storage
            .upsert_federation_peer(domain, "https://a.test", bin, &cert.fingerprint().to_hex())
            .await
            .expect("pin");
    }

    #[tokio::test]
    async fn verify_request_accepts_valid_and_rejects_variants() {
        let (_dir, storage) = storage().await;
        let sender = owney_pgp::generate_cert("federation@a.test", Some("a.test")).expect("cert");
        pin_sender(&storage, &sender, "a.test").await;

        let our_url = "https://b.test";
        let host = host_of(our_url);
        let method = "GET";
        let path = "/.well-known/owney/calendar/sync/fed1?since=0";
        let ts = now_secs();

        // Valid request verifies.
        let h = signed_headers(&sender, "a.test", &host, method, path, ts, "nonceA", b"");
        let peer = verify_request(&storage, our_url, method, path, &h, b"")
            .await
            .expect("valid");
        assert_eq!(peer.domain, "a.test");

        // Replay of the same nonce is rejected.
        let err = verify_request(&storage, our_url, method, path, &h, b"")
            .await
            .expect_err("replay");
        assert!(matches!(err, Rejection::Replay));

        // Missing signature header.
        let mut h2 = h.clone();
        h2.remove(H_SIGNATURE);
        assert!(matches!(
            verify_request(&storage, our_url, method, path, &h2, b"").await,
            Err(Rejection::MissingSignature)
        ));

        // Tampered path (signature was over a different path).
        let h3 = signed_headers(&sender, "a.test", &host, method, path, ts, "nonceB", b"");
        assert!(matches!(
            verify_request(&storage, our_url, method, "/evil/path", &h3, b"").await,
            Err(Rejection::BadSignature)
        ));

        // Stale timestamp.
        let h4 = signed_headers(
            &sender,
            "a.test",
            &host,
            method,
            path,
            ts - (TIMESTAMP_SKEW_SECS + 60),
            "nonceC",
            b"",
        );
        assert!(matches!(
            verify_request(&storage, our_url, method, path, &h4, b"").await,
            Err(Rejection::StaleTimestamp)
        ));

        // Unknown peer domain (never pinned).
        let h5 = signed_headers(
            &sender,
            "unknown.test",
            &host,
            method,
            path,
            ts,
            "nonceD",
            b"",
        );
        assert!(matches!(
            verify_request(&storage, our_url, method, path, &h5, b"").await,
            Err(Rejection::UnknownPeer)
        ));

        storage.close();
    }
}
