# Auth Module Integration Guide

How to wire up the passwordless authentication API into the Owney mailserver.

## Overview

The auth module provides REST endpoints for:
- Passkey registration and authentication
- Recovery code generation and usage
- Cross-device approval requests
- QR code device pairing

This guide shows how to integrate it into the existing API server.

## Integration Steps

### Step 1: Initialize Auth State

In `bin/owneyd/src/main.rs`, add auth state initialization:

```rust
use owney_api::auth::AuthState;

async fn serve(config: Config) -> anyhow::Result<()> {
    // ... existing code ...

    // Initialize authentication state
    let auth_state = Arc::new(
        AuthState::new(&config)
            .context("initializing authentication")?,
    );

    tracing::info!("passwordless authentication enabled");

    // ... rest of serve function ...
}
```

### Step 2: Wire Auth Routes into Main Router

In `crates/owney-api/src/lib.rs`, update the router function:

```rust
use crate::auth;

pub fn router(state: Arc<ApiState>) -> Router {
    let static_dir = std::env::var("UI_STATIC_DIR")
        .unwrap_or_else(|_| "./static".to_string());

    // Create auth state
    let auth_state = Arc::new(
        auth::AuthState::new(&state.config) // pass config from ApiState
            .expect("failed to initialize auth"),
    );

    Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/jmap", get(session))
        .route("/jmap/api", post(api))
        .route("/jmap/eventsource", get(push::eventsource))
        .route("/jmap/ws", get(push::websocket))
        // ... existing routes ...
        .nest("/", auth::auth_routes().with_state(auth_state))  // Add auth routes
        .fallback(ServeDir::new(&static_dir).append_index_html_on_directories(true))
        .with_state(state)
}
```

### Step 3: Add Authentication Middleware

Create middleware to verify session tokens:

```rust
// In crates/owney-api/src/auth.rs

use axum::middleware::Next;
use axum::response::Response;

/// Extracts account from session token in Authorization header.
pub async fn require_auth(
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid Bearer token".to_string()))?;

    // TODO: Verify token and extract account ID
    // let account = verify_session_token(token)?;
    // req.extensions_mut().insert(account);

    Ok(next.run(req).await)
}
```

### Step 4: Protect API Endpoints with Middleware

Protected endpoints should require the middleware:

```rust
// In owney-api/src/auth.rs

pub fn auth_routes_protected() -> Router<Arc<AuthState>> {
    Router::new()
        .route("/auth/recovery/generate", post(recovery_code_generate))
        .route("/auth/recovery/use", post(recovery_code_use))
        .layer(axum::middleware::from_fn(require_auth))
}

pub fn auth_routes() -> Router<Arc<AuthState>> {
    Router::new()
        // Public endpoints (no auth required)
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
        .route("/auth/pairing/qr", get(qr_code_pairing))
        .route("/auth/pairing/confirm", post(qr_code_pairing_confirm))
        .merge(auth_routes_protected())  // Add protected endpoints
}
```

### Step 5: Update Configuration

In `crates/owney-core/src/config.rs`, add auth config:

```rust
use owney_authn_v2::PasswordlessAuthConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub smtp: SmtpConfig,
    pub tls: Option<TlsConfig>,
    pub acme: Option<AcmeConfigSection>,
    pub delivery: DeliveryConfig,
    pub api: ApiConfig,
    pub ai: AiSection,
    pub imap: ImapConfig,
    pub spam: SpamConfig,
    pub log: LogConfig,
    #[serde(default)]
    pub auth: AuthSection,  // Add this
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AuthSection {
    /// Enable passwordless authentication
    pub enabled: bool,
    /// Recovery codes per account
    pub recovery_code_count: usize,
    /// Cross-device approval TTL in seconds
    pub approval_ttl: u64,
    /// Maximum pending approvals per account
    pub max_pending_approvals: usize,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            enabled: true,
            recovery_code_count: 10,
            approval_ttl: 300,  // 5 minutes
            max_pending_approvals: 5,
        }
    }
}
```

### Step 6: Update mailserver.toml Example

```toml
[server]
domain = "example.com"
hostname = "mail.example.com"

# ... other sections ...

[auth]
enabled = true
recovery_code_count = 10
approval_ttl = 300
max_pending_approvals = 5
```

## API Usage Examples

### Registering a Passkey

```bash
# Step 1: Get registration options
curl -X POST http://localhost:8008/auth/passkey/register/start \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'

# Response:
{
  "options": {
    "challenge": "...",
    "rp": {"name": "Owney Mailserver", "id": "mail.example.com"},
    "user": {"id": "...", "name": "alice@example.com", "displayName": "alice@example.com"},
    ...
  },
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}

# Step 2: Create credential in browser
# navigator.credentials.create(options) → credential

# Step 3: Send credential to server
curl -X POST http://localhost:8008/auth/passkey/register/finish \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "device_name": "iPhone 15 Pro",
    "credential": {...}
  }'

# Response:
{
  "success": true,
  "message": "Passkey registered successfully"
}
```

### Authenticating with Passkey

```bash
# Step 1: Get authentication options
curl -X POST http://localhost:8008/auth/passkey/authenticate/start \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'

# Response:
{
  "options": {
    "challenge": "...",
    "timeout": 60000,
    "rpId": "mail.example.com",
    ...
  },
  "session_id": "550e8400-e29b-41d4-a716-446655440001"
}

# Step 2: Get assertion from browser
# navigator.credentials.get(options) → assertion

# Step 3: Send assertion to server
curl -X POST http://localhost:8008/auth/passkey/authenticate/finish \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "550e8400-e29b-41d4-a716-446655440001",
    "credential": {...}
  }'

# Response:
{
  "success": true,
  "session_token": "abc123def456...",
  "user_id": "alice@example.com"
}

# Step 4: Use session token for authenticated requests
curl -H "Authorization: Bearer abc123def456..." \
  http://localhost:8008/auth/recovery/generate
```

### Generating Recovery Codes

```bash
# Must be authenticated
curl -X POST http://localhost:8008/auth/recovery/generate \
  -H "Authorization: Bearer <session_token>" \
  -H "Content-Type: application/json" \
  -d '{"count": 10}'

# Response:
{
  "codes": [
    "AB12-CD34-EF56",
    "GH78-IJ90-KL12",
    ...
  ],
  "display_format": "XXXX-XXXX-XXXX"
}

# User prints or exports these codes for secure storage
```

### Using Recovery Code to Login

```bash
curl -X POST http://localhost:8008/auth/recovery/use \
  -H "Content-Type: application/json" \
  -d '{"recovery_code": "AB12-CD34-EF56"}'

# Response:
{
  "success": true,
  "session_token": "abc123def456...",
  "message": "Logged in with recovery code"
}
```

### Creating Cross-Device Approval

```bash
# Request approval from another device
curl -X POST http://localhost:8008/auth/approval/create \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "web_login",
    "source_device": "San Francisco, CA (192.0.2.1)"
  }'

# Response:
{
  "request_id": "550e8400-e29b-41d4-a716-446655440002",
  "expires_in_seconds": 300,
  "message": "Push notifications sent to enrolled devices"
}

# Client polls for approval status
curl http://localhost:8008/auth/approval/550e8400-e29b-41d4-a716-446655440002

# Response (pending):
{
  "status": "pending",
  "approved_by_device": null,
  "approved_at": null
}

# (after user approves on device)
# Response (approved):
{
  "status": "approved",
  "approved_by_device": "550e8400-e29b-41d4-a716-446655440003",
  "approved_at": 1700000000
}
```

### Generating QR Code for Mobile Pairing

```bash
# Get QR code for terminal
curl http://localhost:8008/auth/pairing/qr

# Response:
{
  "qr_code": "█████████...[Unicode QR]...█████████",
  "pairing_code": "ABCDEF123456",
  "expires_in_seconds": 120
}

# Mobile app scans QR
# Mobile sends confirmation
curl -X POST http://localhost:8008/auth/pairing/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "pairing_code": "ABCDEF123456",
    "device_name": "Alice's iPhone"
  }'

# Response:
{
  "success": true,
  "device_id": "550e8400-e29b-41d4-a716-446655440004"
}
```

## Implementation Checklist

### Core Integration
- [ ] Add `owney-authn-v2` to `owney-api` dependencies
- [ ] Add `auth` module to `owney-api/src/lib.rs`
- [ ] Wire auth routes into main router
- [ ] Initialize AuthState in `serve()` function
- [ ] Add configuration section to `owney-core`
- [ ] Update example `mailserver.toml`

### Middleware & Security
- [ ] Implement `require_auth` middleware
- [ ] Implement session token verification
- [ ] Add protected/public endpoint separation
- [ ] Add rate limiting for approval requests
- [ ] Add rate limiting for login attempts

### Storage Integration
- [ ] Add database migrations
- [ ] Implement storage layer methods (see `API_IMPLEMENTATION_GUIDE.md`)
- [ ] Implement challenge storage (Redis or in-memory)
- [ ] Add tests for database operations

### Endpoint Implementation
- [ ] Passkey registration start/finish
- [ ] Passkey authentication start/finish
- [ ] Recovery code generation/usage
- [ ] Cross-device approval create/status/approve
- [ ] QR code pairing start/confirm

### Testing
- [ ] Unit tests for all handlers
- [ ] Integration tests for full flows
- [ ] Security tests (token expiration, rate limiting)
- [ ] Cross-browser testing with real WebAuthn

## Next Phase: Mobile App Integration

Once the API is working:
1. Mobile app implements QR scanning
2. Mobile app calls `/auth/pairing/confirm`
3. Mobile app receives and registers passkeys
4. Mobile app sends push notification credentials
5. Mobile app handles approval notifications

See `PASSWORDLESS_AUTH.md` for full mobile integration details.

---

**Current Status**: REST API endpoints scaffolded. Ready for implementation.
