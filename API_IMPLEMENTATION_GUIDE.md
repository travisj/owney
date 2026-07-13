# Passwordless Auth API - Implementation Guide

Complete guide for implementing the REST API layer for passwordless authentication.

## Architecture

### API Endpoints

```
POST   /auth/passkey/register/start          → Registration challenge
POST   /auth/passkey/register/finish         → Save credential
POST   /auth/passkey/authenticate/start      → Authentication challenge
POST   /auth/passkey/authenticate/finish     → Verify assertion, return token

POST   /auth/recovery/generate               → Generate recovery codes
POST   /auth/recovery/use                    → Use recovery code for login

POST   /auth/approval/create                 → Create approval request
GET    /auth/approval/{request_id}           → Check approval status
POST   /auth/approval/{request_id}/approve   → Approve from device

GET    /auth/pairing/qr                      → Generate QR code
POST   /auth/pairing/confirm                 → Confirm pairing
```

### Data Flow

```
Browser                 API Server                  Database
  │                        │                           │
  ├─ POST /register/start ─>│                           │
  │                        ├─ Generate challenge       │
  │                        ├─ Store challenge ────────>│
  │<─ Return options ──────┤                           │
  │                        │                           │
  ├─ Create credential ───────────────────────────────>│
  │   (in browser)         │                           │
  │                        │                           │
  ├─ POST /register/finish ─>│                          │
  │   (credential)         ├─ Verify attestation      │
  │                        ├─ Store credential ──────>│
  │<─ Success ─────────────┤                          │
```

## Implementation Steps

### Step 1: Challenge Storage

Implement temporary storage for WebAuthn challenges (5-15 minute TTL).

**Options**:
1. **Redis** (recommended) - Fast, TTL built-in
2. **In-memory HashMap** - Simple, requires TTL thread
3. **Database** - Slower but durable

**Example with Redis**:
```rust
pub struct ChallengeStore {
    redis: redis::Connection,
}

impl ChallengeStore {
    pub fn store(&self, session_id: &str, challenge: &[u8]) -> Result<()> {
        self.redis.set_ex(
            format!("challenge:{}", session_id),
            challenge,
            600,  // 10 minute TTL
        )?;
        Ok(())
    }

    pub fn retrieve(&self, session_id: &str) -> Result<Vec<u8>> {
        self.redis.get(format!("challenge:{}", session_id))
            .ok_or(AuthError::ChallengeMismatch)
    }
}
```

**Example with in-memory**:
```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct InMemoryChallengeStore {
    challenges: Arc<RwLock<HashMap<String, (Vec<u8>, u64)>>>,
}

impl InMemoryChallengeStore {
    pub async fn store(&self, session_id: &str, challenge: Vec<u8>) -> Result<()> {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() + 600;  // 10 min
        
        self.challenges.write().await.insert(
            session_id.to_string(),
            (challenge, expires_at),
        );
        Ok(())
    }

    pub async fn retrieve(&self, session_id: &str) -> Result<Vec<u8>> {
        let mut challenges = self.challenges.write().await;
        
        if let Some((challenge, expires_at)) = challenges.get(session_id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();
                
            if now > *expires_at {
                challenges.remove(session_id);
                return Err(AuthError::ChallengeMismatch);
            }
            
            let challenge = challenge.clone();
            challenges.remove(session_id);
            return Ok(challenge);
        }
        
        Err(AuthError::ChallengeMismatch)
    }
}
```

### Step 2: Database Schema Migration

Add to `owney-storage/src/migrations.rs`:

```rust
// Migration: Add passkey tables
r#"
CREATE TABLE passkey_credentials (
    id BLOB PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN DEFAULT 0,
    backup_state BOOLEAN DEFAULT 0,
    aaguid BLOB,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    disabled BOOLEAN DEFAULT 0,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE INDEX idx_passkey_account ON passkey_credentials(account_id);
CREATE INDEX idx_passkey_disabled ON passkey_credentials(disabled);

CREATE TABLE recovery_codes (
    id BLOB PRIMARY KEY,
    account_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    display_code TEXT NOT NULL,
    used BOOLEAN DEFAULT 0,
    used_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE INDEX idx_recovery_account ON recovery_codes(account_id);
CREATE INDEX idx_recovery_used ON recovery_codes(used);

CREATE TABLE device_pairings (
    id BLOB PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    public_key BLOB NOT NULL,
    can_approve BOOLEAN DEFAULT 1,
    push_token TEXT,
    paired_at INTEGER NOT NULL,
    last_used_at INTEGER,
    disabled BOOLEAN DEFAULT 0,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
CREATE INDEX idx_pairing_account ON device_pairings(account_id);

CREATE TABLE approval_requests (
    id BLOB PRIMARY KEY,
    account_id TEXT NOT NULL,
    source_device TEXT NOT NULL,
    request_type TEXT NOT NULL,
    challenge TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    approved_by_device BLOB,
    approved_at INTEGER,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (approved_by_device) REFERENCES device_pairings(id)
);
CREATE INDEX idx_approval_account ON approval_requests(account_id);
CREATE INDEX idx_approval_expires ON approval_requests(expires_at);
"#,
```

### Step 3: Storage Layer Methods

Add to `owney-storage/src/lib.rs`:

```rust
impl Storage {
    // Passkey methods
    pub async fn save_passkey_credential(
        &self,
        credential: &PasskeyCredential,
    ) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO passkey_credentials 
                     (id, account_id, device_name, public_key, counter, 
                      backup_eligible, backup_state, aaguid, created_at) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rusqlite::params![
                        credential.id.0.as_slice(),
                        credential.account_id,
                        credential.device_name,
                        credential.public_key.as_slice(),
                        credential.counter,
                        credential.backup_eligible,
                        credential.backup_state,
                        credential.aaguid.as_slice(),
                        chrono::Utc::now().timestamp(),
                    ],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    pub async fn get_passkey_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, StorageError> {
        let id = credential_id.to_vec();
        self.db
            .call(move |conn| {
                conn.query_row(
                    "SELECT id, account_id, device_name, public_key, counter, 
                            backup_eligible, backup_state, aaguid, created_at, last_used_at
                     FROM passkey_credentials 
                     WHERE id = ?1 AND disabled = 0",
                    rusqlite::params![id.as_slice()],
                    |row| {
                        Ok(PasskeyCredential {
                            id: CredentialId(row.get(0)?),
                            account_id: row.get(1)?,
                            device_name: row.get(2)?,
                            public_key: row.get(3)?,
                            counter: row.get(4)?,
                            backup_eligible: row.get(5)?,
                            backup_state: row.get(6)?,
                            aaguid: row.get(7)?,
                            created_at: chrono::DateTime::from_timestamp(
                                row.get::<_, i64>(8)?,
                                0,
                            )
                            .unwrap(),
                            last_used_at: row
                                .get::<_, Option<i64>>(9)?
                                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
                            disabled: false,
                        })
                    },
                )
                .optional()
                .map_err(|e| StorageError::Database(e.to_string()))
            })
            .await
    }

    pub async fn list_passkeys_for_account(
        &self,
        account_id: String,
    ) -> Result<Vec<PasskeyCredential>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, account_id, device_name, public_key, counter, 
                                backup_eligible, backup_state, aaguid, created_at, last_used_at
                         FROM passkey_credentials 
                         WHERE account_id = ?1 AND disabled = 0",
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                let credentials = stmt
                    .query_map(rusqlite::params![account_id], |row| {
                        Ok(PasskeyCredential {
                            id: CredentialId(row.get(0)?),
                            account_id: row.get(1)?,
                            device_name: row.get(2)?,
                            public_key: row.get(3)?,
                            counter: row.get(4)?,
                            backup_eligible: row.get(5)?,
                            backup_state: row.get(6)?,
                            aaguid: row.get(7)?,
                            created_at: chrono::DateTime::from_timestamp(
                                row.get::<_, i64>(8)?,
                                0,
                            )
                            .unwrap(),
                            last_used_at: row
                                .get::<_, Option<i64>>(9)?
                                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
                            disabled: false,
                        })
                    })
                    .map_err(|e| StorageError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                Ok(credentials)
            })
            .await
    }

    pub async fn update_passkey_counter(
        &self,
        credential_id: &[u8],
        new_counter: u32,
    ) -> Result<(), StorageError> {
        let id = credential_id.to_vec();
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE passkey_credentials 
                     SET counter = ?1, last_used_at = ?2
                     WHERE id = ?3",
                    rusqlite::params![new_counter, chrono::Utc::now().timestamp(), id.as_slice()],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }

    // Recovery code methods
    pub async fn save_recovery_codes(
        &self,
        account_id: String,
        codes: &[RecoveryCode],
    ) -> Result<(), StorageError> {
        let codes = codes.to_vec();
        self.db
            .call(move |conn| {
                for code in &codes {
                    conn.execute(
                        "INSERT INTO recovery_codes 
                         (id, account_id, code_hash, display_code, used, created_at)
                         VALUES (?, ?, ?, ?, ?, ?)",
                        rusqlite::params![
                            code.id.0.as_bytes(),
                            account_id,
                            code.code_hash,
                            code.display_code,
                            0,  // not used yet
                            chrono::Utc::now().timestamp(),
                        ],
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;
                }
                Ok(())
            })
            .await
    }

    pub async fn get_recovery_codes(
        &self,
        account_id: String,
    ) -> Result<Vec<RecoveryCode>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, account_id, code_hash, display_code, used, used_at, created_at
                         FROM recovery_codes 
                         WHERE account_id = ?1
                         ORDER BY created_at DESC",
                    )
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                let codes = stmt
                    .query_map(rusqlite::params![account_id], |row| {
                        Ok(RecoveryCode {
                            id: RecoveryCodeId(uuid::Uuid::from_bytes(
                                row.get::<_, Vec<u8>>(0)?
                                    .try_into()
                                    .unwrap_or_default(),
                            )),
                            account_id: row.get(1)?,
                            code_hash: row.get(2)?,
                            display_code: row.get(3)?,
                            used: row.get(4)?,
                            used_at: row
                                .get::<_, Option<i64>>(5)?
                                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
                            created_at: chrono::DateTime::from_timestamp(
                                row.get::<_, i64>(6)?,
                                0,
                            )
                            .unwrap(),
                        })
                    })
                    .map_err(|e| StorageError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Database(e.to_string()))?;

                Ok(codes)
            })
            .await
    }

    pub async fn mark_recovery_code_used(
        &self,
        code_id: uuid::Uuid,
    ) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE recovery_codes 
                     SET used = 1, used_at = ?1
                     WHERE id = ?2",
                    rusqlite::params![chrono::Utc::now().timestamp(), code_id.as_bytes()],
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
                Ok(())
            })
            .await
    }
}
```

### Step 4: Session Token Generation

Add to `owney-api/src/auth.rs`:

```rust
use owney_core::Config;
use chrono::{Duration, Utc};

pub fn generate_session_token(
    account_id: &str,
    ttl_hours: i64,
) -> String {
    use sha2::{Sha256, Digest};
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    
    let mut hasher = Sha256::new();
    hasher.update(&random_bytes);
    hasher.update(account_id.as_bytes());
    hasher.update(Utc::now().timestamp().to_string());
    
    hex::encode(hasher.finalize())
}

pub struct SessionToken {
    pub token: String,
    pub account_id: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
}

impl SessionToken {
    pub fn new(account_id: String, ttl_hours: i64) -> Self {
        let now = Utc::now();
        Self {
            token: generate_session_token(&account_id, ttl_hours),
            account_id,
            expires_at: now + Duration::hours(ttl_hours),
            created_at: now,
        }
    }

    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}
```

### Step 5: Error Response Handling

Errors are already converted to HTTP responses in `auth.rs` via the `IntoResponse` trait. Extend as needed:

```rust
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // Already implemented in auth.rs
        // Add more specific error codes as needed
    }
}
```

## Implementation Checklist

### Phase 1: Passkey Registration/Authentication
- [ ] Implement `passkey_registration_start`
- [ ] Implement `passkey_registration_finish`
- [ ] Implement `passkey_authentication_start`
- [ ] Implement `passkey_authentication_finish`
- [ ] Add challenge storage (Redis or in-memory)
- [ ] Store credentials in database
- [ ] Generate session tokens
- [ ] Test with browser WebAuthn

### Phase 2: Recovery Codes
- [ ] Implement `recovery_code_generate`
- [ ] Implement `recovery_code_use`
- [ ] Store/retrieve recovery codes from database
- [ ] Mark codes as used
- [ ] Test recovery flow

### Phase 3: Cross-Device Approval
- [ ] Implement `approval_request_create`
- [ ] Implement `approval_request_status`
- [ ] Implement `approval_request_approve`
- [ ] Integrate push notifications (FCM/APNS)
- [ ] Test approval flow

### Phase 4: QR Code Pairing
- [ ] Implement `qr_code_pairing`
- [ ] Implement `qr_code_pairing_confirm`
- [ ] Test with mobile app

### Phase 5: Integration & Testing
- [ ] Wire auth routes into main router
- [ ] Add authentication middleware (verify session token)
- [ ] Integration tests for full flows
- [ ] Cross-browser testing
- [ ] Security audit

## Example: Passkey Registration Implementation

```rust
pub async fn passkey_registration_start(
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<PasskeyRegistrationStartRequest>,
) -> Result<Json<PasskeyRegistrationStartResponse>, AuthError> {
    // Validate email
    if !req.email.contains('@') {
        return Err(AuthError::Config("Invalid email".to_string()));
    }

    // Generate registration challenge
    let reg_opts = auth_state
        .passkey_manager
        .start_registration(
            req.email.clone(),
            req.email,
        )?;

    // Generate session ID
    let session_id = uuid::Uuid::new_v7().to_string();

    // Store challenge (TODO: use challenge store)
    // challenge_store.store(&session_id, &reg_opts.challenge_bytes)?;

    Ok(Json(PasskeyRegistrationStartResponse {
        options: serde_json::to_value(reg_opts.options)?,
        session_id,
    }))
}

pub async fn passkey_registration_finish(
    State(auth_state): State<Arc<AuthState>>,
    State(storage): State<Arc<Storage>>,
    Json(req): Json<PasskeyRegistrationFinishRequest>,
) -> Result<Json<PasskeyRegistrationFinishResponse>, AuthError> {
    // Retrieve challenge (TODO: use challenge store)
    // let challenge = challenge_store.retrieve(&req.session_id)?;

    // Parse client response
    let response: RegistrationResponse = serde_json::from_value(req.credential)
        .map_err(|_| AuthError::WebAuthn("Invalid credential".to_string()))?;

    // Verify registration
    let credential = auth_state
        .passkey_manager
        .finish_registration(
            "account_id".to_string(),  // TODO: get from email
            req.device_name,
            response,
            Vec::new(),  // TODO: actual challenge
        )?;

    // Store credential
    // storage.save_passkey_credential(&credential).await?;

    Ok(Json(PasskeyRegistrationFinishResponse {
        success: true,
        message: "Passkey registered successfully".to_string(),
    }))
}
```

## Testing

### Unit Tests

```rust
#[tokio::test]
async fn test_passkey_registration_flow() {
    let config = PasswordlessAuthConfig::new(...);
    let auth_state = Arc::new(AuthState::new(&config).unwrap());

    // Test registration start
    let start_req = PasskeyRegistrationStartRequest {
        email: "alice@example.com".to_string(),
    };
    // ... test response

    // Test registration finish
    let finish_req = PasskeyRegistrationFinishRequest {
        session_id: "...".to_string(),
        device_name: "iPhone".to_string(),
        credential: serde_json::json!({...}),
    };
    // ... test response
}

#[tokio::test]
async fn test_recovery_code_generation_and_use() {
    // Test generating codes
    // Test storing in database
    // Test using a code
    // Test code cannot be reused
}
```

## Next Steps

1. Implement challenge storage (Redis preferred for production)
2. Add database schema migrations
3. Implement storage layer methods
4. Implement each API endpoint
5. Add integration tests
6. Wire auth routes into main router
7. Add authentication middleware
8. Test with actual browsers and mobile devices

---

See `PASSWORDLESS_AUTH.md` for full context on the authentication system.
