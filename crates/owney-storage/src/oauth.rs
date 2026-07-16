//! OAuth/OIDC provider persistence: registered clients, remembered consent
//! grants, and rotating refresh tokens with family reuse-detection.
//!
//! Secret conventions follow tokens.rs: plaintext returned exactly once with
//! a prefix (`mcs_` client secrets, `mrt_` refresh tokens), only the BLAKE3
//! hash at rest. Refresh tokens rotate on use; presenting an already-rotated
//! token is treated as theft and revokes the whole family plus any access
//! tokens it minted.

use owney_core::{AccountId, OAuthClientId};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::error::StorageError;
use crate::{Storage, unix_now};

const CLIENT_SECRET_PREFIX: &str = "mcs_";
const REFRESH_PREFIX: &str = "mrt_";

#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub id: OAuthClientId,
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// True when no secret is registered (public client, PKCE-only).
    pub public: bool,
    pub disabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct OAuthGrant {
    pub account_id: AccountId,
    pub client_id: OAuthClientId,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenRow {
    pub token_hash: String,
    pub family_id: String,
    pub account_id: AccountId,
    pub client_id: OAuthClientId,
    pub scopes: Vec<String>,
    pub access_token_hash: Option<String>,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}

fn new_secret(prefix: &str) -> Result<(String, String), StorageError> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| StorageError::Crypto("os rng"))?;
    let plaintext = format!("{prefix}{}", crate::tokens::hex(&secret));
    let hash = blake3::hash(plaintext.as_bytes()).to_hex().to_string();
    Ok((plaintext, hash))
}

fn split_scopes(scopes: &str) -> Vec<String> {
    scopes.split_whitespace().map(str::to_owned).collect()
}

fn row_to_client(row: &rusqlite::Row<'_>) -> Result<OAuthClient, rusqlite::Error> {
    let corrupt = |i: usize, err: String| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    };
    let id: String = row.get(0)?;
    let uris: String = row.get(2)?;
    let secret_hash: Option<String> = row.get(3)?;
    Ok(OAuthClient {
        id: id.parse().map_err(|e| corrupt(0, format!("{e}")))?,
        name: row.get(1)?,
        redirect_uris: serde_json::from_str(&uris).map_err(|e| corrupt(2, format!("{e}")))?,
        public: secret_hash.is_none(),
        disabled: row.get::<_, i64>(4)? != 0,
        created_at: row.get(5)?,
    })
}

const CLIENT_COLUMNS: &str = "id, name, redirect_uris, secret_hash, disabled, created_at";

fn row_to_refresh(row: &rusqlite::Row<'_>) -> Result<RefreshTokenRow, rusqlite::Error> {
    let corrupt = |i: usize, err: String| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    };
    let account_id: String = row.get(2)?;
    let client_id: String = row.get(3)?;
    let scopes: String = row.get(4)?;
    Ok(RefreshTokenRow {
        token_hash: row.get(0)?,
        family_id: row.get(1)?,
        account_id: account_id.parse().map_err(|e| corrupt(2, format!("{e}")))?,
        client_id: client_id.parse().map_err(|e| corrupt(3, format!("{e}")))?,
        scopes: split_scopes(&scopes),
        access_token_hash: row.get(5)?,
        expires_at: row.get(6)?,
        used_at: row.get(7)?,
        revoked_at: row.get(8)?,
        created_at: row.get(9)?,
    })
}

const REFRESH_COLUMNS: &str = "token_hash, family_id, account_id, client_id, scopes, \
     access_token_hash, expires_at, used_at, revoked_at, created_at";

fn validate_redirect_uris(uris: &[String]) -> Result<(), StorageError> {
    if uris.is_empty() {
        return Err(StorageError::BadInput(
            "at least one redirect URI is required".into(),
        ));
    }
    for uri in uris {
        let scheme_ok = uri.starts_with("https://") || uri.starts_with("http://");
        if !scheme_ok || uri.contains('#') || uri.len() > 2000 {
            return Err(StorageError::BadInput(format!(
                "bad redirect URI {uri:?}: must be absolute http(s) without a fragment"
            )));
        }
    }
    Ok(())
}

impl Storage {
    /// Register a client. Confidential clients get a `mcs_` secret returned
    /// exactly once; public clients (PKCE-only) get None.
    pub async fn create_oauth_client(
        &self,
        name: &str,
        redirect_uris: &[String],
        public: bool,
    ) -> Result<(OAuthClient, Option<String>), StorageError> {
        if name.is_empty() || name.len() > 200 {
            return Err(StorageError::BadInput("name must be 1-200 chars".into()));
        }
        validate_redirect_uris(redirect_uris)?;

        let (secret_plain, secret_hash) = if public {
            (None, None)
        } else {
            let (plain, hash) = new_secret(CLIENT_SECRET_PREFIX)?;
            (Some(plain), Some(hash))
        };
        let id = OAuthClientId::new();
        let name = name.to_owned();
        let uris = serde_json::to_string(redirect_uris)
            .map_err(|e| StorageError::BadInput(e.to_string()))?;
        let client = self
            .db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO oauth_clients
                       (id, name, redirect_uris, secret_hash, disabled, created_at)
                     VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                    params![id.to_string(), name, uris, secret_hash, unix_now()],
                )?;
                conn.query_row(
                    &format!("SELECT {CLIENT_COLUMNS} FROM oauth_clients WHERE id = ?1"),
                    [id.to_string()],
                    row_to_client,
                )
                .map_err(StorageError::from)
            })
            .await?;
        Ok((client, secret_plain))
    }

    pub async fn oauth_client(
        &self,
        id: OAuthClientId,
    ) -> Result<Option<OAuthClient>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        &format!("SELECT {CLIENT_COLUMNS} FROM oauth_clients WHERE id = ?1"),
                        [id.to_string()],
                        row_to_client,
                    )
                    .optional()?)
            })
            .await
    }

    /// BLAKE3(candidate) vs stored hash — hash-then-compare is the
    /// codebase's timing-safe pattern. False for public/disabled clients.
    pub async fn verify_oauth_client_secret(
        &self,
        id: OAuthClientId,
        secret: &str,
    ) -> Result<bool, StorageError> {
        let candidate = blake3::hash(secret.as_bytes()).to_hex().to_string();
        self.db
            .call(move |conn| {
                let stored: Option<Option<String>> = conn
                    .query_row(
                        "SELECT secret_hash FROM oauth_clients
                         WHERE id = ?1 AND disabled = 0",
                        [id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(matches!(stored, Some(Some(hash)) if hash == candidate))
            })
            .await
    }

    pub async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {CLIENT_COLUMNS} FROM oauth_clients ORDER BY created_at"
                ))?;
                let rows = stmt
                    .query_map([], row_to_client)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    /// Disable a client and revoke everything it issued (refresh families +
    /// access tokens), in one transaction.
    pub async fn disable_oauth_client(&self, id: OAuthClientId) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let changed = tx.execute(
                    "UPDATE oauth_clients SET disabled = 1 WHERE id = ?1",
                    [id.to_string()],
                )?;
                if changed == 0 {
                    return Err(StorageError::BadInput("no such client".into()));
                }
                tx.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = ?2
                     WHERE client_id = ?1 AND revoked_at IS NULL",
                    params![id.to_string(), unix_now()],
                )?;
                tx.execute(
                    "DELETE FROM app_passwords WHERE oauth_client_id = ?1",
                    [id.to_string()],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Record consent; scopes are unioned so consent only ever widens by an
    /// explicit approval, never narrows silently.
    pub async fn upsert_oauth_grant(
        &self,
        account_id: AccountId,
        client_id: OAuthClientId,
        scopes: &[String],
    ) -> Result<(), StorageError> {
        let scopes: Vec<String> = scopes.to_vec();
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT scopes FROM oauth_grants
                         WHERE account_id = ?1 AND client_id = ?2",
                        params![account_id.to_string(), client_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                let mut merged: Vec<String> =
                    existing.as_deref().map(split_scopes).unwrap_or_default();
                for scope in &scopes {
                    if !merged.contains(scope) {
                        merged.push(scope.clone());
                    }
                }
                merged.sort();
                let now = unix_now();
                tx.execute(
                    "INSERT INTO oauth_grants
                       (id, account_id, client_id, scopes, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                     ON CONFLICT (account_id, client_id) DO UPDATE SET
                       scopes = excluded.scopes, updated_at = excluded.updated_at",
                    params![
                        Uuid::now_v7().to_string(),
                        account_id.to_string(),
                        client_id.to_string(),
                        merged.join(" "),
                        now,
                    ],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn oauth_grant(
        &self,
        account_id: AccountId,
        client_id: OAuthClientId,
    ) -> Result<Option<OAuthGrant>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT scopes, created_at, updated_at FROM oauth_grants
                         WHERE account_id = ?1 AND client_id = ?2",
                        params![account_id.to_string(), client_id.to_string()],
                        |row| {
                            let scopes: String = row.get(0)?;
                            Ok(OAuthGrant {
                                account_id,
                                client_id,
                                scopes: split_scopes(&scopes),
                                created_at: row.get(1)?,
                                updated_at: row.get(2)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    pub async fn list_oauth_grants(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<OAuthGrant>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT client_id, scopes, created_at, updated_at FROM oauth_grants
                     WHERE account_id = ?1 ORDER BY created_at",
                )?;
                let rows = stmt
                    .query_map([account_id.to_string()], |row| {
                        let client_id: String = row.get(0)?;
                        let scopes: String = row.get(1)?;
                        Ok((client_id, scopes, row.get(2)?, row.get(3)?))
                    })?
                    .collect::<Result<Vec<(String, String, i64, i64)>, _>>()?;
                rows.into_iter()
                    .map(|(client_id, scopes, created_at, updated_at)| {
                        Ok(OAuthGrant {
                            account_id,
                            client_id: client_id.parse().map_err(|_| {
                                StorageError::Corrupt(format!("bad client id {client_id}"))
                            })?,
                            scopes: split_scopes(&scopes),
                            created_at,
                            updated_at,
                        })
                    })
                    .collect()
            })
            .await
    }

    /// Revoke consent: delete the grant, revoke the client's refresh
    /// families for this account, and delete its access tokens — one tx.
    pub async fn revoke_oauth_grant(
        &self,
        account_id: AccountId,
        client_id: OAuthClientId,
    ) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let deleted = tx.execute(
                    "DELETE FROM oauth_grants WHERE account_id = ?1 AND client_id = ?2",
                    params![account_id.to_string(), client_id.to_string()],
                )?;
                if deleted == 0 {
                    return Err(StorageError::BadInput("no such grant".into()));
                }
                tx.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = ?3
                     WHERE account_id = ?1 AND client_id = ?2 AND revoked_at IS NULL",
                    params![account_id.to_string(), client_id.to_string(), unix_now()],
                )?;
                tx.execute(
                    "DELETE FROM app_passwords
                     WHERE account_id = ?1 AND oauth_client_id = ?2",
                    params![account_id.to_string(), client_id.to_string()],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Mint a refresh token; `family_id = None` starts a new rotation family.
    /// Returns the `mrt_` plaintext exactly once.
    pub async fn create_refresh_token(
        &self,
        account_id: AccountId,
        client_id: OAuthClientId,
        scopes: &[String],
        family_id: Option<String>,
        access_token_hash: Option<String>,
        expires_at: i64,
    ) -> Result<String, StorageError> {
        let (plaintext, hash) = new_secret(REFRESH_PREFIX)?;
        let family = family_id.unwrap_or_else(|| Uuid::now_v7().to_string());
        let scopes = scopes.join(" ");
        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO oauth_refresh_tokens
                       (token_hash, family_id, account_id, client_id, scopes,
                        access_token_hash, expires_at, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        hash,
                        family,
                        account_id.to_string(),
                        client_id.to_string(),
                        scopes,
                        access_token_hash,
                        expires_at,
                        unix_now(),
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(plaintext)
    }

    /// Look up a refresh token by its plaintext. Returns rows in ANY state
    /// (used/revoked/expired) — the token endpoint decides what each means
    /// (a used token is the reuse-detection signal, not a simple miss).
    pub async fn refresh_token_by_plaintext(
        &self,
        token: &str,
    ) -> Result<Option<RefreshTokenRow>, StorageError> {
        if !token.starts_with(REFRESH_PREFIX) {
            return Ok(None);
        }
        let hash = blake3::hash(token.as_bytes()).to_hex().to_string();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        &format!(
                            "SELECT {REFRESH_COLUMNS} FROM oauth_refresh_tokens
                             WHERE token_hash = ?1"
                        ),
                        [hash],
                        row_to_refresh,
                    )
                    .optional()?)
            })
            .await
    }

    /// Rotate: mark the old token used and mint its successor in the same
    /// family — one transaction. Errors if the old token is not live.
    pub async fn rotate_refresh_token(
        &self,
        old_hash: &str,
        new_access_token_hash: Option<String>,
        expires_at: i64,
    ) -> Result<String, StorageError> {
        let (plaintext, new_hash) = new_secret(REFRESH_PREFIX)?;
        let old_hash = old_hash.to_owned();
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let old = tx
                    .query_row(
                        &format!(
                            "SELECT {REFRESH_COLUMNS} FROM oauth_refresh_tokens
                             WHERE token_hash = ?1"
                        ),
                        [&old_hash],
                        row_to_refresh,
                    )
                    .optional()?
                    .ok_or_else(|| StorageError::BadInput("no such refresh token".into()))?;
                let now = unix_now();
                if old.used_at.is_some() || old.revoked_at.is_some() || old.expires_at <= now {
                    return Err(StorageError::Conflict("refresh token not live".into()));
                }
                tx.execute(
                    "UPDATE oauth_refresh_tokens SET used_at = ?2 WHERE token_hash = ?1",
                    params![old_hash, now],
                )?;
                tx.execute(
                    "INSERT INTO oauth_refresh_tokens
                       (token_hash, family_id, account_id, client_id, scopes,
                        access_token_hash, expires_at, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        new_hash,
                        old.family_id,
                        old.account_id.to_string(),
                        old.client_id.to_string(),
                        old.scopes.join(" "),
                        new_access_token_hash,
                        expires_at,
                        now,
                    ],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(plaintext)
    }

    /// Reuse detected (or RFC 7009 revocation): kill the whole family and
    /// every access token it minted.
    pub async fn revoke_refresh_family(&self, family_id: &str) -> Result<(), StorageError> {
        let family_id = family_id.to_owned();
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "DELETE FROM app_passwords WHERE token_hash IN (
                       SELECT access_token_hash FROM oauth_refresh_tokens
                       WHERE family_id = ?1 AND access_token_hash IS NOT NULL)",
                    [&family_id],
                )?;
                tx.execute(
                    "UPDATE oauth_refresh_tokens SET revoked_at = ?2
                     WHERE family_id = ?1 AND revoked_at IS NULL",
                    params![family_id, unix_now()],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::open;

    async fn harness() -> (tempfile::TempDir, Storage, AccountId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = open(dir.path()).await;
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");
        (dir, storage, account.id)
    }

    fn uris() -> Vec<String> {
        vec!["https://rp.example/cb".to_string()]
    }

    #[tokio::test]
    async fn client_crud_and_secret_verify() {
        let (_dir, storage, _account) = harness().await;

        let (client, secret) = storage
            .create_oauth_client("grafana", &uris(), false)
            .await
            .expect("create");
        let secret = secret.expect("confidential client has a secret");
        assert!(secret.starts_with("mcs_"));
        assert!(!client.public);

        assert!(
            storage
                .verify_oauth_client_secret(client.id, &secret)
                .await
                .expect("verify")
        );
        assert!(
            !storage
                .verify_oauth_client_secret(client.id, "mcs_wrong")
                .await
                .expect("verify")
        );

        let (public_client, no_secret) = storage
            .create_oauth_client("cli-app", &uris(), true)
            .await
            .expect("create public");
        assert!(no_secret.is_none());
        assert!(public_client.public);
        // A public client never verifies any secret.
        assert!(
            !storage
                .verify_oauth_client_secret(public_client.id, "mcs_anything")
                .await
                .expect("verify")
        );

        // Bad redirect URIs rejected.
        for bad in ["ftp://x/cb", "https://x/cb#frag", ""] {
            assert!(
                storage
                    .create_oauth_client("bad", &[bad.to_string()], true)
                    .await
                    .is_err(),
                "{bad:?} should be rejected"
            );
        }

        assert_eq!(storage.list_oauth_clients().await.expect("list").len(), 2);
        storage.close();
    }

    #[tokio::test]
    async fn grants_union_and_revoke_is_account_scoped() {
        let (_dir, storage, alice) = harness().await;
        let bob = storage
            .create_account("bob@example.com", None)
            .await
            .expect("account")
            .id;
        let (client, _) = storage
            .create_oauth_client("app", &uris(), true)
            .await
            .expect("client");

        storage
            .upsert_oauth_grant(alice, client.id, &["openid".into(), "email".into()])
            .await
            .expect("grant");
        storage
            .upsert_oauth_grant(alice, client.id, &["mcp".into()])
            .await
            .expect("widen");
        let grant = storage
            .oauth_grant(alice, client.id)
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(grant.scopes, vec!["email", "mcp", "openid"], "unioned");

        storage
            .upsert_oauth_grant(bob, client.id, &["openid".into()])
            .await
            .expect("bob grant");

        // Revoking alice's grant leaves bob's untouched.
        storage
            .revoke_oauth_grant(alice, client.id)
            .await
            .expect("revoke");
        assert!(
            storage
                .oauth_grant(alice, client.id)
                .await
                .expect("get")
                .is_none()
        );
        assert!(
            storage
                .oauth_grant(bob, client.id)
                .await
                .expect("get")
                .is_some()
        );
        storage.close();
    }

    #[tokio::test]
    async fn refresh_rotation_and_family_revocation() {
        let (_dir, storage, alice) = harness().await;
        let (client, _) = storage
            .create_oauth_client("app", &uris(), true)
            .await
            .expect("client");
        let scopes = vec!["openid".to_string(), "mcp".to_string()];
        let far = unix_now() + 86_400;

        // Mint an access token + linked refresh token.
        let (access_plain, access_hash) = storage
            .create_scoped_token(alice, "oidc:app", &scopes, far, client.id)
            .await
            .expect("access");
        let refresh1 = storage
            .create_refresh_token(alice, client.id, &scopes, None, Some(access_hash), far)
            .await
            .expect("refresh");
        assert!(refresh1.starts_with("mrt_"));

        // Scoped access token: rejected by legacy path, accepted by scoped path.
        assert!(
            storage
                .account_by_token(&access_plain)
                .await
                .expect("lookup")
                .is_none(),
            "scoped tokens must not pass the legacy (IMAP) path"
        );
        let (_, access) = storage
            .account_and_access_by_token(&access_plain)
            .await
            .expect("lookup")
            .expect("valid");
        assert!(access.allows("mcp") && !access.allows("mail"));

        // Rotate: successor works, old token shows used.
        let (_, access2_hash) = storage
            .create_scoped_token(alice, "oidc:app", &scopes, far, client.id)
            .await
            .expect("access2");
        let old_row = storage
            .refresh_token_by_plaintext(&refresh1)
            .await
            .expect("row")
            .expect("exists");
        let refresh2 = storage
            .rotate_refresh_token(&old_row.token_hash, Some(access2_hash), far)
            .await
            .expect("rotate");
        let old_row = storage
            .refresh_token_by_plaintext(&refresh1)
            .await
            .expect("row")
            .expect("exists");
        assert!(old_row.used_at.is_some(), "rotated token marked used");
        assert!(
            storage
                .rotate_refresh_token(&old_row.token_hash, None, far)
                .await
                .is_err(),
            "re-rotating a used token errors"
        );

        // Family revocation kills the successor AND the access tokens.
        storage
            .revoke_refresh_family(&old_row.family_id)
            .await
            .expect("revoke family");
        let successor = storage
            .refresh_token_by_plaintext(&refresh2)
            .await
            .expect("row")
            .expect("exists");
        assert!(successor.revoked_at.is_some());
        assert!(
            storage
                .account_and_access_by_token(&access_plain)
                .await
                .expect("lookup")
                .is_none(),
            "family revocation deletes linked access tokens"
        );
        storage.close();
    }

    #[tokio::test]
    async fn expired_scoped_tokens_are_rejected() {
        let (_dir, storage, alice) = harness().await;
        let (client, _) = storage
            .create_oauth_client("app", &uris(), true)
            .await
            .expect("client");
        let (token, _) = storage
            .create_scoped_token(
                alice,
                "oidc:app",
                &["mcp".into()],
                unix_now() - 1,
                client.id,
            )
            .await
            .expect("expired token");
        assert!(
            storage
                .account_and_access_by_token(&token)
                .await
                .expect("lookup")
                .is_none()
        );
        storage.close();
    }
}
