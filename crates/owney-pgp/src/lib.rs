//! PGP-native core (M4).
//!
//! Policy (2026-correct, per PLAN.md): emit v4 certs (Ed25519 sign +
//! X25519 encryption subkey), accept anything reasonable inbound, never emit
//! LibrePGP v5. Users never see a keyring: keys are generated at account
//! creation, secret material lives in the (master-key-encrypted) blob store,
//! publication is WKD + Autocrypt, harvesting is automatic.

pub mod autocrypt;
pub mod ops;
pub mod pipeline;
pub mod wkd;

use owney_core::AccountId;
use owney_storage::Storage;
use sequoia_openpgp as openpgp;

use openpgp::Cert;
use openpgp::cert::CertBuilder;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::MarshalInto;

#[derive(Debug, thiserror::Error)]
pub enum PgpError {
    #[error("pgp: {0}")]
    OpenPgp(String),

    #[error("storage: {0}")]
    Storage(#[from] owney_storage::StorageError),

    #[error("no usable encryption key for {0}")]
    NoEncryptionKey(String),
}

impl From<anyhow::Error> for PgpError {
    fn from(err: anyhow::Error) -> Self {
        PgpError::OpenPgp(format!("{err:#}"))
    }
}

/// The policy every verification/encryption decision runs under.
pub fn policy() -> StandardPolicy<'static> {
    StandardPolicy::new()
}

/// Generate a fresh v4 cert (Cv25519: Ed25519 + X25519) for an address.
pub fn generate_cert(email: &str, display_name: Option<&str>) -> Result<Cert, PgpError> {
    let userid = match display_name {
        Some(name) => format!("{name} <{email}>"),
        None => format!("<{email}>"),
    };
    let (cert, _revocation) = CertBuilder::new()
        .set_cipher_suite(openpgp::cert::CipherSuite::Cv25519)
        .add_userid(userid)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()?;
    Ok(cert)
}

/// Load the account's cert (with secrets), generating and persisting one on
/// first use. Secret material is stored in the blob store, which encrypts
/// everything under the master key.
pub async fn own_cert(storage: &Storage, account_id: AccountId) -> Result<Cert, PgpError> {
    if let Some((_fingerprint, blob_id)) = storage.pgp_own_key(account_id).await? {
        let tsk_bytes = storage.get_blob(blob_id).await?;
        let cert = Cert::from_bytes(&tsk_bytes).map_err(PgpError::from)?;
        return Ok(cert);
    }

    let account = storage
        .account(account_id)
        .await?
        .ok_or_else(|| PgpError::OpenPgp("no such account".into()))?;
    let cert = generate_cert(&account.email, account.display_name.as_deref())?;

    // Serialize including secret key material (TSK).
    let tsk_bytes = cert.as_tsk().to_vec().map_err(PgpError::from)?;
    let blob_id = storage.put_blob(tsk_bytes).await?;
    storage
        .set_pgp_own_key(account_id, &cert.fingerprint().to_hex(), blob_id)
        .await?;
    tracing::info!(
        email = %account.email,
        fingerprint = %cert.fingerprint(),
        "generated PGP key"
    );
    Ok(cert)
}

/// Public-only armored form, for WKD and Autocrypt publication.
pub fn public_armored(cert: &Cert) -> Result<String, PgpError> {
    use openpgp::armor::{Kind, Writer};
    use std::io::Write;

    let mut writer = Writer::new(Vec::new(), Kind::PublicKey)
        .map_err(|err| PgpError::OpenPgp(err.to_string()))?;
    let bytes = cert.to_vec().map_err(PgpError::from)?;
    writer
        .write_all(&bytes)
        .map_err(|err| PgpError::OpenPgp(err.to_string()))?;
    let out = writer
        .finalize()
        .map_err(|err| PgpError::OpenPgp(err.to_string()))?;
    String::from_utf8(out).map_err(|err| PgpError::OpenPgp(err.to_string()))
}

/// Public-only binary form.
pub fn public_der(cert: &Cert) -> Result<Vec<u8>, PgpError> {
    cert.to_vec().map_err(PgpError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use owney_events::EventBus;

    #[test]
    fn generated_cert_has_signing_and_encryption_keys() {
        let cert = generate_cert("alice@example.com", Some("Alice")).expect("generate");
        let policy = policy();
        let valid = cert.with_policy(&policy, None).expect("valid");
        assert!(valid.keys().for_signing().next().is_some(), "signing key");
        assert!(
            valid.keys().for_transport_encryption().next().is_some(),
            "encryption key"
        );
        assert!(cert.is_tsk(), "secrets present");
    }

    #[tokio::test]
    async fn own_cert_persists_and_reloads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path(), EventBus::new(8)).expect("open");
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");

        let first = own_cert(&storage, account.id).await.expect("generate");
        let second = own_cert(&storage, account.id).await.expect("reload");
        assert_eq!(
            first.fingerprint(),
            second.fingerprint(),
            "stable across reloads"
        );
        assert!(second.is_tsk(), "secrets survive the round trip");
        storage.close();
    }
}
