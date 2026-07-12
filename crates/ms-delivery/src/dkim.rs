//! DKIM key lifecycle: generate on first use, persist under the data
//! directory, sign outbound messages, and emit the DNS record the setup
//! wizard publishes.

use std::path::Path;

use base64::Engine;
use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::DkimSigner;
use mail_auth::dkim::generate::DkimKeyPair;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::EncodePublicKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};

use crate::DeliveryError;

pub const SELECTOR: &str = "ms1";

/// Headers signed on every outbound message (RFC 6376 §5.4 recommended
/// plus the MIME-transport-protocol set).
const SIGNED_HEADERS: [&str; 9] = [
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "Reply-To",
    "MIME-Version",
    "Content-Type",
];

/// Per-domain signing key, loaded once at startup.
pub struct DkimKeys {
    domain: String,
    signer: DkimSigner<RsaKey<Sha256>, mail_auth::dkim::Done>,
    public_key_der: Vec<u8>,
}

impl std::fmt::Debug for DkimKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimKeys")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl DkimKeys {
    /// Load the domain's RSA-2048 key from `<data_dir>/dkim/`, generating and
    /// persisting one on first use.
    pub fn load_or_generate(data_dir: &Path, domain: &str) -> Result<Self, DeliveryError> {
        let dir = data_dir.join("dkim");
        std::fs::create_dir_all(&dir).map_err(|err| DeliveryError::Io(dir.clone(), err))?;
        let private_path = dir.join(format!("rsa-{SELECTOR}-{domain}.pk8"));
        let public_path = dir.join(format!("rsa-{SELECTOR}-{domain}.pub"));

        let (private_der, public_der) = if private_path.exists() {
            (
                std::fs::read(&private_path)
                    .map_err(|err| DeliveryError::Io(private_path.clone(), err))?,
                std::fs::read(&public_path)
                    .map_err(|err| DeliveryError::Io(public_path.clone(), err))?,
            )
        } else {
            // mail-auth emits PKCS#1 for both halves; the DNS p= tag wants
            // SubjectPublicKeyInfo, so convert the public half once here.
            let pair = DkimKeyPair::generate_rsa(2048)
                .map_err(|err| DeliveryError::Dkim(err.to_string()))?;
            let private_der = pair.private_key().to_vec();
            let public_der = rsa::RsaPublicKey::from_pkcs1_der(pair.public_key())
                .map_err(|err| DeliveryError::Dkim(err.to_string()))?
                .to_public_key_der()
                .map_err(|err| DeliveryError::Dkim(err.to_string()))?
                .into_vec();
            write_restricted(&private_path, &private_der)?;
            write_restricted(&public_path, &public_der)?;
            tracing::info!(%domain, selector = SELECTOR, "generated DKIM signing key");
            (private_der, public_der)
        };

        let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
            private_der.clone(),
        )))
        .map_err(|err| DeliveryError::Dkim(err.to_string()))?;
        let signer = DkimSigner::from_key(key)
            .domain(domain)
            .selector(SELECTOR)
            .headers(SIGNED_HEADERS);

        Ok(Self {
            domain: domain.to_owned(),
            signer,
            public_key_der: public_der,
        })
    }

    /// Sign `message`, returning the DKIM-Signature header line (CRLF-terminated).
    pub fn sign(&self, message: &[u8]) -> Result<String, DeliveryError> {
        let signature = self
            .signer
            .sign(message)
            .map_err(|err| DeliveryError::Dkim(err.to_string()))?;
        Ok(signature.to_header())
    }

    /// The TXT record to publish at `<selector>._domainkey.<domain>`.
    pub fn dns_record(&self) -> (String, String) {
        let name = format!("{SELECTOR}._domainkey.{}", self.domain);
        let value = format!(
            "v=DKIM1; k=rsa; p={}",
            base64::engine::general_purpose::STANDARD.encode(&self.public_key_der)
        );
        (name, value)
    }
}

fn write_restricted(path: &Path, contents: &[u8]) -> Result<(), DeliveryError> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| DeliveryError::Io(path.to_owned(), err))?;
    file.write_all(contents)
        .map_err(|err| DeliveryError::Io(path.to_owned(), err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_persist_reload_and_sign() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = DkimKeys::load_or_generate(dir.path(), "example.com").expect("generate");
        let (name, value) = keys.dns_record();
        assert_eq!(name, "ms1._domainkey.example.com");
        assert!(value.starts_with("v=DKIM1; k=rsa; p="));

        let header = keys
            .sign(b"From: a@example.com\r\nTo: b@remote.test\r\nSubject: x\r\n\r\nbody\r\n")
            .expect("sign");
        assert!(header.starts_with("DKIM-Signature:"), "{header}");
        assert!(header.contains("d=example.com"), "{header}");
        assert!(header.contains("s=ms1"), "{header}");

        // Reload must reuse the same key (same DNS record).
        let reloaded = DkimKeys::load_or_generate(dir.path(), "example.com").expect("reload");
        assert_eq!(reloaded.dns_record(), (name, value));
    }
}
