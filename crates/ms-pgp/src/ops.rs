//! Encrypt/sign and decrypt/verify, via sequoia's streaming API.

use std::io::Write;

use sequoia_openpgp as openpgp;

use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};

use crate::{PgpError, policy};

/// Encrypt `plaintext` to every recipient cert (also readable by the sender),
/// signed with the sender's key. Output is ASCII-armored.
pub fn encrypt_and_sign(
    sender: &Cert,
    recipients: &[&Cert],
    plaintext: &[u8],
) -> Result<Vec<u8>, PgpError> {
    let policy = policy();

    let mut recipient_keys = Vec::new();
    for cert in recipients.iter().copied().chain(std::iter::once(sender)) {
        let mut found = false;
        for key in cert
            .with_policy(&policy, None)
            .map_err(PgpError::from)?
            .keys()
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            recipient_keys.push(key);
            found = true;
        }
        if !found {
            return Err(PgpError::NoEncryptionKey(cert.fingerprint().to_string()));
        }
    }

    let signing_keypair = sender
        .with_policy(&policy, None)
        .map_err(PgpError::from)?
        .keys()
        .secret()
        .for_signing()
        .next()
        .ok_or_else(|| PgpError::OpenPgp("sender has no secret signing key".into()))?
        .key()
        .clone()
        .into_keypair()
        .map_err(PgpError::from)?;

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let message = Armorer::new(message).build().map_err(PgpError::from)?;
    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .map_err(PgpError::from)?;
    let message = Signer::new(message, signing_keypair)
        .map_err(PgpError::from)?
        .build()
        .map_err(PgpError::from)?;
    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(PgpError::from)?;
    literal
        .write_all(plaintext)
        .map_err(|err| PgpError::OpenPgp(err.to_string()))?;
    literal.finalize().map_err(PgpError::from)?;
    Ok(out)
}

/// Outcome of decrypt-and-verify, stored per message as `pgp_status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptOutcome {
    pub plaintext: Vec<u8>,
    /// Signature disposition: "valid", "invalid", "unknown_key", or "none".
    pub signature: &'static str,
}

/// Decrypt with the recipient's secret key; verify any signature against the
/// (optional) claimed sender cert.
pub fn decrypt_and_verify(
    own: &Cert,
    sender: Option<&Cert>,
    ciphertext: &[u8],
) -> Result<DecryptOutcome, PgpError> {
    let policy = policy();
    let helper = Helper {
        own,
        sender,
        signature: "none",
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .map_err(PgpError::from)?
        .with_policy(&policy, None, helper)
        .map_err(PgpError::from)?;

    let mut plaintext = Vec::new();
    std::io::copy(&mut decryptor, &mut plaintext)
        .map_err(|err| PgpError::OpenPgp(err.to_string()))?;

    let helper = decryptor.into_helper();
    Ok(DecryptOutcome {
        plaintext,
        signature: helper.signature,
    })
}

struct Helper<'a> {
    own: &'a Cert,
    sender: Option<&'a Cert>,
    signature: &'static str,
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.sender.into_iter().cloned().collect())
    }

    fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    match result {
                        Ok(_) => {
                            self.signature = "valid";
                            return Ok(());
                        }
                        Err(openpgp::parse::stream::VerificationError::MissingKey { .. }) => {
                            self.signature = "unknown_key";
                        }
                        Err(_) => {
                            if self.signature == "none" {
                                self.signature = "invalid";
                            }
                        }
                    }
                }
            }
        }
        // Absence or failure of signatures never blocks decryption; the
        // disposition is recorded for the client to render.
        Ok(())
    }
}

impl DecryptionHelper for Helper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(
            Option<openpgp::types::SymmetricAlgorithm>,
            &openpgp::crypto::SessionKey,
        ) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        let policy = policy();
        for key in self
            .own
            .with_policy(&policy, None)?
            .keys()
            .secret()
            .for_transport_encryption()
        {
            let mut keypair = key.key().clone().into_keypair()?;
            for pkesk in pkesks {
                if pkesk
                    .decrypt(&mut keypair, sym_algo)
                    .is_some_and(|(algo, sk)| decrypt(algo, &sk))
                {
                    return Ok(Some(self.own.clone()));
                }
            }
        }
        Err(anyhow::anyhow!("no key could decrypt the message"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_cert;

    #[test]
    fn encrypt_decrypt_verify_round_trip() {
        let alice = generate_cert("alice@a.test", Some("Alice")).expect("alice");
        let bob = generate_cert("bob@b.test", Some("Bob")).expect("bob");

        let ciphertext =
            encrypt_and_sign(&alice, &[&bob], b"the plan is in motion").expect("encrypt");
        let armored = String::from_utf8_lossy(&ciphertext);
        assert!(
            armored.starts_with("-----BEGIN PGP MESSAGE-----"),
            "{armored}"
        );

        // Bob decrypts and verifies against Alice's public cert.
        let alice_public = alice.clone().strip_secret_key_material();
        let outcome = decrypt_and_verify(&bob, Some(&alice_public), &ciphertext).expect("decrypt");
        assert_eq!(outcome.plaintext, b"the plan is in motion");
        assert_eq!(outcome.signature, "valid");

        // The sender can read their own sent mail.
        let outcome = decrypt_and_verify(&alice, None, &ciphertext).expect("self decrypt");
        assert_eq!(outcome.plaintext, b"the plan is in motion");
        assert_eq!(outcome.signature, "unknown_key", "no sender cert supplied");
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let alice = generate_cert("alice@a.test", None).expect("alice");
        let bob = generate_cert("bob@b.test", None).expect("bob");
        let eve = generate_cert("eve@e.test", None).expect("eve");

        let ciphertext = encrypt_and_sign(&alice, &[&bob], b"secret").expect("encrypt");
        assert!(decrypt_and_verify(&eve, None, &ciphertext).is_err());
    }
}
