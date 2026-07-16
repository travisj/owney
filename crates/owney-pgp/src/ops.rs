//! Encrypt/sign and decrypt/verify, via sequoia's streaming API.

use std::io::Write;

use sequoia_openpgp as openpgp;

use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
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

/// Produce a binary **detached** signature over `msg` with the signer's key.
/// Used to authenticate federation HTTP requests: the signature covers a
/// canonical request string with no encryption.
pub fn sign_detached(signer: &Cert, msg: &[u8]) -> Result<Vec<u8>, PgpError> {
    let policy = policy();
    let keypair = signer
        .with_policy(&policy, None)
        .map_err(PgpError::from)?
        .keys()
        .secret()
        .for_signing()
        .next()
        .ok_or_else(|| PgpError::OpenPgp("signer has no secret signing key".into()))?
        .key()
        .clone()
        .into_keypair()
        .map_err(PgpError::from)?;

    let mut out = Vec::new();
    let message = Message::new(&mut out);
    let mut signer = Signer::new(message, keypair)
        .map_err(PgpError::from)?
        .detached()
        .build()
        .map_err(PgpError::from)?;
    signer
        .write_all(msg)
        .map_err(|err| PgpError::OpenPgp(err.to_string()))?;
    signer.finalize().map_err(PgpError::from)?;
    Ok(out)
}

/// Verify a detached `sig` over `msg` against `signer_pub`. Returns `true` only
/// for a cryptographically valid signature by that cert under our policy.
pub fn verify_detached(signer_pub: &Cert, msg: &[u8], sig: &[u8]) -> Result<bool, PgpError> {
    let policy = policy();
    let helper = DetachedHelper {
        signer: signer_pub,
        valid: false,
    };
    let mut verifier = DetachedVerifierBuilder::from_bytes(sig)
        .map_err(PgpError::from)?
        .with_policy(&policy, None, helper)
        .map_err(PgpError::from)?;
    // `verify_bytes` drives the helper's `check`; a bad/absent signature is
    // recorded there rather than erroring, so read the flag afterwards.
    verifier.verify_bytes(msg).map_err(PgpError::from)?;
    Ok(verifier.into_helper().valid)
}

/// Seal a federated event: sign with the authoring account's key and encrypt to
/// the receiving server's cert. Thin wrapper over [`encrypt_and_sign`].
pub fn seal_event(
    author_secret: &Cert,
    receiving_server_pub: &Cert,
    plaintext: &[u8],
) -> Result<Vec<u8>, PgpError> {
    encrypt_and_sign(author_secret, &[receiving_server_pub], plaintext)
}

/// Open a sealed event: decrypt with the server's secret cert and require a
/// **valid** signature from the claimed author. Rejects (rather than storing)
/// anything whose author signature does not verify — the crucial check that
/// [`decrypt_and_verify`] deliberately leaves to the caller.
pub fn open_event(
    server_secret: &Cert,
    author_pub: &Cert,
    ciphertext: &[u8],
) -> Result<Vec<u8>, PgpError> {
    let outcome = decrypt_and_verify(server_secret, Some(author_pub), ciphertext)?;
    if outcome.signature != "valid" {
        return Err(PgpError::OpenPgp(format!(
            "federated event signature not valid: {}",
            outcome.signature
        )));
    }
    Ok(outcome.plaintext)
}

struct Helper<'a> {
    own: &'a Cert,
    sender: Option<&'a Cert>,
    signature: &'static str,
}

struct DetachedHelper<'a> {
    signer: &'a Cert,
    valid: bool,
}

impl VerificationHelper for DetachedHelper<'_> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.signer.clone()])
    }

    fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    if result.is_ok() {
                        self.valid = true;
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
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

    #[test]
    fn detached_signature_round_trip() {
        let server = generate_cert("federation@a.test", Some("a.test")).expect("server");
        let msg = b"GET\n/.well-known/owney/calendar/sync/abc\na.test\n1700000000\nnonce123\n";

        let sig = sign_detached(&server, msg).expect("sign");
        let server_pub = server.clone().strip_secret_key_material();
        assert!(verify_detached(&server_pub, msg, &sig).expect("verify"));
    }

    #[test]
    fn detached_verify_rejects_tampered_message_and_wrong_key() {
        let server = generate_cert("federation@a.test", None).expect("server");
        let other = generate_cert("federation@evil.test", None).expect("other");
        let msg = b"canonical-request-bytes";

        let sig = sign_detached(&server, msg).expect("sign");
        let server_pub = server.clone().strip_secret_key_material();

        // Tampered message: must not verify.
        assert!(!verify_detached(&server_pub, b"canonical-request-byteX", &sig).expect("tamper"));
        // Signed by a different key than claimed: must not verify.
        let other_pub = other.strip_secret_key_material();
        assert!(!verify_detached(&other_pub, msg, &sig).expect("wrong key"));
    }

    #[test]
    fn open_event_rejects_unsigned_or_wrong_author() {
        // Author A signs + encrypts an event to server B.
        let author = generate_cert("alice@a.test", Some("Alice")).expect("author");
        let server_b = generate_cert("federation@b.test", Some("b.test")).expect("server b");

        let sealed = seal_event(&author, &server_b, b"{\"title\":\"Standup\"}").expect("seal");

        // B opens it, verifying A's signature.
        let author_pub = author.clone().strip_secret_key_material();
        let plaintext = open_event(&server_b, &author_pub, &sealed).expect("open");
        assert_eq!(plaintext, b"{\"title\":\"Standup\"}");

        // If B is handed the WRONG author cert, the signature is not "valid" and
        // open_event must reject rather than store.
        let impostor = generate_cert("mallory@evil.test", None)
            .expect("impostor")
            .strip_secret_key_material();
        assert!(open_event(&server_b, &impostor, &sealed).is_err());
    }
}
