//! The PGP send/receive pipeline hooks.
//!
//! Outbound: inject the Autocrypt header on every message; when every
//! recipient has a harvested key, wrap the whole message in PGP/MIME
//! (multipart/encrypted), signed by the sender.
//!
//! Inbound: harvest Autocrypt keys into the peer table (reporting fingerprint
//! changes), and transparently decrypt messages encrypted to us — the
//! decrypted form is what gets stored and indexed (trusted-server model);
//! the original ciphertext is kept as an unreferenced blob.

use owney_core::AccountId;
use owney_storage::Storage;
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;

use crate::{PgpError, autocrypt, ops, own_cert, public_der};

/// Outbound processing: Autocrypt injection + opportunistic encryption.
/// Returns the (possibly re-wrapped) message to DKIM-sign and send.
pub async fn outbound(
    storage: &Storage,
    account_id: AccountId,
    mail_from: &str,
    recipients: &[String],
    raw: Vec<u8>,
) -> Result<Vec<u8>, PgpError> {
    let cert = own_cert(storage, account_id).await?;
    let autocrypt_header = autocrypt::header(mail_from, &cert, true)?;

    // Encrypt only when EVERY recipient has a usable harvested key.
    let mut recipient_certs = Vec::new();
    for recipient in recipients {
        match storage.pgp_peer(account_id, recipient).await? {
            Some(peer) => match Cert::from_bytes(&peer.cert) {
                Ok(peer_cert) => recipient_certs.push(peer_cert),
                Err(err) => {
                    tracing::warn!(%recipient, %err, "stored peer cert unreadable");
                    recipient_certs.clear();
                    break;
                }
            },
            None => {
                recipient_certs.clear();
                break;
            }
        }
    }

    if recipient_certs.len() == recipients.len() && !recipients.is_empty() {
        match encrypt_pgp_mime(&cert, &recipient_certs, &autocrypt_header, &raw) {
            Ok(encrypted) => {
                tracing::info!(
                    recipients = recipients.len(),
                    "message encrypted (PGP/MIME)"
                );
                return Ok(encrypted);
            }
            Err(err) => {
                // Never fail delivery because encryption was impossible;
                // fall through to signed-cleartext behavior.
                tracing::warn!(%err, "opportunistic encryption failed, sending cleartext");
            }
        }
    }

    Ok(prepend_header(&raw, "Autocrypt", &autocrypt_header))
}

/// What inbound processing decided about one message.
#[derive(Debug)]
pub struct InboundOutcome {
    /// The bytes to store and index (decrypted when possible).
    pub raw: Vec<u8>,
    /// JSON for `emails.pgp_status`, when the message was PGP-relevant.
    pub pgp_status: Option<String>,
    /// Addresses whose harvested key fingerprint CHANGED (possible MITM or
    /// key rotation) — the caller raises SecurityEvents.
    pub key_changes: Vec<String>,
}

/// Inbound processing: harvest Autocrypt, decrypt if encrypted to us.
pub async fn inbound(
    storage: &Storage,
    account_id: AccountId,
    raw: Vec<u8>,
) -> Result<InboundOutcome, PgpError> {
    let mut key_changes = Vec::new();
    let mut sender_cert: Option<Cert> = None;
    let mut from_addr = None;

    // Harvest the Autocrypt header (if any).
    if let Some(message) = mail_parser::MessageParser::default().parse(&raw) {
        from_addr = message
            .from()
            .and_then(|from| from.first())
            .and_then(|addr| addr.address())
            .map(str::to_owned);
        if let Some(value) = message.header("Autocrypt").and_then(|h| h.as_text()) {
            match autocrypt::parse_header(value) {
                Ok(parsed) => {
                    // Only trust the header for the address it claims AND the
                    // message is from (Autocrypt Level 1 rule).
                    if from_addr.as_deref() == Some(parsed.addr.as_str()) {
                        let der = public_der(&parsed.cert)?;
                        let changed = storage
                            .upsert_pgp_peer(
                                account_id,
                                &parsed.addr,
                                der,
                                &parsed.cert.fingerprint().to_hex(),
                                parsed.prefer_encrypt.clone(),
                            )
                            .await?;
                        if changed {
                            key_changes.push(parsed.addr.clone());
                        }
                        sender_cert = Some(parsed.cert);
                    }
                }
                Err(err) => tracing::debug!(%err, "ignoring unparseable Autocrypt header"),
            }
        }
    }

    // No armored payload → plain message, done.
    let Some(armored) = extract_armored(&raw) else {
        return Ok(InboundOutcome {
            raw,
            pgp_status: None,
            key_changes,
        });
    };

    // Known sender key (harvested now or previously) for verification.
    if sender_cert.is_none()
        && let Some(addr) = &from_addr
        && let Some(peer) = storage.pgp_peer(account_id, addr).await?
    {
        sender_cert = Cert::from_bytes(&peer.cert).ok();
    }

    let own = own_cert(storage, account_id).await?;
    match ops::decrypt_and_verify(&own, sender_cert.as_ref(), armored.as_bytes()) {
        Ok(outcome) => {
            // Keep the ciphertext originals retrievable (content-addressed).
            let original_blob = storage.put_blob(raw).await?;
            let status = format!(
                r#"{{"encrypted":true,"signature":"{}","original_blob":"{}"}}"#,
                outcome.signature,
                original_blob.to_hex(),
            );
            Ok(InboundOutcome {
                raw: outcome.plaintext,
                pgp_status: Some(status),
                key_changes,
            })
        }
        Err(err) => {
            tracing::warn!(%err, "message looks encrypted but could not be decrypted");
            Ok(InboundOutcome {
                raw,
                pgp_status: Some(
                    r#"{"encrypted":true,"signature":"none","undecryptable":true}"#.to_owned(),
                ),
                key_changes,
            })
        }
    }
}

/// Wrap a full message in PGP/MIME (RFC 3156 multipart/encrypted). The inner
/// encrypted entity is the complete original message, headers included —
/// protected-headers style, so the plaintext copy keeps its metadata.
fn encrypt_pgp_mime(
    sender: &Cert,
    recipients: &[Cert],
    autocrypt_header: &str,
    raw: &[u8],
) -> Result<Vec<u8>, PgpError> {
    let recipient_refs: Vec<&Cert> = recipients.iter().collect();
    let ciphertext = ops::encrypt_and_sign(sender, &recipient_refs, raw)?;
    let armored =
        String::from_utf8(ciphertext).map_err(|err| PgpError::OpenPgp(err.to_string()))?;

    let outer_headers = copy_routing_headers(raw);
    let boundary = format!("pgpmime-{}", blake3::hash(raw).to_hex());

    Ok(format!(
        "{outer_headers}Autocrypt: {autocrypt_header}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n\
         \tboundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: application/pgp-encrypted\r\n\
         \r\n\
         Version: 1\r\n\
         --{boundary}\r\n\
         Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
         \r\n\
         {armored}\r\n\
         --{boundary}--\r\n"
    )
    .into_bytes())
}

/// The routing/threading headers copied onto the encrypted envelope.
fn copy_routing_headers(raw: &[u8]) -> String {
    const KEEP: [&str; 7] = [
        "from:",
        "to:",
        "cc:",
        "subject:",
        "date:",
        "message-id:",
        "references:",
    ];
    let text = String::from_utf8_lossy(raw);
    let header_section = text.split("\r\n\r\n").next().unwrap_or("");

    let mut out = String::new();
    let mut keeping = false;
    for line in header_section.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of the previous header.
            if keeping {
                out.push_str(line);
                out.push_str("\r\n");
            }
            continue;
        }
        let lower = line.to_lowercase();
        keeping = KEEP.iter().any(|k| lower.starts_with(k));
        if keeping {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out
}

/// Prepend one header line to a raw message.
fn prepend_header(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let mut out = format!("{name}: {value}\r\n").into_bytes();
    out.extend_from_slice(raw);
    out
}

/// Find an armored PGP message anywhere in the payload (covers PGP/MIME and
/// inline PGP alike).
fn extract_armored(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let start = text.find("-----BEGIN PGP MESSAGE-----")?;
    let end_marker = "-----END PGP MESSAGE-----";
    let end = text[start..].find(end_marker)? + start + end_marker.len();
    Some(text[start..end].to_owned())
}
