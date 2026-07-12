//! Encrypted, content-addressed blob store.
//!
//! Blobs are addressed by the BLAKE3 hash of their *plaintext* — identical
//! content stores once regardless of encryption. On disk, each blob is
//! encrypted with its own random XChaCha20-Poly1305 key, which is itself
//! wrapped by the master key. The blob's address is the AAD for the content
//! encryption, cryptographically binding each file to its name.
//!
//! On-disk layout: `blobs/<first two hex chars>/<full hex>`.
//!
//! File format v1:
//! ```text
//! magic  b"MSB1"                     4 bytes
//! wrap_nonce                        24 bytes
//! wrapped_key (32 + 16 tag)         48 bytes
//! data_nonce                        24 bytes
//! ciphertext (len + 16 tag)         rest
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ms_core::BlobId;

use crate::error::StorageError;
use crate::keys::MasterKey;

const MAGIC: &[u8; 4] = b"MSB1";
const NONCE_LEN: usize = 24;
const WRAPPED_KEY_LEN: usize = 32 + 16;
const HEADER_LEN: usize = 4 + NONCE_LEN + WRAPPED_KEY_LEN + NONCE_LEN;

#[derive(Debug, Clone)]
pub struct BlobStore {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    master: MasterKey,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl BlobStore {
    pub fn open(root: impl Into<PathBuf>, master: MasterKey) -> Result<Self, StorageError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|source| StorageError::io(&root, source))?;
        Ok(Self {
            inner: Arc::new(Inner { root, master }),
        })
    }

    /// Store `plaintext`, returning its content address. Idempotent: storing
    /// the same content twice writes one file.
    pub fn put(&self, plaintext: &[u8]) -> Result<BlobId, StorageError> {
        let id = BlobId(*blake3::hash(plaintext).as_bytes());
        let path = self.path_for(&id);
        // Dedup: if a sibling has already written this BLAKE3-digest blob
        // (different nonces, same plaintext → same id), skip the re-write.
        // The on-disk dedup is *correctness*, not just efficiency: two
        // concurrent writers with content-addressed filenames would race
        // in the check-then-write window below and overwrite each other
        // with different nonce pairs, leaving the file content undecryptable.
        if path.exists() {
            return Ok(id);
        }

        let mut blob_key = [0u8; 32];
        let mut wrap_nonce = [0u8; NONCE_LEN];
        let mut data_nonce = [0u8; NONCE_LEN];
        for buf in [&mut blob_key[..], &mut wrap_nonce[..], &mut data_nonce[..]] {
            getrandom::fill(buf).map_err(|_| StorageError::Crypto("os rng"))?;
        }

        let master_cipher = XChaCha20Poly1305::new(self.inner.master.bytes().into());
        let wrapped_key = master_cipher
            .encrypt(&XNonce::from(wrap_nonce), &blob_key[..])
            .map_err(|_| StorageError::Crypto("wrap blob key"))?;

        let data_cipher = XChaCha20Poly1305::new((&blob_key).into());
        let ciphertext = data_cipher
            .encrypt(
                &XNonce::from(data_nonce),
                Payload {
                    msg: plaintext,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| StorageError::Crypto("encrypt blob"))?;

        let mut file = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&wrap_nonce);
        file.extend_from_slice(&wrapped_key);
        file.extend_from_slice(&data_nonce);
        file.extend_from_slice(&ciphertext);

        self.write_atomically(&path, &file)?;
        Ok(id)
    }

    pub fn get(&self, id: &BlobId) -> Result<Vec<u8>, StorageError> {
        let path = self.path_for(id);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::BlobNotFound(*id));
            }
            Err(source) => return Err(StorageError::io(&path, source)),
        };

        if raw.len() < HEADER_LEN || &raw[..4] != MAGIC {
            return Err(StorageError::Corrupt(format!("blob {id}: bad header")));
        }
        let (wrap_nonce, rest) = raw[4..].split_at(NONCE_LEN);
        let (wrapped_key, rest) = rest.split_at(WRAPPED_KEY_LEN);
        let (data_nonce, ciphertext) = rest.split_at(NONCE_LEN);

        let wrap_nonce =
            XNonce::try_from(wrap_nonce).map_err(|_| StorageError::Crypto("bad nonce"))?;
        let data_nonce =
            XNonce::try_from(data_nonce).map_err(|_| StorageError::Crypto("bad nonce"))?;

        let master_cipher = XChaCha20Poly1305::new(self.inner.master.bytes().into());
        let blob_key = master_cipher
            .decrypt(&wrap_nonce, wrapped_key)
            .map_err(|_| StorageError::Crypto("unwrap blob key"))?;
        let blob_key: [u8; 32] = blob_key
            .try_into()
            .map_err(|_| StorageError::Corrupt(format!("blob {id}: bad key length")))?;

        let data_cipher = XChaCha20Poly1305::new((&blob_key).into());
        let plaintext = data_cipher
            .decrypt(
                &data_nonce,
                Payload {
                    msg: ciphertext,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| StorageError::Crypto("decrypt blob"))?;

        if blake3::hash(&plaintext).as_bytes() != id.as_bytes() {
            return Err(StorageError::Corrupt(format!(
                "blob {id}: content hash mismatch"
            )));
        }
        Ok(plaintext)
    }

    pub fn contains(&self, id: &BlobId) -> bool {
        self.path_for(id).exists()
    }

    fn path_for(&self, id: &BlobId) -> PathBuf {
        let hex = id.to_hex();
        self.inner.root.join(&hex[..2]).join(hex)
    }

    fn write_atomically(&self, path: &Path, contents: &[u8]) -> Result<(), StorageError> {
        let parent = path.parent().unwrap_or(&self.inner.root);
        std::fs::create_dir_all(parent).map_err(|source| StorageError::io(parent, source))?;
        // Each call needs a UNIQUE tmp path: two concurrent writers
        // targeting the same final `path` would both try to write the
        // same `.tmp` file if we used a deterministic name, racing on the
        // write before the rename even fires.
        let nonce = {
            let mut n = [0u8; 8];
            getrandom::fill(&mut n).map_err(|_| StorageError::Crypto("os rng"))?;
            u64::from_le_bytes(n)
        };
        let mut tmp = path.to_path_buf();
        let fname = match tmp.file_name() {
            Some(name) => name.to_owned(),
            None => return Err(StorageError::io(path, std::io::Error::other("no filename"))),
        };
        let unique = format!(".{}.{nonce}.tmp", fname.to_string_lossy());
        tmp.set_file_name(unique);
        std::fs::write(&tmp, contents).map_err(|source| StorageError::io(&tmp, source))?;
        // `sync_all` flushes the file's bytes to disk and ensures the
        // directory entry rename is durable too (otherwise a crash between
        // rename and a subsequent power-cut could leave a ghost
        // zero-length file at the rename target). On non-Linux FS this is
        // best-effort.
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        match std::fs::rename(&tmp, path) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                // A concurrent writer committed first (newer information
                // on disk is functionally equivalent — same BLAKE3 id,
                // same plaintext, decrypts the same way).
                let _ = std::fs::remove_file(&tmp);
            }
            Err(source) => return Err(StorageError::io(path, source)),
        }
        // Durability: ensure the directory rename settles. On every
        // platform we use `open_dir`-style, but fall back gracefully when
        // the FS doesn't expose it.
        #[cfg(unix)]
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MASTER_KEY_FILE;

    fn store(dir: &Path) -> BlobStore {
        let master = MasterKey::load_or_create(&dir.join(MASTER_KEY_FILE)).expect("key");
        BlobStore::open(dir.join("blobs"), master).expect("open")
    }

    #[test]
    fn round_trip_and_dedup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        let plaintext = b"From: alice@example.com\r\n\r\nhello world".to_vec();
        let id1 = store.put(&plaintext).expect("put");
        let id2 = store.put(&plaintext).expect("put again");
        assert_eq!(id1, id2, "content addressing dedups");
        assert_eq!(id1.as_bytes(), blake3::hash(&plaintext).as_bytes());

        assert_eq!(store.get(&id1).expect("get"), plaintext);
    }

    #[test]
    fn concurrent_writes_for_same_blob_succeed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = std::sync::Arc::new(store(dir.path()));

        let plaintext = b"From: a@x\r\n\r\nbandit content for two writers".to_vec();
        let mut joins = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let plaintext = plaintext.clone();
            joins.push(std::thread::spawn(move || {
                store.put(&plaintext).expect("concurrent put")
            }));
        }
        let mut ids = joins
            .into_iter()
            .map(|j| j.join().expect("join"))
            .collect::<Vec<_>>();
        ids.dedup();
        assert_eq!(ids.len(), 1, "all writers produce the same content address");

        // The resulting file MUST decrypt to the original plaintext. If
        // a race had overwritten with a different nonce, decryption would
        // fail or produce garbage bytes.
        let id = ids[0];
        assert_eq!(store.get(&id).expect("get"), plaintext);
    }

    #[test]
    fn on_disk_bytes_are_not_plaintext() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());

        let plaintext = b"extremely secret message body".to_vec();
        let id = store.put(&plaintext).expect("put");

        let hex = id.to_hex();
        let raw = std::fs::read(dir.path().join("blobs").join(&hex[..2]).join(&hex))
            .expect("read raw file");
        assert!(
            !raw.windows(plaintext.len())
                .any(|w| w == plaintext.as_slice()),
            "plaintext must not appear in the stored file"
        );
    }

    #[test]
    fn wrong_master_key_cannot_decrypt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store1 = store(dir.path());
        let id = store1.put(b"secret").expect("put");

        // Same blob directory, different master key.
        let other_dir = tempfile::tempdir().expect("tempdir");
        let other_master =
            MasterKey::load_or_create(&other_dir.path().join(MASTER_KEY_FILE)).expect("key");
        let store2 = BlobStore::open(dir.path().join("blobs"), other_master).expect("open");
        assert!(matches!(store2.get(&id), Err(StorageError::Crypto(_))));
    }

    #[test]
    fn missing_blob_is_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        let id = BlobId([7u8; 32]);
        assert!(matches!(store.get(&id), Err(StorageError::BlobNotFound(_))));
    }

    #[test]
    fn tampered_file_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path());
        let id = store.put(b"tamper me").expect("put");

        let hex = id.to_hex();
        let path = dir.path().join("blobs").join(&hex[..2]).join(&hex);
        let mut raw = std::fs::read(&path).expect("read");
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&path, &raw).expect("write");

        assert!(matches!(store.get(&id), Err(StorageError::Crypto(_))));
    }
}
