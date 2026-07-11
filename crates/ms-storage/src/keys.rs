//! The master key: a 32-byte secret generated at first startup, stored in a
//! mode-0600 keyfile inside the data directory. Every per-blob encryption key
//! and (from M4) every PGP secret key is wrapped by it.
//!
//! Lose the data directory but keep this file: blobs from a backup remain
//! readable. Lose this file: the data is gone. `ms-backup` (M6) treats it
//! accordingly.

use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::error::StorageError;

pub const MASTER_KEY_FILE: &str = "master.key";

#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn load_or_create(path: &Path) -> Result<Self, StorageError> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let key: [u8; 32] = bytes.try_into().map_err(|_| {
                    StorageError::Corrupt(format!("{} is not a 32-byte master key", path.display()))
                })?;
                Ok(Self(key))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).map_err(|_| StorageError::Crypto("os rng"))?;

                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options
                    .open(path)
                    .map_err(|source| StorageError::io(path, source))?;
                file.write_all(&key)
                    .map_err(|source| StorageError::io(path, source))?;
                file.sync_all()
                    .map_err(|source| StorageError::io(path, source))?;
                tracing::info!(path = %path.display(), "generated new master key");
                Ok(Self(key))
            }
            Err(source) => Err(StorageError::io(path, source)),
        }
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_reload_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(MASTER_KEY_FILE);

        let first = MasterKey::load_or_create(&path).expect("create");
        let second = MasterKey::load_or_create(&path).expect("reload");
        assert_eq!(first.bytes(), second.bytes());
    }

    #[cfg(unix)]
    #[test]
    fn keyfile_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(MASTER_KEY_FILE);
        MasterKey::load_or_create(&path).expect("create");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "master key must be 0600");
    }

    #[test]
    fn truncated_keyfile_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(MASTER_KEY_FILE);
        std::fs::write(&path, b"short").expect("write");
        assert!(matches!(
            MasterKey::load_or_create(&path),
            Err(StorageError::Corrupt(_))
        ));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(MASTER_KEY_FILE);
        let key = MasterKey::load_or_create(&path).expect("create");
        assert_eq!(format!("{key:?}"), "MasterKey(<redacted>)");
    }
}
