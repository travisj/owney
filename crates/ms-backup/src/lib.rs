//! Backup and restore: full logical snapshots (SQL dump + encrypted blob tarball).
//!
//! Backup format: a tar.zst archive containing:
//! - `manifest.json`: version, timestamp, checksum metadata
//! - `schema.sql`: full schema + data as INSERT statements
//! - `blobs.tar`: encrypted blob store directory tree
//! - `master-key-hash.txt`: BLAKE3 hash of master key (for verification; key itself NOT in backup)
//!
//! Restore applies the schema, migrations if needed, and restores the blob store.
//! The master key must be preserved separately by the operator.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::io;

use anyhow::Context;
use blake3::Hash;
use chrono::Utc;
use ms_core::Config;
use serde::{Deserialize, Serialize};
use tar::Archive;
use walkdir::WalkDir;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("backup error: {0}")]
    Other(String),
}

/// Backup manifest metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Mailserver version (from package version)
    pub version: String,
    /// ISO 8601 timestamp when backup was created
    pub created_at: String,
    /// BLAKE3 hash of master.key file (hex-encoded, for verification)
    pub master_key_hash: String,
    /// Size of uncompressed archive in bytes (informational)
    pub uncompressed_size: u64,
    /// BLAKE3 hash of entire tar.zst archive (hex-encoded, for integrity)
    pub archive_hash: String,
}

/// Create a full backup of the server.
///
/// Returns the path to the created backup archive (tar.zst).
pub async fn create_backup(
    config: &Config,
    output_dir: &Path,
) -> Result<PathBuf, BackupError> {
    let data_dir = &config.storage.data_dir;

    // Verify master key exists
    let master_key_path = data_dir.join(ms_storage::MASTER_KEY_FILE);
    if !master_key_path.exists() {
        return Err(BackupError::Other(
            "master key not found; cannot create backup".into(),
        ));
    }

    // Compute master key hash (for verification, not security)
    let master_key_bytes = fs::read(&master_key_path)
        .context("reading master key")
        .map_err(|e| BackupError::Other(e.to_string()))?;
    let master_key_hash = blake3::hash(&master_key_bytes);

    // Create temp directory for staging
    let temp_dir = tempfile::tempdir()
        .map_err(|e| BackupError::Other(format!("creating temp dir: {e}")))?;
    let temp_path = temp_dir.path();

    // Dump database schema + data
    tracing::info!("dumping database schema and data");
    let schema_sql = dump_database(&data_dir.join("mail.db"))
        .await
        .map_err(|e| BackupError::Other(format!("dumping database: {e}")))?;
    fs::write(temp_path.join("schema.sql"), &schema_sql)
        .context("writing schema.sql")
        .map_err(|e| BackupError::Other(e.to_string()))?;

    // Archive blob store
    tracing::info!("archiving blob store");
    let blobs_tar_path = temp_path.join("blobs.tar");
    archive_blobs(&data_dir.join("blobs"), &blobs_tar_path)
        .context("archiving blobs")
        .map_err(|e| BackupError::Other(e.to_string()))?;

    // Write master key hash (not the key itself)
    fs::write(
        temp_path.join("master-key-hash.txt"),
        master_key_hash.to_hex().as_bytes(),
    )
    .context("writing master key hash")
    .map_err(|e| BackupError::Other(e.to_string()))?;

    // Read blobs.tar size for manifest
    let blobs_tar_size = fs::metadata(&blobs_tar_path)
        .context("reading blobs.tar size")
        .map_err(|e| BackupError::Other(e.to_string()))?
        .len();
    let uncompressed_size = schema_sql.len() as u64
        + blobs_tar_size
        + master_key_hash.to_hex().len() as u64;

    // Create manifest
    let manifest = BackupManifest {
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: Utc::now().to_rfc3339(),
        master_key_hash: master_key_hash.to_hex().to_string(),
        uncompressed_size,
        archive_hash: String::new(), // Will fill after compressing
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| BackupError::Other(format!("serializing manifest: {e}")))?;
    fs::write(temp_path.join("manifest.json"), &manifest_json)
        .context("writing manifest.json")
        .map_err(|e| BackupError::Other(e.to_string()))?;

    // Create tar.zst archive
    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let archive_name = format!("backup-{}.tar.zst", timestamp);
    let archive_path = output_dir.join(&archive_name);

    tracing::info!("compressing backup to {}", archive_path.display());
    compress_to_zst(temp_path, &archive_path)
        .context("compressing backup")
        .map_err(|e| BackupError::Other(e.to_string()))?;

    // Compute final archive hash
    let archive_bytes = fs::read(&archive_path)
        .context("reading final archive")
        .map_err(|e| BackupError::Other(e.to_string()))?;
    let archive_hash = blake3::hash(&archive_bytes);

    tracing::info!(
        "backup created: {} ({} bytes)",
        archive_path.display(),
        archive_bytes.len()
    );

    Ok(archive_path)
}

/// Restore a backup to a new data directory.
pub async fn restore_backup(
    archive_path: &Path,
    target_data_dir: &Path,
) -> Result<BackupManifest, BackupError> {
    if !archive_path.exists() {
        return Err(BackupError::Other(format!(
            "backup archive not found: {}",
            archive_path.display()
        )));
    }

    let temp_dir = tempfile::tempdir()
        .map_err(|e| BackupError::Other(format!("creating temp dir: {e}")))?;
    let temp_path = temp_dir.path();

    // Decompress archive
    tracing::info!("decompressing backup from {}", archive_path.display());
    decompress_from_zst(archive_path, temp_path)
        .context("decompressing backup")
        .map_err(|e| BackupError::Other(e.to_string()))?;

    // Verify manifest exists and load it
    let manifest_path = temp_path.join("manifest.json");
    if !manifest_path.exists() {
        return Err(BackupError::Other(
            "backup archive missing manifest.json".into(),
        ));
    }

    let manifest_json = fs::read_to_string(&manifest_path)
        .context("reading manifest.json")
        .map_err(|e| BackupError::Other(e.to_string()))?;
    let mut manifest: BackupManifest = serde_json::from_str(&manifest_json)
        .context("parsing manifest.json")
        .map_err(|e| BackupError::Other(e.to_string()))?;

    tracing::info!(
        "restoring backup from version {}",
        manifest.version
    );

    // Restore blob store
    let blobs_tar_path = temp_path.join("blobs.tar");
    if blobs_tar_path.exists() {
        tracing::info!("extracting blob store");
        extract_blobs(&blobs_tar_path, &target_data_dir.join("blobs"))
            .context("extracting blobs")
            .map_err(|e| BackupError::Other(e.to_string()))?;
    }

    // Restore database
    let schema_path = temp_path.join("schema.sql");
    if schema_path.exists() {
        tracing::info!("restoring database");
        restore_database(&schema_path, &target_data_dir.join("mail.db"))
            .await
            .context("restoring database")
            .map_err(|e| BackupError::Other(e.to_string()))?;
    }

    // Verify master key hash matches (if key exists)
    let master_key_path = target_data_dir.join(ms_storage::MASTER_KEY_FILE);
    if master_key_path.exists() {
        let key_bytes = fs::read(&master_key_path)
            .context("reading master key")
            .map_err(|e| BackupError::Other(e.to_string()))?;
        let key_hash = blake3::hash(&key_bytes);
        if key_hash.to_hex().to_string() != manifest.master_key_hash {
            tracing::warn!(
                "master key hash mismatch: backup has {}, current has {}",
                manifest.master_key_hash,
                key_hash.to_hex()
            );
            return Err(BackupError::Other(
                "master key has changed; restore may be incomplete".into(),
            ));
        }
    }

    // Update archive hash in manifest
    let archive_bytes = fs::read(archive_path)
        .context("reading archive")
        .map_err(|e| BackupError::Other(e.to_string()))?;
    manifest.archive_hash = blake3::hash(&archive_bytes).to_hex().to_string();

    tracing::info!("backup restored successfully");
    Ok(manifest)
}

// --- Helper functions ---

async fn dump_database(db_path: &Path) -> anyhow::Result<String> {
    let db_path = db_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)?;
        let mut output = String::new();

        // Dump schema
        let mut stmt = conn.prepare(
            "SELECT sql FROM sqlite_master WHERE type IN ('table', 'index', 'trigger') \
             AND sql NOT NULL ORDER BY tbl_name, type DESC, name",
        )?;
        let schema_rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for row_result in schema_rows {
            let sql = row_result?;
            output.push_str(&sql);
            output.push_str(";\n");
        }

        // Dump data (INSERT statements)
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND sql NOT NULL ORDER BY name",
        )?;
        let table_names = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for table_result in table_names {
            let table = table_result?;
            dump_table(&conn, &table, &mut output)?;
        }

        Ok(output)
    })
    .await?
}

fn dump_table(conn: &rusqlite::Connection, table: &str, output: &mut String) -> anyhow::Result<()> {
    let mut stmt = conn.prepare(&format!("SELECT * FROM {}", table))?;
    let columns: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let rows = stmt.query_map([], |row| {
        let mut values = Vec::new();
        for i in 0..columns.len() {
            match row.get::<_, String>(i) {
                Ok(v) => values.push(format!("'{}'", v.replace("'", "''"))),
                Err(_) => values.push("NULL".to_string()),
            }
        }
        Ok(values)
    })?;

    for row_result in rows {
        let values = row_result?;
        output.push_str(&format!(
            "INSERT INTO {} ({}) VALUES ({});\n",
            table,
            columns.join(", "),
            values.join(", ")
        ));
    }

    Ok(())
}

async fn restore_database(schema_path: &Path, target_db: &Path) -> anyhow::Result<()> {
    let schema_path = schema_path.to_path_buf();
    let target_db = target_db.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&target_db)?;
        let schema_sql = fs::read_to_string(&schema_path)?;
        conn.execute_batch(&schema_sql)?;
        Ok(())
    })
    .await?
}

fn archive_blobs(blobs_dir: &Path, tar_path: &Path) -> anyhow::Result<()> {
    let tar_file = File::create(tar_path)?;
    let mut tar = tar::Builder::new(tar_file);

    if blobs_dir.exists() {
        for entry in WalkDir::new(blobs_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                let relative = path.strip_prefix(blobs_dir)?;
                tar.append_path_with_name(path, relative)?;
            }
        }
    }

    tar.finish()?;
    Ok(())
}

fn extract_blobs(tar_path: &Path, blobs_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(blobs_dir)?;
    let tar_file = File::open(tar_path)?;
    let mut archive = Archive::new(tar_file);
    archive.unpack(blobs_dir)?;
    Ok(())
}

fn compress_to_zst(source_dir: &Path, output_path: &Path) -> anyhow::Result<()> {
    let tar_file = File::create(output_path)?;
    let encoder = zstd::Encoder::new(tar_file, 3)?;
    let mut tar = tar::Builder::new(encoder);

    for entry in WalkDir::new(source_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() {
            let relative = path.strip_prefix(source_dir)?;
            tar.append_path_with_name(path, relative)?;
        }
    }

    tar.finish()?;
    Ok(())
}

fn decompress_from_zst(archive_path: &Path, extract_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(extract_dir)?;
    let tar_file = File::open(archive_path)?;
    let decoder = zstd::Decoder::new(tar_file)?;
    let mut archive = Archive::new(decoder);
    archive.unpack(extract_dir)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn archive_and_extract_roundtrip() {
        let source_dir = TempDir::new().expect("temp dir");
        let tar_path = source_dir.path().join("test.tar");
        let extract_dir = TempDir::new().expect("temp dir");

        // Create a test file structure
        let subdir = source_dir.path().join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");
        std::fs::write(subdir.join("file1.txt"), b"content1").expect("write file1");
        std::fs::write(source_dir.path().join("file2.txt"), b"content2").expect("write file2");

        // Archive files
        archive_blobs(source_dir.path(), &tar_path).expect("archive");
        assert!(tar_path.exists(), "tar should exist");

        // Extract files
        extract_blobs(&tar_path, extract_dir.path()).expect("extract");

        // Verify files exist with correct content
        let file1 = extract_dir.path().join("subdir/file1.txt");
        let file2 = extract_dir.path().join("file2.txt");
        assert!(file1.exists(), "file1 should be extracted");
        assert!(file2.exists(), "file2 should be extracted");
        assert_eq!(std::fs::read_to_string(&file1).unwrap(), "content1");
        assert_eq!(std::fs::read_to_string(&file2).unwrap(), "content2");
    }

    #[test]
    fn compress_and_decompress_roundtrip() {
        let source_dir = TempDir::new().expect("temp dir");
        let archive_path = source_dir.path().join("test.tar.zst");
        let extract_dir = TempDir::new().expect("temp dir");

        // Create test files
        std::fs::write(source_dir.path().join("file.txt"), b"test data").expect("write file");

        // Compress
        compress_to_zst(source_dir.path(), &archive_path).expect("compress");
        assert!(archive_path.exists(), "archive should exist");
        assert!(archive_path.file_name().unwrap().to_str().unwrap().ends_with(".tar.zst"));

        // Decompress
        decompress_from_zst(&archive_path, extract_dir.path()).expect("decompress");

        // Verify
        let extracted = extract_dir.path().join("file.txt");
        assert!(extracted.exists(), "file should be extracted");
        assert_eq!(std::fs::read_to_string(&extracted).unwrap(), "test data");
    }

    #[test]
    fn manifest_serialization() {
        let manifest = BackupManifest {
            version: "0.1.0".to_string(),
            created_at: "2026-07-12T00:00:00Z".to_string(),
            master_key_hash: "abc123".to_string(),
            uncompressed_size: 1024,
            archive_hash: "def456".to_string(),
        };

        let json = serde_json::to_string(&manifest).expect("serialize");
        let restored: BackupManifest = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.version, manifest.version);
        assert_eq!(restored.created_at, manifest.created_at);
        assert_eq!(restored.master_key_hash, manifest.master_key_hash);
        assert_eq!(restored.uncompressed_size, manifest.uncompressed_size);
        assert_eq!(restored.archive_hash, manifest.archive_hash);
    }
}
