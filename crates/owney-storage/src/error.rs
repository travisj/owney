use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("io error on {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("database error")]
    Sqlite(#[from] rusqlite::Error),

    #[error("crypto failure: {0}")]
    Crypto(&'static str),

    #[error("corrupt data: {0}")]
    Corrupt(String),

    #[error("bad input: {0}")]
    BadInput(String),

    #[error("blob {0} not found")]
    BlobNotFound(owney_core::BlobId),

    #[error("account not found")]
    AccountNotFound,

    #[error("storage is shut down")]
    Closed,

    #[error("writer panicked: {0}")]
    WriterPanicked(String),
}

impl StorageError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
