//! Error taxonomy.
//!
//! Each crate defines its own error enum near the code that raises it;
//! `ms-core` holds only the errors for types it owns.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read config file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not parse config file {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },

    #[error("invalid config: {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
}
