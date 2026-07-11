//! Shared domain model: ids, configuration, and the error taxonomy.
//!
//! Every other crate in the workspace depends on `ms-core` and nothing in
//! `ms-core` depends on the rest of the workspace. Traits that firewall risky
//! third-party dependencies (PGP backend, FTS engine, AI provider) also live
//! here as they are introduced by later milestones.

pub mod config;
pub mod error;
pub mod id;
pub mod time;

pub use config::Config;
pub use error::ConfigError;
pub use id::{AccountId, BlobId, DataType, EmailId, MailboxId, ModSeq, ThreadId};

/// Firewall trait: hand a composed message to the outbound pipeline.
/// Implemented by ms-delivery; consumed by the JMAP/REST/MCP surfaces so they
/// never depend on delivery internals.
pub trait Submitter: Send + Sync {
    /// Sign, store the Sent copy, and enqueue for each recipient. Returns the
    /// queue ids.
    fn submit(
        &self,
        account_id: AccountId,
        mail_from: String,
        recipients: Vec<String>,
        raw: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<uuid::Uuid>, String>> + Send + '_>>;
}
