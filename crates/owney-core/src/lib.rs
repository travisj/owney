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
pub use id::{
    AccountId, BlobId, BookingId, CalendarId, ContactId, CreateId, DataType, EmailId,
    EmailSubmissionId, EventId, MailboxId, ModSeq, SchedulingPageId, ThreadId,
};
