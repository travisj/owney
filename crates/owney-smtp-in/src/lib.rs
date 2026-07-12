//! Inbound SMTP (the MX side).
//!
//! `session` is the per-connection protocol state machine, generic over any
//! `AsyncRead + AsyncWrite` (tested against in-memory duplex streams);
//! `server` is the TCP accept loop. Policy — who exists, where mail goes —
//! lives behind the [`MailHandler`] trait so this crate stays pure protocol.
//!
//! Ground rule (see PLAN.md): a message is rejected at SMTP time or accepted
//! for delivery — this server never accepts-then-bounces.

pub mod server;
pub mod session;

use std::net::IpAddr;

/// Outcome of recipient validation at RCPT time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcptVerdict {
    /// Local user exists; accept.
    Accept,
    /// The domain is ours but the user doesn't exist (550 5.1.1).
    UnknownUser,
    /// The domain is not ours; we don't relay (550 5.7.1).
    NotLocal,
    /// Validation infrastructure failed; soft-fail (451 4.3.0).
    TryAgainLater,
}

/// A fully received inbound message, ready for the ingest pipeline.
#[derive(Debug, Clone)]
pub struct InboundMail {
    pub remote: IpAddr,
    /// EHLO/HELO name as claimed by the client (empty if none was sent).
    pub helo: String,
    /// Envelope sender (empty string = null reverse-path, i.e. a bounce).
    pub mail_from: String,
    /// Envelope recipients, all previously accepted by `rcpt`.
    pub recipients: Vec<String>,
    /// Raw RFC 5322 message, dot-unstuffed, with our Received header prepended.
    pub raw: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
#[error("delivery failed: {0}")]
pub struct DeliverError(pub String);

/// Server policy: recipient validation and delivery.
pub trait MailHandler: Send + Sync + 'static {
    fn rcpt(&self, address: &str) -> impl Future<Output = RcptVerdict> + Send;
    fn deliver(&self, mail: InboundMail) -> impl Future<Output = Result<(), DeliverError>> + Send;
}

/// Per-listener settings, derived from `owney_core::config` at startup.
#[derive(Clone)]
pub struct SmtpParams {
    /// Our FQDN, used in the banner and Received headers.
    pub hostname: String,
    pub max_message_size: u64,
    pub max_recipients: usize,
    /// Consecutive protocol errors before the connection is dropped.
    pub max_errors: usize,
    /// Per-read timeout; RFC 5321 suggests 5 minutes.
    pub read_timeout: std::time::Duration,
    /// When present, STARTTLS is advertised and accepted.
    pub tls: Option<tokio_rustls::TlsAcceptor>,
}

impl std::fmt::Debug for SmtpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpParams")
            .field("hostname", &self.hostname)
            .field("max_message_size", &self.max_message_size)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl SmtpParams {
    pub fn from_config(config: &owney_core::Config) -> Self {
        Self {
            hostname: config.server.hostname.clone(),
            max_message_size: config.smtp.max_message_size,
            max_recipients: config.smtp.max_recipients,
            max_errors: config.smtp.max_errors,
            read_timeout: std::time::Duration::from_secs(config.smtp.read_timeout_secs),
            tls: None,
        }
    }

    pub fn with_tls(mut self, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }
}
