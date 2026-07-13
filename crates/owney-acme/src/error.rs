use thiserror::Error;

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("ACME request failed: {0}")]
    AcmeRequest(String),

    #[error("DNS provider error: {0}")]
    DnsProvider(String),

    #[error("Challenge validation failed: {0}")]
    ChallengeValidation(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("Timeout waiting for DNS propagation")]
    DnsTimeout,

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Certificate not found or expired")]
    CertificateNotFound,
}
