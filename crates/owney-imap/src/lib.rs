//! IMAP4rev2 (RFC 9051) read-only bridge for Owney.
//!
//! External IMAP clients (Thunderbird, Apple Mail, iOS Mail) read the mailbox
//! via standard IMAP. Send commands (APPEND, etc.) are rejected with a directive
//! to use JMAP instead. This preserves end-to-end encryption and signing.
//!
//! Supported commands:
//! - LOGIN/AUTHENTICATE
//! - SELECT (mailbox)
//! - SEARCH, FETCH, STATUS
//! - LIST, LSUB, NAMESPACE
//! - NOOP, LOGOUT, STARTTLS
//!
//! Blocked commands (must use JMAP):
//! - APPEND (send → use JMAP EmailSubmission)
//! - STORE (flags → use JMAP Email/set)
//! - DELETE, EXPUNGE (→ use JMAP Email/set with destroy)

pub mod commands;
pub mod server;
pub mod session;

use std::net::IpAddr;
use std::sync::Arc;

use owney_core::Config;
use owney_storage::Storage;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::info;

pub use server::serve_imap;
pub use session::ImapSession;

/// Spawn IMAP4rev2 listener on the configured port.
pub async fn spawn_imap_listener(
    config: Arc<Config>,
    storage: Arc<Storage>,
) -> Result<JoinHandle<()>, anyhow::Error> {
    let imap_listen = config.imap.listen.clone();
    let listener = TcpListener::bind(&imap_listen).await?;
    info!("IMAP4rev2 listening on {}", imap_listen);

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let storage = storage.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_imap(stream, peer_addr.ip(), storage).await {
                            tracing::debug!("IMAP session error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("IMAP accept error: {}", e);
                }
            }
        }
    });

    Ok(handle)
}
