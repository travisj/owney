//! TCP accept loop for one SMTP listener.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::{MailHandler, SmtpParams};

/// Hard cap on concurrent SMTP sessions per listener; connections beyond it
/// are greeted with 421 and closed rather than left hanging.
const MAX_CONNECTIONS: usize = 512;

/// Accept connections forever. Cancel by dropping/aborting the task running it.
pub async fn run_listener<H: MailHandler>(
    listener: TcpListener,
    params: Arc<SmtpParams>,
    handler: Arc<H>,
) {
    let limiter = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let local = listener.local_addr().ok();
    tracing::info!(addr = ?local, "smtp listener started");

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // Transient accept errors (EMFILE, ECONNABORTED) shouldn't
                // kill the listener.
                tracing::warn!(%err, "accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let Ok(permit) = limiter.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "connection limit reached, rejecting");
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = stream
                    .write_all(b"421 4.3.2 too busy, try again later\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
            continue;
        };

        let params = params.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            tracing::debug!(%peer, "smtp connection opened");
            crate::session::serve_connection(stream, peer.ip(), params, handler).await;
            tracing::debug!(%peer, "smtp connection closed");
            drop(permit);
        });
    }
}
