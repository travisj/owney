//! IMAP connection handler.

use std::net::IpAddr;
use std::sync::Arc;

use owney_storage::Storage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use crate::session::ImapSession;

/// Handle one IMAP connection from start to finish.
pub async fn serve_imap(
    mut stream: TcpStream,
    remote: IpAddr,
    storage: Arc<Storage>,
) -> anyhow::Result<()> {
    info!("IMAP connection from {}", remote);

    // Send greeting (RFC 9051 §7.1)
    stream
        .write_all(b"* OK Owney IMAP4rev2 ready\r\n")
        .await?;
    stream.flush().await?;

    let mut session = ImapSession::new(storage, remote);
    let mut buffer = vec![0u8; 8192];

    loop {
        match stream.read(&mut buffer).await? {
            0 => {
                // Connection closed
                info!("IMAP connection closed from {}", remote);
                break;
            }
            n => {
                let input = &buffer[..n];
                match session.handle_input(input).await {
                    Ok(Some(response)) => {
                        stream.write_all(&response).await?;
                        stream.flush().await?;
                    }
                    Ok(None) => {
                        // Silent (e.g., during multi-line data)
                    }
                    Err(e) => {
                        let err_response = format!("* BYE {}\r\n", e);
                        let _ = stream.write_all(err_response.as_bytes()).await;
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
