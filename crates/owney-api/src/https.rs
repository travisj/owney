use anyhow::Context;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Loads TLS configuration from certificate and key files.
pub fn load_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("opening {}", cert_path.display()))?;
    let mut reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing certificate chain")?;
    anyhow::ensure!(
        !certs.is_empty(),
        "{} contains no certificates",
        cert_path.display()
    );

    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("opening {}", key_path.display()))?;
    let mut reader = std::io::BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)
        .context("parsing private key")?
        .with_context(|| format!("{} contains no private key", key_path.display()))?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS config")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
