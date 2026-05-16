//! TLS configuration for Naive proxy server.
//!
//! Naive requires TLS with ALPN "h2" to negotiate HTTP/2.

use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// Load TLS ServerConfig from cert+key files with ALPN h2 enabled.
pub fn load_tls_config(cert_path: &Path, key_path: &Path) -> std::io::Result<Arc<ServerConfig>> {
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No certificates found in cert file",
        ));
    }

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "No private key found")
    })?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Naive requires HTTP/2 via ALPN negotiation
    config.alpn_protocols = vec![b"h2".to_vec()];

    // Session tickets for faster reconnection
    if let Ok(ticketer) = rustls::crypto::aws_lc_rs::Ticketer::new() {
        config.ticketer = ticketer;
    }

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_tls_config_invalid_cert() {
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(b"invalid cert").unwrap();
        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"invalid key").unwrap();
        let result = load_tls_config(cert_file.path(), key_file.path());
        assert!(result.is_err());
    }
}
