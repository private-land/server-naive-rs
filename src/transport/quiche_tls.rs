//! TLS path wrapper for the quiche/tokio-quiche H3 backend.
//!
//! tokio-quiche's `TlsCertificatePaths<'p>` borrows `&'p str` for cert/key
//! paths. This module provides an owning struct that holds the paths as
//! `String` and can be borrowed as `TlsCertificatePaths<'_>` when needed.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

/// Owns PEM cert/key file paths for tokio-quiche TLS configuration.
#[allow(dead_code)] // wired into runtime starting in A5; kept allow until then.
pub struct QuicheTlsPaths {
    cert: String,
    private_key: String,
}

#[allow(dead_code)] // wired into runtime starting in A5; kept allow until then.
impl QuicheTlsPaths {
    /// Validate cert/key paths are readable PEM files and return an owner that
    /// can later be borrowed as `tokio_quiche::settings::TlsCertificatePaths`.
    ///
    /// Validation is intentionally shallow — we confirm the file is readable
    /// and contains the expected PEM markers. Full ASN.1 / key-material
    /// parsing is deferred to BoringSSL inside tokio-quiche at handshake time;
    /// duplicating that check here would mean pulling in a PEM parser just to
    /// fail one millisecond earlier.
    pub fn new(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_content = std::fs::read_to_string(cert_path)
            .with_context(|| format!("reading cert {}", cert_path.display()))?;
        if !cert_content.contains("BEGIN CERTIFICATE") {
            return Err(anyhow!(
                "not a PEM certificate (missing BEGIN CERTIFICATE marker): {}",
                cert_path.display()
            ));
        }

        let key_content = std::fs::read_to_string(key_path)
            .with_context(|| format!("reading key {}", key_path.display()))?;
        // Accept any "-----BEGIN <kind> PRIVATE KEY-----" marker so PKCS#8,
        // EC PRIVATE KEY, RSA PRIVATE KEY, and ED25519 variants all work.
        if !key_content.contains("PRIVATE KEY-----") {
            return Err(anyhow!(
                "not a PEM private key (no PRIVATE KEY marker): {}",
                key_path.display()
            ));
        }

        let cert = cert_path
            .to_str()
            .ok_or_else(|| anyhow!("cert path is not valid UTF-8: {}", cert_path.display()))?
            .to_owned();
        let private_key = key_path
            .to_str()
            .ok_or_else(|| anyhow!("key path is not valid UTF-8: {}", key_path.display()))?
            .to_owned();

        Ok(Self { cert, private_key })
    }

    pub fn cert(&self) -> &str {
        &self.cert
    }

    pub fn private_key(&self) -> &str {
        &self.private_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_self_signed_pem() -> (NamedTempFile, NamedTempFile) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert.pem().as_bytes()).unwrap();
        cert_file.flush().unwrap();
        let mut key_file = NamedTempFile::new().unwrap();
        key_file
            .write_all(signing_key.serialize_pem().as_bytes())
            .unwrap();
        key_file.flush().unwrap();
        (cert_file, key_file)
    }

    /// A1 — Constructing `QuicheTlsPaths` over a valid self-signed PEM pair
    /// must succeed and expose the input paths as `&str`.
    #[test]
    fn quiche_tls_loads_pem_files_ok() {
        let (cert, key) = write_self_signed_pem();
        let paths = QuicheTlsPaths::new(cert.path(), key.path()).expect("PEM should load");
        assert_eq!(paths.cert(), cert.path().to_str().unwrap());
        assert_eq!(paths.private_key(), key.path().to_str().unwrap());
    }
}
