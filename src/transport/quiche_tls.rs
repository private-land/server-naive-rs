//! TLS path wrapper for the quiche/tokio-quiche H3 backend.
//!
//! tokio-quiche's `TlsCertificatePaths<'p>` borrows `&'p str` for cert/key
//! paths. This module provides an owning struct that holds the paths as
//! `String` and can be borrowed as `TlsCertificatePaths<'_>` when needed.

use anyhow::Result;
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
    pub fn new(_cert_path: &Path, _key_path: &Path) -> Result<Self> {
        // Stub for A1 red: returns empty strings so the test fails on the
        // path-equality assertion (a meaningful failure mode) rather than the
        // error path.
        Ok(Self {
            cert: String::new(),
            private_key: String::new(),
        })
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
