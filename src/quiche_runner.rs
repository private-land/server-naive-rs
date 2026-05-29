//! H3/QUIC accept loop built on tokio-quiche (PoC migration; see plan
//! `quiet-tinkering-raven.md`).
//!
//! This module sits alongside `server_runner.rs` during the PoC: the runtime
//! `--h3_backend` CLI flag selects between the legacy quinn+h3 path
//! ([`crate::server_runner::run_h3_server`]) and the new tokio-quiche path
//! ([`run_h3_server_quiche`]).
//!
//! The current step (A3) is just the `make_quiche_settings` builder.

use crate::config;
use crate::transport::quiche_tls::QuicheTlsPaths;
use anyhow::Result;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::QuicConnectionStream;

/// Bind a UDP socket to a tokio-quiche HTTP/3 listener.  Returns the
/// `QuicConnectionStream` for the bound socket; each `next().await` yields one
/// accepted (handshake-complete) QUIC connection.
pub fn bind_h3_listener(
    socket: tokio::net::UdpSocket,
    settings: QuicSettings,
    tls: &QuicheTlsPaths,
) -> Result<QuicConnectionStream<DefaultMetrics>> {
    use tokio_quiche::settings::{CertificateKind, ConnectionParams, Hooks, TlsCertificatePaths};

    let tls_paths = TlsCertificatePaths {
        cert: tls.cert(),
        private_key: tls.private_key(),
        kind: CertificateKind::X509,
    };
    let params = ConnectionParams::new_server(settings, tls_paths, Hooks::default());

    let listeners = tokio_quiche::listen([socket], params, DefaultMetrics)
        .map_err(|e| anyhow::anyhow!("tokio_quiche::listen failed: {e}"))?;

    listeners
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("tokio_quiche::listen returned no listener"))
}

/// Build a `QuicSettings` for the tokio-quiche server, mirroring the tuning
/// `server_runner::make_transport_config` applies to the quinn `TransportConfig`.
///
/// Returned as a free function so unit tests can exercise every CC variant
/// without spinning up a real QUIC endpoint.
#[allow(dead_code)] // wired into runtime starting in A5; kept allow until then.
pub fn make_quiche_settings(cc: &config::CongestionControl) -> QuicSettings {
    use config::CongestionControl;

    // `QuicSettings` is `#[non_exhaustive]`, so we start from Default and
    // overwrite only the fields we care about.  tokio-quiche already defaults
    // `alpn` to `[b"h3"]`, but we set it explicitly to document the contract:
    // a regression that nukes the field would still fail A3 here.
    let mut settings = QuicSettings::default();
    settings.alpn = vec![b"h3".to_vec()];

    // CC mapping: the strings come from quiche's
    // `CongestionControlAlgorithm::FromStr` impl (quiche 0.29).  BBRv2 needs
    // the `gcongestion` cargo feature — already enabled on the dep.
    settings.cc_algorithm = match cc {
        CongestionControl::Bbr => "bbr2_gcongestion".to_string(),
        CongestionControl::Cubic => "cubic".to_string(),
        CongestionControl::NewReno => "reno".to_string(),
    };

    settings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CongestionControl;

    /// A3 — The H3 backend must advertise ALPN `h3` so QUIC clients (cronet,
    /// sing-box, quinn) can negotiate the H3 protocol on the connection.
    #[test]
    fn quiche_make_settings_alpn_h3() {
        let settings = make_quiche_settings(&CongestionControl::Cubic);
        assert_eq!(
            settings.alpn,
            vec![b"h3".to_vec()],
            "QUIC settings must advertise ALPN h3"
        );
    }

    // A4 — Map config::CongestionControl variants to the strings quiche's
    // `CongestionControlAlgorithm::FromStr` accepts.  Validated against the
    // quiche 0.29 docs:
    //   Reno              -> "reno"
    //   CUBIC             -> "cubic"
    //   Bbr2Gcongestion   -> "bbr2_gcongestion"   (requires `gcongestion` feature)

    #[test]
    fn quiche_make_settings_bbr2_when_bbr_requested() {
        let settings = make_quiche_settings(&CongestionControl::Bbr);
        assert_eq!(
            settings.cc_algorithm, "bbr2_gcongestion",
            "CC::Bbr must map to BBRv2 from the gcongestion branch"
        );
    }

    #[test]
    fn quiche_make_settings_cubic_when_cubic_requested() {
        let settings = make_quiche_settings(&CongestionControl::Cubic);
        assert_eq!(settings.cc_algorithm, "cubic");
    }

    #[test]
    fn quiche_make_settings_reno_when_newreno_requested() {
        let settings = make_quiche_settings(&CongestionControl::NewReno);
        assert_eq!(settings.cc_algorithm, "reno");
    }

    // ── A5 integration: real QUIC handshake — quinn client vs. quiche server ──
    mod integration {
        use super::super::*;
        use crate::config::CongestionControl;
        use futures_util::StreamExt;
        use rustls::pki_types::CertificateDer;
        use std::io::Write;
        use std::sync::Arc;
        use std::time::Duration;
        use tempfile::NamedTempFile;
        use tokio::net::UdpSocket;

        fn install_crypto() {
            static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            });
        }

        /// Generate a self-signed cert pair, write PEMs to temp files, and
        /// return the DER cert too so the quinn client can trust it.
        fn gen_cert_files() -> (NamedTempFile, NamedTempFile, CertificateDer<'static>) {
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
            let cert_der: CertificateDer<'static> = cert.into();
            (cert_file, key_file, cert_der)
        }

        async fn quinn_connect(
            cert: CertificateDer<'static>,
            server_addr: std::net::SocketAddr,
        ) -> anyhow::Result<quinn::Connection> {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert)?;
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let cc = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
            ));
            let mut ep = quinn::Endpoint::client("[::]:0".parse()?)?;
            ep.set_default_client_config(cc);
            Ok(ep.connect(server_addr, "localhost")?.await?)
        }

        /// A5 — Bringing up a quiche listener and connecting from a quinn
        /// client must complete the QUIC TLS 1.3 handshake with ALPN `h3`
        /// negotiated.
        #[tokio::test(flavor = "multi_thread")]
        async fn quiche_accept_quic_handshake() {
            install_crypto();
            let (cert_file, key_file, cert_der) = gen_cert_files();
            let tls = QuicheTlsPaths::new(cert_file.path(), key_file.path()).unwrap();
            let settings = make_quiche_settings(&CongestionControl::Cubic);

            let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
            let server_addr = server_socket.local_addr().unwrap();

            let mut listener =
                bind_h3_listener(server_socket, settings, &tls).expect("listener bind");

            // Accept the InitialQuicConnection and call `.start(driver)` so
            // tokio-quiche actually drives the QUIC handshake.  Without the
            // driver the server never responds to the client's CHLO; we
            // discovered this the hard way in A5's first green attempt.
            let accept_task = tokio::spawn(async move {
                let initial = tokio::time::timeout(Duration::from_secs(15), listener.next())
                    .await
                    .ok()
                    .flatten()
                    .and_then(|res| res.ok());
                if let Some(conn) = initial {
                    let (driver, mut controller) = tokio_quiche::ServerH3Driver::new(
                        tokio_quiche::http3::settings::Http3Settings::default(),
                    );
                    conn.start(driver);
                    // Keep the controller alive long enough for the handshake
                    // to flush through.  We don't read any events for A5.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(15),
                        controller.event_receiver_mut().recv(),
                    )
                    .await;
                }
            });

            let conn = tokio::time::timeout(
                Duration::from_secs(10),
                quinn_connect(cert_der, server_addr),
            )
            .await
            .expect("client connect should not time out")
            .expect("client connect should succeed");

            // ALPN check: quinn surfaces the negotiated protocol via
            // handshake_data downcast to rustls::HandshakeData.
            let hd = conn
                .handshake_data()
                .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .expect("handshake data should be rustls");
            assert_eq!(hd.protocol.as_deref(), Some(&b"h3"[..]), "ALPN must be h3");

            drop(conn);
            accept_task.abort();
        }
    }
}
