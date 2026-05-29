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
use crate::core::Server;
use crate::handler::process_h3_request_quiche;
use crate::logger::log;
use crate::transport::quiche_tls::QuicheTlsPaths;
use anyhow::Result;
use futures_util::{SinkExt as _, StreamExt};
use quiche::h3::Header;
use std::sync::Arc;
use tokio_quiche::http3::driver::{IncomingH3Headers, OutboundFrame, ServerH3Event};
use tokio_quiche::http3::settings::Http3Settings;
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

/// Build the per-connection HTTP/3 driver settings.
///
/// NaiveProxy uses HTTP CONNECT tunneling, which requires
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` (RFC 9220).  Cronet/sing-box clients
/// open the first CONNECT stream before the server's SETTINGS arrive
/// (succeeds) but refuse all subsequent CONNECT streams once SETTINGS is
/// processed and the flag is absent — exactly the bug that broke multi-thread
/// speed tests in the legacy quinn path (v0.1.2 fix).  We carry that lesson
/// forward here.
///
#[allow(dead_code)]
pub fn make_h3_settings() -> Http3Settings {
    Http3Settings {
        enable_extended_connect: true,
        ..Default::default()
    }
}

/// Send a minimal `200 OK` response on the CONNECT stream described by
/// `headers`.  The full handler (auth, padding, routing, relay) gets layered
/// on top of this in later steps.
///
/// The empty-body+fin frame after the headers is required: without it the
/// frame_sender drop terminates the stream as RemoteTerminate / CANCELLED
/// and the client never sees the headers.
#[allow(dead_code)]
pub async fn respond_200_to_connect(headers: IncomingH3Headers) {
    use tokio_quiche::buf_factory::BufFactory;
    use tokio_quiche::quiche::BufFactory as _;

    let IncomingH3Headers {
        send: mut frame_sender,
        ..
    } = headers;
    let response = vec![Header::new(b":status", b"200")];
    if frame_sender
        .send(OutboundFrame::Headers(response, None))
        .await
        .is_err()
    {
        return;
    }
    let empty = BufFactory::buf_from_slice(&[]);
    let _ = frame_sender.send(OutboundFrame::Body(empty, true)).await;
}

/// QUIC connection idle timeout — generous to survive cronet's
/// keep-alive cadence on long-lived tunnels.
const QUIC_MAX_IDLE_TIMEOUT_SECS: u64 = 120;

/// Per-connection flow-control window (~16 MB) — speedtest single-stream
/// uses one CONNECT and benefits from a large window.
const QUIC_INITIAL_MAX_DATA: u64 = 16 * 1024 * 1024;

/// Per-stream flow-control window (~2 MB local / 2 MB remote).
const QUIC_INITIAL_MAX_STREAM_DATA: u64 = 2 * 1024 * 1024;

/// Build a `QuicSettings` for the tokio-quiche server, mirroring the tuning
/// `server_runner::make_transport_config` applies to the quinn `TransportConfig`.
///
/// Returned as a free function so unit tests can exercise every CC variant
/// without spinning up a real QUIC endpoint.
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

    // Transport tuning that matches sing-box / quinn's effective profile.
    // PoC defaults — A11/A12/cronet smoke may tune further.
    settings.max_idle_timeout = Some(std::time::Duration::from_secs(QUIC_MAX_IDLE_TIMEOUT_SECS));
    // sing-box uses `1 << 60` for max streams; we mirror that (well under QUIC
    // VarInt's 2^62 ceiling).  Setting u64::MAX here triggers a transport-param
    // VarInt overflow on the wire and the handshake aborts with
    // "illegal value".  Lesson learned 2026-05-29.
    settings.initial_max_streams_bidi = 1u64 << 60;
    settings.initial_max_streams_uni = 256;
    settings.initial_max_data = QUIC_INITIAL_MAX_DATA;
    settings.initial_max_stream_data_bidi_local = QUIC_INITIAL_MAX_STREAM_DATA;
    settings.initial_max_stream_data_bidi_remote = QUIC_INITIAL_MAX_STREAM_DATA;
    settings.initial_max_stream_data_uni = QUIC_INITIAL_MAX_STREAM_DATA;
    settings.enable_dgram = false;
    settings.disable_active_migration = true;

    settings
}

/// Bind a dual-stack IPv6 UDP socket (also accepts IPv4 traffic) on the given
/// port, falling back to an IPv4-only socket if the dual-stack bind fails.
fn bind_dual_stack_udp(port: u16) -> Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let addr_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let try_v6 = || -> Result<tokio::net::UdpSocket> {
        let raw = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        raw.set_only_v6(false)?;
        raw.set_reuse_address(true)?;
        raw.bind(&SockAddr::from(addr_v6))?;
        raw.set_nonblocking(true)?;
        let std_sock: std::net::UdpSocket = raw.into();
        Ok(tokio::net::UdpSocket::from_std(std_sock)?)
    };

    match try_v6() {
        Ok(s) => Ok(s),
        Err(_) => {
            let addr_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            raw.set_reuse_address(true)?;
            raw.bind(&SockAddr::from(addr_v4))?;
            raw.set_nonblocking(true)?;
            let std_sock: std::net::UdpSocket = raw.into();
            Ok(tokio::net::UdpSocket::from_std(std_sock)?)
        }
    }
}

/// Run the Naive H3 server backed by tokio-quiche.
///
/// Mirrors [`crate::server_runner::run_h3_server`] but routes through the new
/// transport (`quiche_runner` + `transport/quiche_stream`).
pub async fn run_h3_server_quiche(
    server: Arc<Server>,
    config: &config::ServerConfig,
) -> Result<()> {
    use tokio::sync::Semaphore;

    let cert = config
        .cert
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("cert required for H3 backend"))?;
    let key = config
        .key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("key required for H3 backend"))?;
    let tls = QuicheTlsPaths::new(cert, key)?;
    let settings = make_quiche_settings(&config.congestion_control);

    let socket = bind_dual_stack_udp(config.port)?;
    let local_addr = socket.local_addr()?;
    let mut listener = bind_h3_listener(socket, settings, &tls)?;

    let conn_limiter = if server.conn_config.max_connections > 0 {
        Some(Arc::new(Semaphore::new(server.conn_config.max_connections)))
    } else {
        None
    };

    log::info!(
        address = %local_addr,
        tls = true,
        transport = "h3",
        backend = "quiche",
        max_connections = server.conn_config.max_connections,
        "Naive H3 server started (tokio-quiche)"
    );

    while let Some(conn_res) = listener.next().await {
        let initial = match conn_res {
            Ok(c) => c,
            Err(e) => {
                log::error!(error = %e, "QUIC accept error");
                continue;
            }
        };

        // Acquire connection permit (backpressure at limit).
        let permit = if let Some(ref limiter) = conn_limiter {
            match limiter.clone().acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => break, // semaphore closed → shutting down
            }
        } else {
            None
        };

        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let _permit = permit;

            let (driver, mut controller) = tokio_quiche::ServerH3Driver::new(make_h3_settings());
            let quic_conn = initial.start(driver);
            let peer_addr = quic_conn.peer_addr();

            log::connection(peer_addr, "new (quic-quiche)");
            log::debug!(peer = %peer_addr, "H3-quiche connection established");

            while let Some(event) = controller.event_receiver_mut().recv().await {
                match event {
                    ServerH3Event::Headers {
                        incoming_headers, ..
                    } => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            if let Err(e) =
                                process_h3_request_quiche(&server, incoming_headers, peer_addr)
                                    .await
                            {
                                log::debug!(peer = %peer_addr, error = %e, "H3-quiche request error");
                            }
                        });
                    }
                    ServerH3Event::Core(core_event) => {
                        // Connection-level signals: errors / shutdown break us out.
                        use tokio_quiche::http3::driver::H3Event;
                        match core_event {
                            H3Event::ConnectionError(err) => {
                                log::debug!(peer = %peer_addr, error = ?err, "H3-quiche conn error");
                                break;
                            }
                            H3Event::ConnectionShutdown(err) => {
                                log::debug!(peer = %peer_addr, error = ?err, "H3-quiche conn shutdown");
                                break;
                            }
                            _ => {} // SETTINGS / BodyBytesReceived / StreamClosed / ResetStream — ignore
                        }
                    }
                }
            }

            log::debug!(peer = %peer_addr, "H3-quiche connection closed");
            // Hold the quic_conn until the event loop ends to keep the driver alive.
            drop(quic_conn);
        });
    }

    Ok(())
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

        // ── A6: server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL=1 ──────
        //
        // We point a hyperium/h3 client at the quiche server and read the
        // SETTINGS frame the driver emits.  The driver is created with our
        // `make_h3_settings()`; the assertion catches the case where the
        // function forgets to flip `enable_extended_connect` on.

        async fn drive_h3_client(
            driver: &mut h3::client::Connection<h3_quinn::Connection, bytes::Bytes>,
            budget: Duration,
        ) {
            tokio::select! {
                _ = tokio::time::sleep(budget) => {}
                _ = std::future::poll_fn(|cx| driver.poll_close(cx)) => {}
            }
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn quiche_advertises_extended_connect_setting() {
            use h3::ConnectionState as _;

            install_crypto();
            let (cert_file, key_file, cert_der) = gen_cert_files();
            let tls = QuicheTlsPaths::new(cert_file.path(), key_file.path()).unwrap();
            let settings = make_quiche_settings(&CongestionControl::Cubic);

            let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
            let server_addr = server_socket.local_addr().unwrap();
            let mut listener =
                bind_h3_listener(server_socket, settings, &tls).expect("listener bind");

            // Server task: accept one connection, start the H3 driver with
            // the production `make_h3_settings()`.  We don't process any
            // events for A6 — receiving SETTINGS on the client side is what
            // the test asserts.
            let accept_task = tokio::spawn(async move {
                let initial = tokio::time::timeout(Duration::from_secs(10), listener.next())
                    .await
                    .ok()
                    .flatten()
                    .and_then(|res| res.ok());
                if let Some(conn) = initial {
                    let (driver, mut controller) =
                        tokio_quiche::ServerH3Driver::new(make_h3_settings());
                    conn.start(driver);
                    let _ = tokio::time::timeout(
                        Duration::from_secs(10),
                        controller.event_receiver_mut().recv(),
                    )
                    .await;
                }
            });

            let quic_conn = tokio::time::timeout(
                Duration::from_secs(10),
                quinn_connect(cert_der, server_addr),
            )
            .await
            .expect("client connect should not time out")
            .expect("client connect should succeed");

            let h3_conn = h3_quinn::Connection::new(quic_conn);
            let (mut h3_driver, send_req) = h3::client::new(h3_conn).await.unwrap();

            // Drive briefly so the client processes the server's SETTINGS frame.
            drive_h3_client(&mut h3_driver, Duration::from_millis(500)).await;

            assert!(
                send_req.settings().enable_extended_connect(),
                "quiche server MUST advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1"
            );

            accept_task.abort();
        }

        // ── A7: server responds 200 to a CONNECT request ────────────────────
        //
        // Pumps the H3 controller event stream: when we receive the first
        // `ServerH3Event::Headers`, hand the IncomingH3Headers to
        // `respond_200_to_connect` which sends `:status 200`.  The h3 client
        // verifies it receives a 200.

        #[tokio::test(flavor = "multi_thread")]
        async fn quiche_connect_responds_200() {
            use tokio_quiche::http3::driver::ServerH3Event;

            install_crypto();
            let (cert_file, key_file, cert_der) = gen_cert_files();
            let tls = QuicheTlsPaths::new(cert_file.path(), key_file.path()).unwrap();
            let settings = make_quiche_settings(&CongestionControl::Cubic);

            let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
            let server_addr = server_socket.local_addr().unwrap();
            let mut listener =
                bind_h3_listener(server_socket, settings, &tls).expect("listener bind");

            let accept_task = tokio::spawn(async move {
                let initial = tokio::time::timeout(Duration::from_secs(10), listener.next())
                    .await
                    .ok()
                    .flatten()
                    .and_then(|res| res.ok());
                let Some(conn) = initial else { return };
                let (driver, mut controller) =
                    tokio_quiche::ServerH3Driver::new(make_h3_settings());
                conn.start(driver);

                // Pump events until we see Headers, then respond.
                while let Some(event) = controller.event_receiver_mut().recv().await {
                    if let ServerH3Event::Headers {
                        incoming_headers, ..
                    } = event
                    {
                        respond_200_to_connect(incoming_headers).await;
                        break;
                    }
                }
            });

            let quic_conn = tokio::time::timeout(
                Duration::from_secs(10),
                quinn_connect(cert_der, server_addr),
            )
            .await
            .expect("client connect should not time out")
            .expect("client connect should succeed");

            let h3_conn = h3_quinn::Connection::new(quic_conn);
            let (mut h3_driver, mut send_req) = h3::client::new(h3_conn).await.unwrap();
            let driver_task =
                tokio::spawn(std::future::poll_fn(move |cx| h3_driver.poll_close(cx)));

            // Give the server time to flush SETTINGS so its CONNECT advertisement
            // is in effect before we open the stream.
            tokio::time::sleep(Duration::from_millis(100)).await;

            let req = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("example.com:80")
                .body(())
                .unwrap();
            let mut stream = send_req.send_request(req).await.unwrap();

            let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
                .await
                .expect("recv_response timed out")
                .expect("recv_response failed");

            assert_eq!(
                resp.status(),
                http::StatusCode::OK,
                "CONNECT must receive a 200 OK"
            );

            accept_task.abort();
            driver_task.abort();
        }

        // ── A10: full bidirectional echo through the new transport stack ───
        //
        // End-to-end assembly test:
        //   client CONNECT → 200 → upload UP_SIZE bytes + finish
        //                    → server reads via H3StreamReader
        //                    → server writes DOWN_SIZE bytes via H3StreamWriter
        //                    → server shuts down → client receives bytes + EOF
        //
        // This is the milestone the plan flags for the first cronet smoke
        // test.  No production-side stub: it exercises code that A6/A7/A8/A9
        // already turned green.

        #[tokio::test(flavor = "multi_thread")]
        async fn quiche_single_stream_bidirectional_echo() {
            use crate::transport::quiche_stream::{H3StreamReader, H3StreamWriter};
            use bytes::{Buf, Bytes};
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio_quiche::http3::driver::ServerH3Event;

            const UP_SIZE: usize = 32 * 1024;
            const DOWN_SIZE: usize = 48 * 1024;

            install_crypto();
            let (cert_file, key_file, cert_der) = gen_cert_files();
            let tls = QuicheTlsPaths::new(cert_file.path(), key_file.path()).unwrap();
            let settings = make_quiche_settings(&CongestionControl::Cubic);
            let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
            let server_addr = server_socket.local_addr().unwrap();
            let mut listener =
                bind_h3_listener(server_socket, settings, &tls).expect("listener bind");

            let download_payload: Vec<u8> = (0..DOWN_SIZE).map(|i| (i % 256) as u8).collect();
            let download_for_server = download_payload.clone();

            let accept_task = tokio::spawn(async move {
                let initial = tokio::time::timeout(Duration::from_secs(10), listener.next())
                    .await
                    .ok()
                    .flatten()
                    .and_then(|res| res.ok());
                let Some(conn) = initial else { return };
                let (driver, mut controller) =
                    tokio_quiche::ServerH3Driver::new(make_h3_settings());
                conn.start(driver);

                while let Some(event) = controller.event_receiver_mut().recv().await {
                    if let ServerH3Event::Headers {
                        incoming_headers, ..
                    } = event
                    {
                        let IncomingH3Headers {
                            send: mut frame_sender,
                            recv,
                            ..
                        } = incoming_headers;

                        // Send 200 directly on the frame sender, then hand it to
                        // the writer adapter for the body relay.
                        let response = vec![Header::new(b":status", b"200")];
                        frame_sender
                            .send(OutboundFrame::Headers(response, None))
                            .await
                            .unwrap();

                        let mut reader = H3StreamReader::new(recv);
                        let mut writer = H3StreamWriter::new(frame_sender);

                        let mut up_buf = vec![0u8; UP_SIZE];
                        reader.read_exact(&mut up_buf).await.unwrap();

                        writer.write_all(&download_for_server).await.unwrap();
                        writer.shutdown().await.unwrap();
                        break;
                    }
                }
            });

            let quic_conn = tokio::time::timeout(
                Duration::from_secs(10),
                quinn_connect(cert_der, server_addr),
            )
            .await
            .expect("client connect should not time out")
            .expect("client connect should succeed");
            let h3_conn = h3_quinn::Connection::new(quic_conn);
            let (mut h3_driver, mut send_req) = h3::client::new(h3_conn).await.unwrap();
            let driver_task =
                tokio::spawn(std::future::poll_fn(move |cx| h3_driver.poll_close(cx)));

            // Let SETTINGS flush so CONNECT is allowed before we send it.
            tokio::time::sleep(Duration::from_millis(100)).await;

            let upload_payload: Vec<u8> = (0..UP_SIZE).map(|i| ((i + 0x80) % 256) as u8).collect();

            let req = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("example.com:80")
                .body(())
                .unwrap();
            let mut stream = send_req.send_request(req).await.unwrap();

            let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
                .await
                .expect("recv_response timed out")
                .expect("recv_response failed");
            assert_eq!(
                resp.status(),
                http::StatusCode::OK,
                "CONNECT must be accepted"
            );

            stream
                .send_data(Bytes::from(upload_payload.clone()))
                .await
                .unwrap();
            stream.finish().await.unwrap();

            // Pull the download stream to completion.
            let mut down_buf = Vec::with_capacity(DOWN_SIZE);
            loop {
                let chunk = tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
                    .await
                    .expect("download stalled")
                    .unwrap();
                match chunk {
                    Some(mut data) => {
                        let len = data.remaining();
                        let mut tmp = vec![0u8; len];
                        data.copy_to_slice(&mut tmp);
                        down_buf.extend_from_slice(&tmp);
                    }
                    None => break,
                }
            }

            assert_eq!(
                down_buf.len(),
                DOWN_SIZE,
                "client must receive the full download payload"
            );
            assert_eq!(down_buf, download_payload, "download bytes must match");

            accept_task.abort();
            driver_task.abort();
        }

        // ── A11: client FIN propagates as Ok(0) on the server's reader ─────
        //
        // The peer sending end_of_stream=true on a body frame must surface as
        // a clean EOF (0 bytes) on H3StreamReader, so `process_tunnel`'s relay
        // can propagate the half-close downstream.  Mirrors
        // `transport::h3::tests::test_upload_eof_propagates` for the new path.

        #[tokio::test(flavor = "multi_thread")]
        async fn quiche_upload_eof_propagates() {
            use crate::transport::quiche_stream::{H3StreamReader, H3StreamWriter};
            use bytes::Bytes;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio_quiche::http3::driver::ServerH3Event;

            install_crypto();
            let (cert_file, key_file, cert_der) = gen_cert_files();
            let tls = QuicheTlsPaths::new(cert_file.path(), key_file.path()).unwrap();
            let settings = make_quiche_settings(&CongestionControl::Cubic);
            let server_socket = UdpSocket::bind("[::1]:0").await.unwrap();
            let server_addr = server_socket.local_addr().unwrap();
            let mut listener =
                bind_h3_listener(server_socket, settings, &tls).expect("listener bind");

            const PAYLOAD: &[u8] = b"eof-test-payload";
            let (totals_tx, totals_rx) = tokio::sync::oneshot::channel::<usize>();

            let accept_task = tokio::spawn(async move {
                let initial = tokio::time::timeout(Duration::from_secs(10), listener.next())
                    .await
                    .ok()
                    .flatten()
                    .and_then(|res| res.ok());
                let Some(conn) = initial else { return };
                let (driver, mut controller) =
                    tokio_quiche::ServerH3Driver::new(make_h3_settings());
                conn.start(driver);

                while let Some(event) = controller.event_receiver_mut().recv().await {
                    if let ServerH3Event::Headers {
                        incoming_headers, ..
                    } = event
                    {
                        let IncomingH3Headers {
                            send: mut frame_sender,
                            recv,
                            ..
                        } = incoming_headers;

                        let response = vec![Header::new(b":status", b"200")];
                        frame_sender
                            .send(OutboundFrame::Headers(response, None))
                            .await
                            .unwrap();

                        let mut reader = H3StreamReader::new(recv);
                        let mut writer = H3StreamWriter::new(frame_sender);

                        // Drain the upload until EOF.  The asserted property
                        // is that `read` returns Ok(0) after the client's
                        // finish() — without that the loop would hang.
                        let mut total = 0usize;
                        let mut buf = vec![0u8; 1024];
                        loop {
                            let n = reader.read(&mut buf).await.unwrap();
                            if n == 0 {
                                break; // EOF — the property under test
                            }
                            total += n;
                        }

                        // Close our side cleanly so the client's recv_data
                        // returns None and the test can complete.
                        writer.shutdown().await.unwrap();
                        let _ = totals_tx.send(total);
                        break;
                    }
                }
            });

            let quic_conn = tokio::time::timeout(
                Duration::from_secs(10),
                quinn_connect(cert_der, server_addr),
            )
            .await
            .expect("client connect should not time out")
            .expect("client connect should succeed");
            let h3_conn = h3_quinn::Connection::new(quic_conn);
            let (mut h3_driver, mut send_req) = h3::client::new(h3_conn).await.unwrap();
            let driver_task =
                tokio::spawn(std::future::poll_fn(move |cx| h3_driver.poll_close(cx)));

            tokio::time::sleep(Duration::from_millis(100)).await;

            let req = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("example.com:80")
                .body(())
                .unwrap();
            let mut stream = send_req.send_request(req).await.unwrap();

            let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
                .await
                .expect("recv_response timed out")
                .expect("recv_response failed");
            assert_eq!(resp.status(), http::StatusCode::OK);

            stream
                .send_data(Bytes::copy_from_slice(PAYLOAD))
                .await
                .unwrap();
            stream.finish().await.unwrap();

            let server_total = tokio::time::timeout(Duration::from_secs(10), totals_rx)
                .await
                .expect("server task did not finish (EOF likely not propagating)")
                .expect("server task closed without reporting");

            assert_eq!(
                server_total,
                PAYLOAD.len(),
                "server must receive exactly the bytes the client sent before finish()"
            );

            accept_task.abort();
            driver_task.abort();
        }
    }
}
