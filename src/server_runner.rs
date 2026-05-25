//! Server startup and accept loops for Naive proxy.
//!
//! H2/TCP flow:
//!   TCP accept → TLS handshake (ALPN h2) → H2 server handshake
//!   → accept H2 streams (CONNECT requests) → handler::process_request
//!
//! H3/QUIC flow:
//!   QUIC accept → TLS 1.3 (ALPN h3) → H3 connection
//!   → accept H3 streams (CONNECT requests) → handler::process_h3_request

use crate::acl;
use crate::config;
use crate::core::{hooks, Server};
use crate::handler::{process_h3_request, process_request};
use crate::logger::log;
use crate::transport::{load_h3_tls_config, load_tls_config};
use dns_cache_rs::DnsCache;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use socket2::{SockRef, TcpKeepalive};
use std::sync::Arc;

/// Build outbound router from ACL configuration (or DirectRouter if no ACL file)
pub async fn build_router(
    config: &config::ServerConfig,
    refresh_geodata: bool,
    dns_cache: DnsCache,
) -> Result<Arc<dyn hooks::OutboundRouter>> {
    use crate::acl::AclRouter;

    if let Some(ref acl_path) = config.acl_conf_file {
        if !acl_path.exists() {
            return Err(anyhow!("ACL config file not found: {}", acl_path.display()));
        }
        let ext = acl_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
            return Err(anyhow!(
                "Invalid ACL config file format: expected .yaml or .yml"
            ));
        }

        let acl_config = acl::load_acl_config(acl_path).await?;
        let engine =
            acl::AclEngine::new(acl_config, Some(config.data_dir.as_path()), refresh_geodata)
                .await?;

        log::info!(
            acl_file = %acl_path.display(),
            rules = engine.rule_count(),
            block_private_ip = config.block_private_ip,
            "ACL router loaded"
        );

        Ok(Arc::new(AclRouter::with_cache(
            engine,
            config.block_private_ip,
            dns_cache,
        )) as Arc<dyn hooks::OutboundRouter>)
    } else {
        log::info!(
            block_private_ip = config.block_private_ip,
            "No ACL config, using direct connection for all traffic"
        );
        Ok(Arc::new(hooks::DirectRouter::with_cache(
            config.block_private_ip,
            dns_cache,
        )) as Arc<dyn hooks::OutboundRouter>)
    }
}

/// TCP keepalive interval — detects dead peers in ~45s (3 probes × 15s)
const TCP_KEEPALIVE_SECS: u64 = 15;

/// H2 initial flow-control window for each stream (1MB)
const H2_INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;

/// H2 initial connection-level flow-control window (2MB)
const H2_INITIAL_CONN_WINDOW_SIZE: u32 = 2 * 1024 * 1024;

/// Interval between H2 PING frames — keeps the connection alive through NAT/firewalls.
const H2_KEEPALIVE_INTERVAL_SECS: u64 = 20;

/// Time to wait for a PONG before treating the peer as dead and closing the connection.
const H2_KEEPALIVE_TIMEOUT_SECS: u64 = 15;

/// Interval between QUIC PING frames — prevents idle-timeout on the QUIC connection.
const QUIC_KEEPALIVE_INTERVAL_SECS: u64 = 20;

/// QUIC connection idle timeout: must be larger than keep-alive interval.
/// Capped conservatively at 2 minutes to match typical NAT/middlebox limits.
const QUIC_MAX_IDLE_TIMEOUT_SECS: u64 = 120;

/// Run the Naive server accept loop.
pub async fn run_server(server: Arc<Server>, config: &config::ServerConfig) -> Result<()> {
    use tokio::sync::Semaphore;

    // TLS is required for Naive (ALPN h2 is set in load_tls_config)
    let tls_config = load_tls_config(
        config.cert.as_ref().expect("cert required"),
        config.key.as_ref().expect("key required"),
    )?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    // Connection limiter for backpressure
    let conn_limiter = if server.conn_config.max_connections > 0 {
        Some(Arc::new(Semaphore::new(server.conn_config.max_connections)))
    } else {
        None
    };

    let listener = crate::net::bind_dual_stack(config.port, server.conn_config.tcp_backlog)?;
    let local_addr = listener.local_addr()?;

    log::info!(
        address = %local_addr,
        tls = true,
        transport = "h2",
        max_connections = server.conn_config.max_connections,
        "Naive server started"
    );

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                log::error!(error = %e, "Failed to accept TCP connection");
                if e.kind() == std::io::ErrorKind::Other {
                    break;
                }
                continue;
            }
        };

        log::connection(peer_addr, "new");

        // Acquire connection permit (backpressure at limit)
        let _permit = if let Some(ref limiter) = conn_limiter {
            match limiter.clone().acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => break, // semaphore closed → shutting down
            }
        } else {
            None
        };

        let server = Arc::clone(&server);
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let _permit = _permit;

            // TCP optimizations
            if server.conn_config.tcp_nodelay {
                let _ = tcp_stream.set_nodelay(true);
            }
            let ka = TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS))
                .with_interval(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS));
            let _ = SockRef::from(&tcp_stream).set_tcp_keepalive(&ka);

            // TLS handshake with timeout
            let tls_stream = match tokio::time::timeout(
                server.conn_config.tls_handshake_timeout,
                tls_acceptor.accept(tcp_stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    log::debug!(peer = %peer_addr, error = %e, stage = "tls", "Connection failed");
                    return;
                }
                Err(_) => {
                    log::debug!(peer = %peer_addr, stage = "tls_timeout", "Connection failed");
                    return;
                }
            };

            // HTTP/2 server handshake — timeout guards against clients that complete TLS
            // but never send the HTTP/2 preface, leaking a task per connection.
            let mut h2_conn: h2::server::Connection<_, bytes::Bytes> = match tokio::time::timeout(
                server.conn_config.request_timeout,
                h2::server::Builder::new()
                    .initial_window_size(H2_INITIAL_WINDOW_SIZE)
                    .initial_connection_window_size(H2_INITIAL_CONN_WINDOW_SIZE)
                    .handshake(tls_stream),
            )
            .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    log::debug!(peer = %peer_addr, error = %e, stage = "h2_handshake", "Connection failed");
                    return;
                }
                Err(_) => {
                    log::debug!(peer = %peer_addr, stage = "h2_handshake_timeout", "Connection timed out");
                    return;
                }
            };

            log::debug!(peer = %peer_addr, "H2 connection established");

            // PING-based keep-alive: prevents NAT/firewall from silently dropping idle
            // H2 connections.  PingPong shares internal state via Arc so it runs
            // concurrently with h2_conn.accept(); accept() processes the PONG frames
            // that wake the ping() future.
            let keepalive_handle = h2_conn.ping_pong().map(|mut pinger| {
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(
                            H2_KEEPALIVE_INTERVAL_SECS,
                        ))
                        .await;
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(H2_KEEPALIVE_TIMEOUT_SECS),
                            pinger.ping(h2::Ping::opaque()),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {} // PONG received — connection alive
                            _ => break,     // timeout or error — peer is gone
                        }
                    }
                })
            });

            // Accept H2 streams (each stream is one CONNECT tunnel)
            while let Some(result) = h2_conn.accept().await {
                match result {
                    Ok((req, respond)) => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            if let Err(e) = process_request(&server, req, respond, peer_addr).await
                            {
                                log::debug!(peer = %peer_addr, error = %e, "Request error");
                            }
                        });
                    }
                    Err(e) => {
                        // GOAWAY or connection-level error
                        if !e.is_go_away() {
                            log::debug!(peer = %peer_addr, error = %e, "H2 accept error");
                        }
                        break;
                    }
                }
            }

            if let Some(handle) = keepalive_handle {
                handle.abort();
            }

            log::debug!(peer = %peer_addr, "H2 connection closed");
        });
    }

    Ok(())
}

// ── H3/QUIC server ────────────────────────────────────────────────────────────

/// Run the Naive H3/QUIC server accept loop.
///
/// Connection flow:
///   UDP QUIC accept → TLS 1.3 handshake (ALPN h3) → H3 connection
///   → accept H3 CONNECT streams → handler::process_h3_request
pub async fn run_h3_server(server: Arc<Server>, config: &config::ServerConfig) -> Result<()> {
    use quinn::crypto::rustls::QuicServerConfig;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::sync::Semaphore;

    let cert = config.cert.as_ref().expect("cert required");
    let key = config.key.as_ref().expect("key required");

    let tls_config = load_h3_tls_config(cert, key)?;
    let quinn_crypto = QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow!("Failed to build Quinn TLS config: {}", e))?;

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(
        QUIC_KEEPALIVE_INTERVAL_SECS,
    )));
    transport_config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(QUIC_MAX_IDLE_TIMEOUT_SECS))
            .expect("QUIC idle timeout value is valid"),
    ));

    let mut quinn_server = quinn::ServerConfig::with_crypto(Arc::new(quinn_crypto));
    quinn_server.transport_config(Arc::new(transport_config));

    // Try IPv6 dual-stack first, fall back to IPv4-only.
    let addr_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), config.port);
    let endpoint = match quinn::Endpoint::server(quinn_server.clone(), addr_v6) {
        Ok(ep) => ep,
        Err(_) => {
            let addr_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.port);
            quinn::Endpoint::server(quinn_server, addr_v4)?
        }
    };

    let local_addr = endpoint.local_addr()?;

    // Connection limiter (per-stream semantics match the H2 approach).
    let conn_limiter = if server.conn_config.max_connections > 0 {
        Some(Arc::new(Semaphore::new(server.conn_config.max_connections)))
    } else {
        None
    };

    log::info!(
        address = %local_addr,
        tls = true,
        transport = "h3",
        max_connections = server.conn_config.max_connections,
        "Naive H3 server started"
    );

    while let Some(incoming) = endpoint.accept().await {
        let peer_addr = incoming.remote_address();
        log::connection(peer_addr, "new (quic)");

        let _permit = if let Some(ref limiter) = conn_limiter {
            match limiter.clone().acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => break, // semaphore closed → shutting down
            }
        } else {
            None
        };

        let server = Arc::clone(&server);

        tokio::spawn(async move {
            let _permit = _permit;

            // Complete QUIC handshake (TLS 1.3 + ALPN h3).
            let quic_conn = match tokio::time::timeout(
                server.conn_config.tls_handshake_timeout,
                incoming,
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    log::debug!(peer = %peer_addr, error = %e, stage = "quic_handshake", "Connection failed");
                    return;
                }
                Err(_) => {
                    log::debug!(peer = %peer_addr, stage = "quic_handshake_timeout", "Connection failed");
                    return;
                }
            };

            log::debug!(peer = %peer_addr, "QUIC connection established");

            // Upgrade to HTTP/3. enable_extended_connect advertises SETTINGS_ENABLE_CONNECT_PROTOCOL=1
            // (RFC 8441); without it, strict clients refuse to send CONNECT requests.
            let mut h3_conn = match tokio::time::timeout(
                server.conn_config.request_timeout,
                h3::server::builder()
                    .enable_extended_connect(true)
                    .build::<_, Bytes>(h3_quinn::Connection::new(quic_conn)),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    log::debug!(peer = %peer_addr, error = %e, stage = "h3_handshake", "Connection failed");
                    return;
                }
                Err(_) => {
                    log::debug!(peer = %peer_addr, stage = "h3_handshake_timeout", "Connection timed out");
                    return;
                }
            };

            log::debug!(peer = %peer_addr, "H3 connection established");

            // Accept H3 streams (each stream is one CONNECT tunnel).
            // h3 0.0.8: accept() returns a RequestResolver; resolve_request() gives (Request, Stream).
            loop {
                match h3_conn.accept().await {
                    Ok(Some(resolver)) => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            match resolver.resolve_request().await {
                                Ok((req, stream)) => {
                                    if let Err(e) =
                                        process_h3_request(&server, req, stream, peer_addr).await
                                    {
                                        log::debug!(peer = %peer_addr, error = %e, "H3 request error");
                                    }
                                }
                                Err(e) => {
                                    log::debug!(peer = %peer_addr, error = %e, "H3 resolve error");
                                }
                            }
                        });
                    }
                    Ok(None) => break, // connection closed cleanly
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "H3 accept error");
                        break;
                    }
                }
            }

            log::debug!(peer = %peer_addr, "H3 connection closed");
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn test_conn_limiter_backpressure() {
        let limiter = Arc::new(Semaphore::new(2));

        let p1 = limiter.clone().acquire_owned().await.unwrap();
        let p2 = limiter.clone().acquire_owned().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);
        assert!(limiter.try_acquire().is_err());

        drop(p1);
        assert_eq!(limiter.available_permits(), 1);

        drop(p2);
        assert_eq!(limiter.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_conn_limiter_unlimited_when_none() {
        let max_connections: usize = 0;
        let conn_limiter: Option<Arc<Semaphore>> = if max_connections > 0 {
            Some(Arc::new(Semaphore::new(max_connections)))
        } else {
            None
        };
        assert!(conn_limiter.is_none());
    }

    #[test]
    fn test_tcp_keepalive_interval() {
        // 3 probes × 15s = 45s detection window
        let detection = super::TCP_KEEPALIVE_SECS * 3;
        assert!(detection <= 60);
    }

    #[test]
    fn test_h2_window_sizes_are_reasonable() {
        const { assert!(super::H2_INITIAL_WINDOW_SIZE >= 64 * 1024) };
        const { assert!(super::H2_INITIAL_CONN_WINDOW_SIZE >= super::H2_INITIAL_WINDOW_SIZE) };
    }

    /// Verify that a silent client (no H2 preface) is rejected within the request_timeout.
    ///
    /// Without a timeout on the H2 handshake a client that completes TLS but never
    /// sends the HTTP/2 preface can hold a task open indefinitely, exhausting max_connections.
    #[tokio::test(start_paused = true)]
    async fn test_h2_handshake_times_out_on_silent_client() {
        use tokio::io::duplex;
        use tokio::time::{timeout, Duration};

        let (_client_io, server_io) = duplex(1024);
        // _client_io is kept alive but never writes, so the server's H2 handshake stalls.

        let result = timeout(Duration::from_secs(10), h2::server::handshake(server_io)).await;

        assert!(
            result.is_err(),
            "H2 handshake must time out when client sends no preface"
        );
    }

    // ── H3 SETTINGS_ENABLE_CONNECT_PROTOCOL tests ─────────────────────────────
    //
    // The naive proxy protocol requires HTTP CONNECT tunneling (RFC 8441 extended CONNECT).
    // RFC 8441 §3: a server MUST advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1 before clients
    // may use the CONNECT method.  Sing-box's naive outbound (quic:true) checks this setting
    // before opening each stream: the FIRST stream is opened before SETTINGS arrive (succeeds),
    // but streams 2..N — opened after the client has processed the server's SETTINGS — fail
    // when the flag is absent.  This is why single-thread worked but multi-thread did not.
    mod h3_extended_connect {
        use bytes::Bytes;
        use h3::ConnectionState as _;
        use h3_quinn::Connection as H3Conn;
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::net::{Ipv6Addr, ToSocketAddrs};
        use std::sync::Arc;
        use std::time::Duration;

        fn install_crypto() {
            static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            });
        }

        fn gen_certs() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            (
                cert.into(),
                PrivateKeyDer::Pkcs8(signing_key.serialize_der().into()),
            )
        }

        fn server_endpoint(
            cert: CertificateDer<'static>,
            key: PrivateKeyDer<'static>,
        ) -> (quinn::Endpoint, u16) {
            let mut tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap();
            tls.max_early_data_size = u32::MAX;
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(Duration::from_secs(5)).unwrap(),
            ));
            let mut sc = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(tls).unwrap(),
            ));
            sc.transport_config(Arc::new(transport));
            let ep = quinn::Endpoint::server(sc, "[::1]:0".parse().unwrap()).unwrap();
            let port = ep.local_addr().unwrap().port();
            (ep, port)
        }

        async fn client_conn(cert: CertificateDer<'static>, port: u16) -> H3Conn {
            let addr = (Ipv6Addr::LOCALHOST, port)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tls.enable_early_data = true;
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
            let mut ep = quinn::Endpoint::client("[::]:0".parse().unwrap()).unwrap();
            ep.set_default_client_config(cc);
            H3Conn::new(ep.connect(addr, "localhost").unwrap().await.unwrap())
        }

        /// Drive the h3 client connection for up to `budget` to let it process
        /// incoming SETTINGS and other control frames from the server.
        async fn drive(driver: &mut h3::client::Connection<H3Conn, Bytes>, budget: Duration) {
            tokio::select! {
                _ = tokio::time::sleep(budget) => {}
                _ = std::future::poll_fn(|cx| driver.poll_close(cx)) => {}
            }
        }

        /// RED — Documents the pre-fix behavior: `h3::server::Connection::new()` uses
        /// default settings where `enable_extended_connect = false`, so the server sends
        /// `SETTINGS_ENABLE_CONNECT_PROTOCOL = 0`.
        ///
        /// Consequence: a strict client (sing-box naive outbound) accepts the first CONNECT
        /// stream (opened before the SETTINGS frame arrives), but refuses all subsequent
        /// streams once it has processed the server's SETTINGS — breaking multi-thread tests.
        #[tokio::test]
        async fn red_connection_new_sends_zero_enable_connect_protocol() {
            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            let server = tokio::spawn(async move {
                let quic = ep.accept().await.unwrap().await.unwrap();
                // Pre-fix code path: Connection::new() with default (broken) settings.
                let _h3 = h3::server::Connection::<_, Bytes>::new(H3Conn::new(quic))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
            });

            let (mut driver, send_req) = h3::client::new(client_conn(cert, port).await)
                .await
                .unwrap();
            drive(&mut driver, Duration::from_millis(150)).await;

            // This asserts the bug: the flag is NOT set, so streams 2..N would be refused.
            assert!(
                !send_req.settings().enable_extended_connect(),
                "Connection::new() must NOT advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1 \
                 (this is the bug that broke multi-thread speed tests)"
            );
            server.abort();
        }

        /// GREEN — Validates the fix: `h3::server::builder().enable_extended_connect(true)`
        /// sends `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
        ///
        /// With this setting present, sing-box's naive outbound allows CONNECT on every stream
        /// it opens — fixing both single-thread and multi-thread speed tests.
        #[tokio::test]
        async fn green_builder_enable_extended_connect_sends_one() {
            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            let server = tokio::spawn(async move {
                let quic = ep.accept().await.unwrap().await.unwrap();
                // Post-fix code path: builder with enable_extended_connect(true).
                let _h3 = h3::server::builder()
                    .enable_extended_connect(true)
                    .build::<_, Bytes>(H3Conn::new(quic))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
            });

            let (mut driver, send_req) = h3::client::new(client_conn(cert, port).await)
                .await
                .unwrap();
            drive(&mut driver, Duration::from_millis(150)).await;

            assert!(
                send_req.settings().enable_extended_connect(),
                "builder with enable_extended_connect(true) MUST advertise \
                 SETTINGS_ENABLE_CONNECT_PROTOCOL=1"
            );
            server.abort();
        }
    }
}
