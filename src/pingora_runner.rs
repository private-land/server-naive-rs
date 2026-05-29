//! H2 accept loop built on pingora (`pingora_proxy::http_proxy_service`).
//!
//! Pingora's `Server::run_forever()` is sync and takes ownership of the
//! calling thread, so we wrap it in `tokio::task::spawn_blocking` to expose
//! a `serve()` future that fits the rest of our async lifecycle.  When the
//! pingora server receives SIGINT/SIGTERM it cleans up its listeners and
//! returns; the surrounding cleanup in `main.rs` then runs.
//!
//! Reference: `private-land/naive-rs` `src/h2/server.rs` for the pingora
//! integration pattern.

use crate::config;
use crate::core::Server;
use crate::handler::process_h2_request_pingora;
use crate::logger::log;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use pingora::apps::HttpServerOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::{TcpSocketOptions, ALPN};
use pingora::protocols::TcpKeepalive;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::server::configuration::ServerConf;
use pingora::server::{RunArgs, Server as PingoraServer, ShutdownSignal, ShutdownSignalWatch};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// TCP keepalive probing: detect dead peers in ~45s (3 probes × 15s) instead
/// of the OS default (~11 minutes on Linux).  Mirrors the legacy H2 path's
/// `TCP_KEEPALIVE_SECS = 15` setting.
const TCP_KEEPALIVE_IDLE_SECS: u64 = 15;
const TCP_KEEPALIVE_INTERVAL_SECS: u64 = 15;
const TCP_KEEPALIVE_COUNT: usize = 3;

/// Build the TCP socket options applied to accepted H2 connections.
///
/// Extracted as a free function so its keepalive intent is unit-testable —
/// the live behaviour cannot be observed from outside pingora's accepted
/// socket, but having an explicit `tcp_keepalive: Some(_)` is the contract
/// we want to lock in.
fn make_tcp_sock_opts() -> TcpSocketOptions {
    let mut opts = TcpSocketOptions::default();
    opts.tcp_keepalive = Some(TcpKeepalive {
        idle: Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS),
        interval: Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS),
        count: TCP_KEEPALIVE_COUNT,
        #[cfg(target_os = "linux")]
        user_timeout: Duration::from_secs(
            TCP_KEEPALIVE_IDLE_SECS + TCP_KEEPALIVE_INTERVAL_SECS * TCP_KEEPALIVE_COUNT as u64,
        ),
    });
    opts
}

/// How long pingora waits after starting graceful shutdown before forcibly
/// closing remaining connections.  The pingora default is 5 minutes, far
/// too long for our shutdown path which should be done in seconds.
const GRACE_PERIOD_SECONDS: u64 = 10;

/// Per-runtime drain budget after grace period ends.
const GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = 5;

/// Custom shutdown watcher that ties pingora's graceful-shutdown trigger to
/// the rest of the process's `CancellationToken`.  Without this, pingora
/// installs its own SIGINT/SIGTERM handler and then calls
/// `std::process::exit(0)`, which races our main.rs cleanup (panel
/// unregister, connection drain).
struct CancelTokenShutdown(CancellationToken);

#[async_trait]
impl ShutdownSignalWatch for CancelTokenShutdown {
    async fn recv(&self) -> ShutdownSignal {
        self.0.cancelled().await;
        // We always request a graceful shutdown — the legacy server_runner
        // also did "graceful drain" before unregistering from the panel.
        ShutdownSignal::GracefulTerminate
    }
}

/// pingora `ProxyHttp` impl that delegates every CONNECT to our handler.
pub struct NaiveProxy {
    server: Arc<Server>,
}

/// Per-request context.  Naive does not stash state across pingora's
/// filter callbacks for H2 — every CONNECT is self-contained.
pub struct NaiveCtx;

#[async_trait]
impl ProxyHttp for NaiveProxy {
    type CTX = NaiveCtx;

    fn new_ctx(&self) -> Self::CTX {
        NaiveCtx
    }

    /// Intercept every downstream request.  Any non-CONNECT or
    /// authentication failure is answered with the matching status code and
    /// the request is considered handled (`Ok(true)`).  Authenticated
    /// CONNECT runs the bidirectional tunnel inline before returning.
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let peer_addr = session
            .downstream_session
            .client_addr()
            .and_then(|a| a.as_inet().copied())
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));

        if let Err(e) =
            process_h2_request_pingora(Arc::clone(&self.server), session, peer_addr).await
        {
            log::debug!(peer = %peer_addr, error = %e, "H2-pingora request error");
        }
        Ok(true)
    }

    /// Required by `ProxyHttp` but unreachable: `request_filter` always
    /// returns `Ok(true)`, meaning the request is fully handled inside our
    /// CONNECT tunnel logic and pingora never needs an upstream peer.
    /// `unreachable!` would be the strongest signal but pingora may call
    /// this defensively on lifecycle hooks, so we return a precise error
    /// instead of crashing the worker.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<pingora::upstreams::peer::HttpPeer>> {
        Err(pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "naive proxy: upstream_peer called but request_filter handles every request",
        ))
    }
}

/// Run the Naive H2 server backed by pingora.
///
/// `cancel_token` ties pingora's shutdown trigger to the rest of the
/// process — when `cancel_token.cancel()` fires, pingora drains its
/// services and returns from `run()`, then this future resolves, then
/// `main.rs` proceeds to its own cleanup (panel unregister etc.).
///
/// We deliberately do NOT call `Server::run_forever()` even though pingora's
/// examples do: that method ends with `std::process::exit(0)`, which races
/// the cancellation cleanup in main.rs and would skip the panel unregister.
pub async fn run_h2_server_pingora(
    server: Arc<Server>,
    config: &config::ServerConfig,
    cancel_token: CancellationToken,
) -> Result<()> {
    let cert = config
        .cert
        .as_ref()
        .ok_or_else(|| anyhow!("cert required for H2 backend"))?;
    let key = config
        .key
        .as_ref()
        .ok_or_else(|| anyhow!("key required for H2 backend"))?;
    let cert_path = cert
        .to_str()
        .ok_or_else(|| anyhow!("cert path is not valid UTF-8: {}", cert.display()))?
        .to_owned();
    let key_path = key
        .to_str()
        .ok_or_else(|| anyhow!("key path is not valid UTF-8: {}", key.display()))?
        .to_owned();

    let port = config.port;
    let bind_addr = format!("[::]:{port}");

    // Override pingora's default 5-minute grace period — naive tunnels are
    // either short-lived (CONNECT) or already idle by the time we shut down,
    // and main.rs is waiting on us to finish so it can unregister from the
    // panel.  10s grace + 5s drain is the established naive-rs profile.
    let conf = ServerConf {
        grace_period_seconds: Some(GRACE_PERIOD_SECONDS),
        graceful_shutdown_timeout_seconds: Some(GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS),
        ..Default::default()
    };

    let mut pingora_server = PingoraServer::new_with_opt_and_conf(None, conf);
    pingora_server.bootstrap();

    let mut service = http_proxy_service(
        &pingora_server.configuration,
        NaiveProxy {
            server: Arc::clone(&server),
        },
    );

    // Enable CONNECT method on the embedded HTTP server.  Without this
    // pingora rejects CONNECT before our request_filter ever runs.
    if let Some(app) = service.app_logic_mut() {
        let mut opts = HttpServerOptions::default();
        opts.allow_connect_method_proxying = true;
        app.server_options = Some(opts);
    }

    let mut tls_settings =
        TlsSettings::intermediate(&cert_path, &key_path).map_err(|e| anyhow!("TLS error: {e}"))?;
    // Naive expects ALPN "h2"; H2H1 also accepts HTTP/1.1 negotiation.
    // We intentionally allow H1 so an H1 probe is answered with the same
    // 4xx error our H2 handler produces, instead of TLS-level rejection —
    // this preserves naive's "look like a normal HTTPS server" property.
    tls_settings.set_alpn(ALPN::H2H1);
    service.add_tls_with_settings(&bind_addr, Some(make_tcp_sock_opts()), tls_settings);

    pingora_server.add_service(service);

    log::info!(
        address = %bind_addr,
        tls = true,
        transport = "h2",
        backend = "pingora",
        max_connections = server.conn_config.max_connections,
        "Naive H2 server started (pingora)"
    );

    // Construct RunArgs INSIDE the closure: `Box<dyn ShutdownSignalWatch>`
    // is not `Send`, so it must not cross the spawn_blocking boundary.  The
    // CancellationToken on the other hand is Send + Sync, safe to capture.
    tokio::task::spawn_blocking(move || {
        let run_args = RunArgs {
            shutdown_signal: Box::new(CancelTokenShutdown(cancel_token)),
        };
        pingora_server.run(run_args)
    })
    .await
    .map_err(|e| anyhow!("pingora server thread panicked: {e}"))?;

    Ok(())
}

// ── Integration smoke ────────────────────────────────────────────────────────
//
// Pingora's `Server` owns its tokio runtime and exits the whole process on
// SIGTERM, which makes a true in-process integration test painful (the
// embedded runtime panics on drop if the test runtime is still active, and
// `run_forever` returns `!`).  We sidestep both by hosting pingora on a
// dedicated OS thread with its own `Runtime`, then talking to it from the
// test's tokio runtime via TLS + hyperium/h2.  The pingora thread is leaked
// at end-of-test — acceptable for a single short-lived integration run.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CongestionControl, ConnConfig, ServerConfig};
    use crate::core::hooks::{Authenticator, DirectRouter, StatsCollector};
    use crate::core::UserId;
    use rustls::pki_types::CertificateDer;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    struct AcceptAllAuth;
    impl Authenticator for AcceptAllAuth {
        fn authenticate(&self, _credential: &str) -> Option<UserId> {
            Some(1)
        }
    }

    struct NoopStats;
    impl StatsCollector for NoopStats {
        fn record_request(&self, _user_id: UserId) {}
        fn record_upload(&self, _user_id: UserId, _bytes: u64) {}
        fn record_download(&self, _user_id: UserId, _bytes: u64) {}
    }

    fn install_crypto() {
        static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

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

    fn pre_bind_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    fn test_conn_config() -> ConnConfig {
        ConnConfig {
            idle_timeout: Duration::from_secs(5),
            uplink_only_timeout: Duration::from_secs(2),
            downlink_only_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(5),
            tls_handshake_timeout: Duration::from_secs(10),
            buffer_size: 32 * 1024,
            tcp_backlog: 1024,
            tcp_nodelay: true,
            max_connections: 4096,
        }
    }

    fn make_test_server() -> Arc<Server> {
        let dns_cache = dns_cache_rs::DnsCache::new();
        Arc::new(
            Server::builder()
                .authenticator(Arc::new(AcceptAllAuth))
                .stats(Arc::new(NoopStats))
                // Explicit DirectRouter with block_private_ip=false so the
                // test's 127.0.0.1 target is allowed through.  The
                // Server::builder default is block_private_ip=true.
                .router(Arc::new(DirectRouter::with_cache(false, dns_cache.clone())))
                .conn_config(test_conn_config())
                .dns_cache(dns_cache)
                .build(),
        )
    }

    fn make_test_server_config(port: u16, cert: &Path, key: &Path) -> ServerConfig {
        ServerConfig {
            port,
            cert: Some(cert.to_path_buf()),
            key: Some(key.to_path_buf()),
            acl_conf_file: None,
            data_dir: PathBuf::from("/tmp"),
            block_private_ip: false, // allow 127.0.0.1 target for test
            congestion_control: CongestionControl::Cubic,
        }
    }

    fn spawn_pingora(
        server: Arc<Server>,
        cfg: ServerConfig,
        cancel_token: CancellationToken,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let _ = run_h2_server_pingora(server, &cfg, cancel_token).await;
            });
        })
    }

    async fn wait_for_port(port: u16, timeout: Duration) {
        let start = std::time::Instant::now();
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return;
            }
            if start.elapsed() > timeout {
                panic!("pingora port {port} did not start listening within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Integration smoke: TLS + H2 client opens a CONNECT stream against a
    /// real pingora server and asserts the 200 response + Padding header.
    /// Does NOT exercise the body-relay tunnel (upstream `127.0.0.1:1` is
    /// expected to fail connect; the handler logs and tears down).
    #[tokio::test(flavor = "multi_thread")]
    async fn pingora_h2_connect_returns_200_with_padding() {
        install_crypto();
        let (cert_file, key_file, cert_der) = gen_cert_files();
        let port = pre_bind_port();
        let server = make_test_server();
        let cfg = make_test_server_config(port, cert_file.path(), key_file.path());

        // Local cancel_token: leaked by the spawned pingora thread on
        // test exit; we don't fire it, so pingora keeps running until the
        // test process tears it down.
        let cancel = CancellationToken::new();
        let _pingora_thread = spawn_pingora(server, cfg, cancel);
        wait_for_port(port, Duration::from_secs(10)).await;

        // TLS client config trusting our self-signed cert, with ALPN h2.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = connector.connect(server_name, tcp).await.expect("tls");

        let (mut h2_client, conn) = h2::client::handshake(tls).await.expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("127.0.0.1:1") // refuses fast; we only assert the 200 here
            .header("padding", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // any non-empty value
            .header("proxy-authorization", "Basic dXNlcjp1dWlk") // user:uuid; AcceptAllAuth ok
            .body(())
            .unwrap();
        let (resp_fut, mut send_stream) = h2_client.send_request(req, false).expect("send_request");

        let resp = tokio::time::timeout(Duration::from_secs(5), resp_fut)
            .await
            .expect("recv_response timeout")
            .expect("recv_response error");

        assert_eq!(
            resp.status(),
            http::StatusCode::OK,
            "CONNECT must receive 200 OK"
        );
        assert!(
            resp.headers().contains_key("padding"),
            "200 response must carry naive Padding header"
        );

        // Cleanly close from client side so the bridge stops polling
        // read_body_or_idle and the handler can return promptly.
        let _ = send_stream.send_data(bytes::Bytes::new(), true);
        let _ = h2_client; // drop
                           // The pingora thread is intentionally leaked here — the cancel_token
                           // we passed in is never fired, so pingora keeps running.  Process
                           // teardown reaps the thread.
    }

    /// #3: TCP keepalive must be explicitly set so dead peers are detected
    /// in ~45s (3 × 15s) instead of the OS default (~11 minutes on Linux).
    #[test]
    fn tcp_sock_opts_set_keepalive() {
        let opts = make_tcp_sock_opts();
        let ka = opts.tcp_keepalive.expect("tcp_keepalive must be Some");
        assert_eq!(ka.idle, Duration::from_secs(15));
        assert_eq!(ka.interval, Duration::from_secs(15));
        assert_eq!(ka.count, 3);
    }

    /// Verifies the graceful shutdown wiring: firing the CancellationToken
    /// must make pingora `run()` return (instead of `process::exit(0)` from
    /// `run_forever()`), so main.rs can run its panel-unregister cleanup.
    #[tokio::test(flavor = "multi_thread")]
    async fn pingora_graceful_shutdown_via_cancel_token() {
        install_crypto();
        let (cert_file, key_file, _cert_der) = gen_cert_files();
        let port = pre_bind_port();
        let server = make_test_server();
        let cfg = make_test_server_config(port, cert_file.path(), key_file.path());

        let cancel = CancellationToken::new();
        let pingora_thread = spawn_pingora(server, cfg, cancel.clone());
        wait_for_port(port, Duration::from_secs(10)).await;

        // Trigger our graceful shutdown signal.
        cancel.cancel();

        // The pingora OS thread must exit within a reasonable window.
        // Use spawn_blocking to await the join handle without blocking the
        // tokio worker.
        let join_result = tokio::time::timeout(
            Duration::from_secs(20),
            tokio::task::spawn_blocking(move || pingora_thread.join()),
        )
        .await;

        match join_result {
            Ok(Ok(Ok(()))) => {
                // pingora thread exited cleanly — the CancelTokenShutdown
                // watcher delivered ShutdownSignal::GracefulTerminate and
                // run() returned (i.e., we are NOT in run_forever's
                // process::exit path).
            }
            Ok(Ok(Err(_panic))) => panic!("pingora thread panicked during shutdown"),
            Ok(Err(_join)) => panic!("spawn_blocking join failed"),
            Err(_elapsed) => panic!(
                "pingora did not shut down within 20s of cancel_token — \
                 run_forever's process::exit(0) is likely still being used \
                 or the custom ShutdownSignalWatch did not wire correctly"
            ),
        }
    }
}
