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
use pingora::listeners::ALPN;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::server::Server as PingoraServer;
use std::sync::Arc;

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

        if let Err(e) = process_h2_request_pingora(&self.server, session, peer_addr).await {
            log::debug!(peer = %peer_addr, error = %e, "H2-pingora request error");
        }
        Ok(true)
    }

    /// Required by `ProxyHttp`, but unreachable: `request_filter` always
    /// returns `Ok(true)`, so pingora never asks for an upstream peer.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<pingora::upstreams::peer::HttpPeer>> {
        Err(pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "upstream_peer should be unreachable for naive proxy",
        ))
    }
}

/// Run the Naive H2 server backed by pingora.
///
/// Pingora's `Server::run_forever()` is sync and blocks; we wrap it in
/// `tokio::task::spawn_blocking` so the returned future fits the rest of
/// our async lifecycle.
pub async fn run_h2_server_pingora(
    server: Arc<Server>,
    config: &config::ServerConfig,
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

    let mut pingora_server =
        PingoraServer::new(None).map_err(|e| anyhow!("failed to create pingora Server: {e}"))?;
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
    // Naive expects ALPN "h2"; H2H1 lets us answer the rare HTTP/1.1
    // request with a 405 too without crashing.
    tls_settings.set_alpn(ALPN::H2H1);
    service.add_tls_with_settings(&bind_addr, None, tls_settings);

    pingora_server.add_service(service);

    log::info!(
        address = %bind_addr,
        tls = true,
        transport = "h2",
        backend = "pingora",
        max_connections = server.conn_config.max_connections,
        "Naive H2 server started (pingora)"
    );

    tokio::task::spawn_blocking(move || pingora_server.run_forever())
        .await
        .map_err(|e| anyhow!("pingora server thread panicked: {e}"))?;

    Ok(())
}
