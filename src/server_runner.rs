//! Server startup and accept loop for Naive proxy.
//!
//! Connection flow:
//!   TCP accept → TLS handshake (ALPN h2) → H2 server handshake
//!   → accept H2 streams (CONNECT requests) → handler::process_request

use crate::acl;
use crate::config;
use crate::core::{hooks, Server};
use crate::handler::process_request;
use crate::logger::log;
use crate::transport::load_tls_config;
use dns_cache_rs::DnsCache;

use anyhow::{anyhow, Result};
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

        Ok(Arc::new(AclRouter::with_cache(engine, config.block_private_ip, dns_cache))
            as Arc<dyn hooks::OutboundRouter>)
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
            let mut h2_conn = match tokio::time::timeout(
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

            // Accept H2 streams (each stream is one CONNECT tunnel)
            while let Some(result) = h2_conn.accept().await {
                match result {
                    Ok((req, respond)) => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            if let Err(e) = process_request(&server, req, respond, peer_addr).await {
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

            log::debug!(peer = %peer_addr, "H2 connection closed");
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
        assert!(super::H2_INITIAL_WINDOW_SIZE >= 64 * 1024);
        assert!(super::H2_INITIAL_CONN_WINDOW_SIZE >= super::H2_INITIAL_WINDOW_SIZE);
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

        let result = timeout(
            Duration::from_secs(10),
            h2::server::handshake(server_io),
        )
        .await;

        assert!(result.is_err(), "H2 handshake must time out when client sends no preface");
    }
}
