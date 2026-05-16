//! HTTP/2 CONNECT request handler for NaiveProxy protocol.
//!
//! Naive clients connect via:
//!   CONNECT target:port HTTP/2
//!   Proxy-Authorization: Basic base64(username:password)
//!
//! The password field of Basic Auth contains the user's UUID.
//! On successful auth the server responds 200 and relays raw bytes.

use crate::acl;
use crate::core::{copy_bidirectional_with_stats, hooks, Address, Server, UserId};
use crate::logger::log;
use crate::transport::H2Transport;

use anyhow::{anyhow, Result};
use base64::Engine as _;
use bytes::Bytes;
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// TCP keepalive interval for outbound connections
const TCP_KEEPALIVE_SECS: u64 = 15;

/// Shutdown timeout — prevents infinite hang when peer is unresponsive
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Parse HTTP Basic Auth header value and return the password portion.
///
/// Format: `Basic base64(username:password)` — the password after the colon
/// is the user's UUID credential.
pub fn parse_basic_auth(auth_header: &str) -> Result<String> {
    let encoded = auth_header
        .strip_prefix("Basic ")
        .ok_or_else(|| anyhow!("Expected 'Basic ' prefix in Proxy-Authorization header"))?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| anyhow!("Base64 decode failed: {}", e))?;

    let decoded_str =
        std::str::from_utf8(&decoded).map_err(|e| anyhow!("UTF-8 decode failed: {}", e))?;

    // Format is "username:password" — extract the password after the first colon.
    // If there is no colon, treat the whole string as the credential.
    Ok(match decoded_str.find(':') {
        Some(pos) => decoded_str[pos + 1..].to_string(),
        None => decoded_str.to_string(),
    })
}

/// Process a single H2 CONNECT request.
pub async fn process_request(
    server: &Server,
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Validate method — only CONNECT is accepted
    if req.method() != http::Method::CONNECT {
        let response = http::Response::builder()
            .status(http::StatusCode::METHOD_NOT_ALLOWED)
            .body(())?;
        let _ = respond.send_response(response, true);
        return Err(anyhow!("Expected CONNECT method, got {}", req.method()));
    }

    // Parse :authority header for the tunnel target
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .ok_or_else(|| anyhow!("Missing :authority in CONNECT request"))?;
    let target = Address::from_authority(authority)
        .ok_or_else(|| anyhow!("Invalid target address: {}", authority))?;

    // Parse Proxy-Authorization header
    let auth_header = match req.headers().get("proxy-authorization") {
        Some(v) => v,
        None => {
            log::authentication(peer_addr, false);
            let response = http::Response::builder()
                .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .body(())?;
            let _ = respond.send_response(response, true);
            return Err(anyhow!("Missing Proxy-Authorization header"));
        }
    };

    let auth_str = auth_header
        .to_str()
        .map_err(|_| anyhow!("Invalid Proxy-Authorization encoding"))?;
    let credential = parse_basic_auth(auth_str)?;

    // Authenticate user
    let user_id = match server.authenticator.authenticate(&credential) {
        Some(id) => id,
        None => {
            log::authentication(peer_addr, false);
            let response = http::Response::builder()
                .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .body(())?;
            let _ = respond.send_response(response, true);
            return Err(anyhow!("Authentication failed for peer {}", peer_addr));
        }
    };

    log::authentication(peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, target = %target, "CONNECT request authenticated");

    // Route the connection
    let outbound_type = server.router.route(&target).await;
    if matches!(outbound_type, hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "Connection rejected by router");
        let response = http::Response::builder().status(http::StatusCode::FORBIDDEN).body(())?;
        let _ = respond.send_response(response, true);
        return Ok(());
    }

    // Send 200 Connection Established — this opens the tunnel
    let response = http::Response::builder().status(http::StatusCode::OK).body(())?;
    let send_stream = respond
        .send_response(response, false)
        .map_err(|e| anyhow!("Failed to send 200 response: {}", e))?;
    let recv_stream = req.into_body();
    let mut h2_stream = H2Transport::new(recv_stream, send_stream);

    // Register connection for tracking and kick capability
    let (conn_id, cancel_token) = server.conn_manager.register(user_id, peer_addr);
    let _guard = scopeguard::guard((), |_| {
        server.conn_manager.unregister(conn_id);
        log::debug!(conn_id = conn_id, "Connection unregistered");
    });

    // Record request stat
    server.stats.record_request(user_id);

    // Handle the tunnel based on outbound type
    match outbound_type {
        hooks::OutboundType::Direct { resolved, handler } => {
            handle_direct_connect(server, &mut h2_stream, &target, resolved, handler, peer_addr, user_id, cancel_token).await
        }
        hooks::OutboundType::Proxy(handler) => {
            handle_proxy_connect(server, &mut h2_stream, &target, handler, peer_addr, user_id, cancel_token).await
        }
        hooks::OutboundType::Reject => Ok(()), // handled above
    }
}

/// Relay data between the H2 stream and a remote TCP stream.
async fn relay<S>(
    server: &Server,
    h2_stream: &mut H2Transport,
    remote_stream: &mut S,
    target: &Address,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let relay_start = std::time::Instant::now();
    let stats = Arc::clone(&server.stats);
    let relay_fut = copy_bidirectional_with_stats(
        h2_stream,
        remote_stream,
        server.conn_config.idle_timeout_secs(),
        server.conn_config.uplink_only_timeout_secs(),
        server.conn_config.downlink_only_timeout_secs(),
        server.conn_config.buffer_size,
        Some((user_id, stats)),
    );

    let cancelled = tokio::select! {
        result = relay_fut => {
            let duration = relay_start.elapsed().as_secs();
            match result {
                Ok(r) => {
                    log::debug!(
                        peer = %peer_addr,
                        target = %target,
                        up = r.a_to_b,
                        down = r.b_to_a,
                        duration_secs = duration,
                        termination = %r.termination,
                        "Relay done"
                    );
                }
                Err(e) => {
                    log::debug!(
                        peer = %peer_addr,
                        target = %target,
                        duration_secs = duration,
                        error = %e,
                        "Relay error"
                    );
                }
            }
            false
        }
        _ = cancel_token.cancelled() => {
            log::debug!(peer = %peer_addr, "Connection kicked");
            true
        }
    };

    if cancelled {
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, h2_stream.shutdown()).await;
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, remote_stream.shutdown()).await;
    }

    Ok(())
}

/// Handle direct connection to target
async fn handle_direct_connect(
    server: &Server,
    h2_stream: &mut H2Transport,
    target: &Address,
    resolved: Option<std::net::SocketAddr>,
    handler: Option<Arc<acl::OutboundHandler>>,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    // When an ACL handler is present, delegate dialing to it
    if let Some(handler) = handler {
        use acl::{Addr as AclAddr, AsyncOutbound};

        let mut acl_addr = if let Some(addr) = resolved {
            AclAddr::from_socket_addr(addr)
        } else {
            AclAddr::new(target.host().into_owned(), target.port())
        };

        let mut remote_stream = match tokio::time::timeout(
            server.conn_config.connect_timeout,
            handler.dial_tcp(&mut acl_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log::debug!(peer = %peer_addr, target = %target, error = %e, "Direct connect failed");
                return Err(anyhow!("Direct connect failed: {}", e));
            }
            Err(_) => {
                log::debug!(peer = %peer_addr, target = %target, "Direct connect timeout");
                return Err(anyhow!("Direct connect timeout"));
            }
        };

        log::debug!(peer = %peer_addr, target = %target, "Connected to remote (direct via handler)");
        return relay(server, h2_stream, &mut remote_stream, target, peer_addr, user_id, cancel_token).await;
    }

    // Fast path: plain TcpStream::connect with keepalive and nodelay
    let remote_addr = match resolved {
        Some(addr) => addr,
        None => crate::core::dns::resolve_socket_addr(&server.dns_cache, target).await?,
    };

    let mut remote_stream = match tokio::time::timeout(
        server.conn_config.connect_timeout,
        TcpStream::connect(remote_addr),
    )
    .await
    {
        Ok(Ok(s)) => {
            if server.conn_config.tcp_nodelay {
                let _ = s.set_nodelay(true);
            }
            let ka = TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS))
                .with_interval(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS));
            let _ = SockRef::from(&s).set_tcp_keepalive(&ka);
            s
        }
        Ok(Err(e)) => {
            log::debug!(peer = %peer_addr, target = %target, error = %e, "TCP connect failed");
            return Err(e.into());
        }
        Err(_) => {
            log::debug!(peer = %peer_addr, target = %target, "TCP connect timeout");
            return Err(anyhow!("TCP connect timeout"));
        }
    };

    log::debug!(peer = %peer_addr, remote = %remote_addr, "Connected to remote (direct)");
    relay(server, h2_stream, &mut remote_stream, target, peer_addr, user_id, cancel_token).await
}

/// Handle connection via ACL proxy outbound
async fn handle_proxy_connect(
    server: &Server,
    h2_stream: &mut H2Transport,
    target: &Address,
    handler: Arc<acl::OutboundHandler>,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    use acl::{Addr as AclAddr, AsyncOutbound};

    let mut acl_addr = AclAddr::new(target.host().into_owned(), target.port());
    let mut remote_stream = match tokio::time::timeout(
        server.conn_config.connect_timeout,
        handler.dial_tcp(&mut acl_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            log::debug!(peer = %peer_addr, target = %target, error = %e, "Proxy connect failed");
            return Err(anyhow!("Proxy connect failed: {}", e));
        }
        Err(_) => {
            log::debug!(peer = %peer_addr, target = %target, "Proxy connect timeout");
            return Err(anyhow!("Proxy connect timeout"));
        }
    };

    log::debug!(peer = %peer_addr, target = %target, handler = ?handler, "Connected via proxy");
    relay(server, h2_stream, &mut remote_stream, target, peer_addr, user_id, cancel_token).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_auth_with_username() {
        let header = "Basic dXNlcjpteS11dWlkLTEyMw=="; // user:my-uuid-123
        let cred = parse_basic_auth(header).unwrap();
        assert_eq!(cred, "my-uuid-123");
    }

    #[test]
    fn test_parse_basic_auth_colon_only() {
        // ":uuid" base64 encoded
        let encoded = base64::engine::general_purpose::STANDARD.encode(":my-uuid");
        let header = format!("Basic {}", encoded);
        let cred = parse_basic_auth(&header).unwrap();
        assert_eq!(cred, "my-uuid");
    }

    #[test]
    fn test_parse_basic_auth_no_colon() {
        // "uuid-only" base64 encoded (no colon)
        let encoded = base64::engine::general_purpose::STANDARD.encode("uuid-only");
        let header = format!("Basic {}", encoded);
        let cred = parse_basic_auth(&header).unwrap();
        assert_eq!(cred, "uuid-only");
    }

    #[test]
    fn test_parse_basic_auth_missing_prefix() {
        let header = "Bearer token";
        assert!(parse_basic_auth(header).is_err());
    }

    #[test]
    fn test_parse_basic_auth_invalid_base64() {
        let header = "Basic !!!not-base64!!!";
        assert!(parse_basic_auth(header).is_err());
    }

    #[test]
    fn test_parse_basic_auth_multiple_colons() {
        // "user:pass:word" — only split at first colon
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass:word");
        let header = format!("Basic {}", encoded);
        let cred = parse_basic_auth(&header).unwrap();
        assert_eq!(cred, "pass:word");
    }

    #[test]
    fn test_parse_basic_auth_empty_password() {
        // "user:" — empty password
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:");
        let header = format!("Basic {}", encoded);
        let cred = parse_basic_auth(&header).unwrap();
        assert_eq!(cred, "");
    }

    #[test]
    fn test_keepalive_and_shutdown_constants() {
        assert_eq!(TCP_KEEPALIVE_SECS, 15);
        assert_eq!(SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(5));
    }
}
