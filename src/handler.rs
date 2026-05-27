//! HTTP/2 and HTTP/3 CONNECT request handler for NaiveProxy protocol.
//!
//! Naive clients connect via:
//!   CONNECT target:port HTTP/2 (or HTTP/3)
//!   Proxy-Authorization: Basic base64(username:password)
//!   Padding: <random 30-61 char value>
//!
//! The password field of Basic Auth contains the user's UUID.
//! On successful auth the server responds 200 (with a Padding header) and
//! relays padded bytes for the first 8 frames then raw bytes thereafter.

use crate::acl;
use crate::core::{copy_bidirectional_with_stats, hooks, Address, Server, UserId};
use crate::logger::log;
use crate::transport::{generate_padding_header, H2Transport, H3Transport, NaivePaddedTransport};
use crate::uot;

use anyhow::{anyhow, Result};
use base64::Engine as _;
use bytes::Bytes;
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// TCP keepalive interval for outbound connections.
const TCP_KEEPALIVE_SECS: u64 = 15;

/// Shutdown timeout — prevents infinite hang when peer is unresponsive.
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

// ── H2 entry point ────────────────────────────────────────────────────────────

/// Process a single H2 CONNECT request.
pub async fn process_request(
    server: &Server,
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Validate method — only CONNECT is accepted.
    if req.method() != http::Method::CONNECT {
        let response = http::Response::builder()
            .status(http::StatusCode::METHOD_NOT_ALLOWED)
            .body(())?;
        let _ = respond.send_response(response, true);
        return Err(anyhow!("Expected CONNECT method, got {}", req.method()));
    }

    // Require the naive Padding header (present in all real naive clients).
    if req.headers().get("padding").is_none() {
        let response = http::Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .body(())?;
        let _ = respond.send_response(response, true);
        return Err(anyhow!("Missing naive Padding header from {}", peer_addr));
    }

    // Parse :authority header for the tunnel target.
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .ok_or_else(|| anyhow!("Missing :authority in CONNECT request"))?;
    let target = Address::from_authority(authority)
        .ok_or_else(|| anyhow!("Invalid target address: {}", authority))?;

    // Parse and authenticate.
    let credential = extract_credential(req.headers(), peer_addr)?;
    let user_id = authenticate(server, &credential, peer_addr, || {
        if let Ok(r) = http::Response::builder()
            .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .body(())
        {
            let _ = respond.send_response(r, true);
        }
    })?;

    // Route the connection.
    let outbound_type = server.router.route(&target).await;
    if matches!(outbound_type, hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "Connection rejected by router");
        let response = http::Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .body(())?;
        let _ = respond.send_response(response, true);
        return Ok(());
    }

    // Send 200 Connection Established with a naive Padding response header.
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("padding", generate_padding_header())
        .body(())?;
    let send_stream = respond
        .send_response(response, false)
        .map_err(|e| anyhow!("Failed to send 200 response: {}", e))?;
    let recv_stream = req.into_body();
    let padded = NaivePaddedTransport::new(H2Transport::new(recv_stream, send_stream));

    process_tunnel(server, padded, target, peer_addr, user_id, outbound_type).await
}

// ── H3 entry point ────────────────────────────────────────────────────────────

/// Process a single H3 CONNECT request.
pub async fn process_h3_request<C>(
    server: &Server,
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<C, Bytes>,
    peer_addr: SocketAddr,
) -> Result<()>
where
    C: h3::quic::BidiStream<Bytes> + Send + 'static,
    C::RecvStream: Send + 'static,
    C::SendStream: Send + 'static,
{
    // Validate method — only CONNECT is accepted.
    if req.method() != http::Method::CONNECT {
        let response = http::Response::builder()
            .status(http::StatusCode::METHOD_NOT_ALLOWED)
            .body(())?;
        let _ = stream.send_response(response).await;
        let _ = stream.finish().await;
        return Err(anyhow!("Expected CONNECT method, got {}", req.method()));
    }

    // Require the naive Padding header.
    if req.headers().get("padding").is_none() {
        let response = http::Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .body(())?;
        let _ = stream.send_response(response).await;
        let _ = stream.finish().await;
        return Err(anyhow!("Missing naive Padding header from {}", peer_addr));
    }

    // Parse :authority header for the tunnel target.
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .ok_or_else(|| anyhow!("Missing :authority in H3 CONNECT request"))?;
    let target = Address::from_authority(authority)
        .ok_or_else(|| anyhow!("Invalid target address: {}", authority))?;

    // Parse and authenticate.
    let credential = match extract_credential(req.headers(), peer_addr) {
        Ok(c) => c,
        Err(e) => {
            let response = http::Response::builder()
                .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .body(())?;
            let _ = stream.send_response(response).await;
            let _ = stream.finish().await;
            return Err(e);
        }
    };

    let user_id = match server.authenticator.authenticate(&credential) {
        Some(id) => id,
        None => {
            log::authentication(peer_addr, false);
            let response = http::Response::builder()
                .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .body(())?;
            let _ = stream.send_response(response).await;
            let _ = stream.finish().await;
            return Err(anyhow!("Authentication failed for peer {}", peer_addr));
        }
    };
    log::authentication(peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, target = %target, "H3 CONNECT authenticated");

    // Route the connection.
    let outbound_type = server.router.route(&target).await;
    if matches!(outbound_type, hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "H3 connection rejected by router");
        let response = http::Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .body(())?;
        let _ = stream.send_response(response).await;
        let _ = stream.finish().await;
        return Ok(());
    }

    // Send 200 Connection Established with a naive Padding response header.
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("padding", generate_padding_header())
        .body(())?;
    stream
        .send_response(response)
        .await
        .map_err(|e| anyhow!("Failed to send H3 200 response: {}", e))?;

    // Wrap the H3 stream as AsyncRead + AsyncWrite and apply padding protocol.
    let transport = H3Transport::new(stream, server.conn_config.buffer_size);
    let padded = NaivePaddedTransport::new(transport);

    process_tunnel(server, padded, target, peer_addr, user_id, outbound_type).await
}

// ── Shared tunnel logic ───────────────────────────────────────────────────────

/// Common post-auth tunnel processing (works for both H2 and H3).
async fn process_tunnel<T>(
    server: &Server,
    mut padded: NaivePaddedTransport<T>,
    target: Address,
    peer_addr: SocketAddr,
    user_id: UserId,
    outbound_type: hooks::OutboundType,
) -> Result<()>
where
    T: tokio::io::AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Register connection for tracking and kick capability.
    let (conn_id, cancel_token) = server.conn_manager.register(user_id, peer_addr);
    let _guard = scopeguard::guard((), |_| {
        server.conn_manager.unregister(conn_id);
        log::debug!(conn_id = conn_id, "Connection unregistered");
    });

    // Record request stat.
    server.stats.record_request(user_id);

    // Detect UDP-over-TCP magic address and route to UoT handler.
    let target_host = target.host();
    if let Some(uot_version) = uot::detect_uot(&target_host) {
        log::debug!(
            peer = %peer_addr,
            user_id = user_id,
            version = ?uot_version,
            "UoT connection"
        );
        return uot::handle_uot_stream(
            padded,
            uot_version,
            server.dns_cache.clone(),
            Arc::clone(&server.stats),
            user_id,
            peer_addr,
            cancel_token,
        )
        .await;
    }

    // Handle regular TCP tunnel based on outbound type.
    match outbound_type {
        hooks::OutboundType::Direct { resolved, handler } => {
            handle_direct_connect(
                server,
                &mut padded,
                &target,
                resolved,
                handler,
                peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
        hooks::OutboundType::Proxy(handler) => {
            handle_proxy_connect(
                server,
                &mut padded,
                &target,
                handler,
                peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
        hooks::OutboundType::Reject => Ok(()), // handled above
    }
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

fn extract_credential(headers: &http::HeaderMap, peer_addr: SocketAddr) -> Result<String> {
    let auth_header = match headers.get("proxy-authorization") {
        Some(v) => v,
        None => {
            log::authentication(peer_addr, false);
            return Err(anyhow!("Missing Proxy-Authorization header"));
        }
    };

    let auth_str = auth_header
        .to_str()
        .map_err(|_| anyhow!("Invalid Proxy-Authorization encoding"))?;
    parse_basic_auth(auth_str)
}

fn authenticate(
    server: &Server,
    credential: &str,
    peer_addr: SocketAddr,
    on_fail: impl FnOnce(),
) -> Result<UserId> {
    match server.authenticator.authenticate(credential) {
        Some(id) => {
            log::authentication(peer_addr, true);
            Ok(id)
        }
        None => {
            log::authentication(peer_addr, false);
            on_fail();
            Err(anyhow!("Authentication failed for peer {}", peer_addr))
        }
    }
}

// ── Relay ─────────────────────────────────────────────────────────────────────

/// Relay data between a padded transport stream and a remote TCP stream.
async fn relay<T, S>(
    server: &Server,
    padded: &mut NaivePaddedTransport<T>,
    remote_stream: &mut S,
    target: &Address,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()>
where
    T: tokio::io::AsyncRead + AsyncWrite + Unpin,
    S: tokio::io::AsyncRead + AsyncWrite + Unpin + Send,
{
    let relay_start = std::time::Instant::now();
    let stats = Arc::clone(&server.stats);
    // suppress_a_to_b_shutdown = false: propagate client half-close as TCP FIN
    // to the origin server.  This is the correct behaviour for HTTP CONNECT
    // tunnelling: when the client (NaiveProxy/sing-box) closes its QUIC upload
    // stream after sending a proxied request, the relay forwards the half-close
    // to the origin so that HTTP servers can commit to sending the full response
    // and then close the connection cleanly.
    //
    // Note: an earlier version used suppress=true, based on a flawed `nc -q1`
    // test that appeared to show ooklaserver truncating responses when a FIN was
    // received.  Subsequent testing confirmed that ookla sends the full response
    // body regardless (nc was exiting before the full body arrived, not ookla
    // truncating).  sing-box naive H3 propagates FIN identically and works
    // correctly for both latency and download tests.
    let relay_fut = copy_bidirectional_with_stats(
        padded,
        remote_stream,
        server.conn_config.idle_timeout_secs(),
        server.conn_config.uplink_only_timeout_secs(),
        server.conn_config.downlink_only_timeout_secs(),
        server.conn_config.buffer_size,
        Some((user_id, stats)),
        false,
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
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, padded.shutdown()).await;
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, remote_stream.shutdown()).await;
    }

    Ok(())
}

// ── Outbound connect handlers ─────────────────────────────────────────────────

/// Handle direct connection to target.
#[allow(clippy::too_many_arguments)]
async fn handle_direct_connect<T>(
    server: &Server,
    padded: &mut NaivePaddedTransport<T>,
    target: &Address,
    resolved: Option<std::net::SocketAddr>,
    handler: Option<Arc<acl::OutboundHandler>>,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()>
where
    T: tokio::io::AsyncRead + AsyncWrite + Unpin,
{
    // When an ACL handler is present, delegate dialing to it.
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
        return relay(
            server,
            padded,
            &mut remote_stream,
            target,
            peer_addr,
            user_id,
            cancel_token,
        )
        .await;
    }

    // Fast path: plain TcpStream::connect with keepalive and nodelay.
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
    relay(
        server,
        padded,
        &mut remote_stream,
        target,
        peer_addr,
        user_id,
        cancel_token,
    )
    .await
}

/// Handle connection via ACL proxy outbound.
async fn handle_proxy_connect<T>(
    server: &Server,
    padded: &mut NaivePaddedTransport<T>,
    target: &Address,
    handler: Arc<acl::OutboundHandler>,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()>
where
    T: tokio::io::AsyncRead + AsyncWrite + Unpin,
{
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
    relay(
        server,
        padded,
        &mut remote_stream,
        target,
        peer_addr,
        user_id,
        cancel_token,
    )
    .await
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
