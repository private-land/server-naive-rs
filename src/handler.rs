//! HTTP/2 and HTTP/3 CONNECT request handler for NaiveProxy protocol.
//!
//! Naive clients connect via:
//!   CONNECT target:port HTTP/2 (over TLS via pingora) or HTTP/3 (over
//!     QUIC via tokio-quiche)
//!   Proxy-Authorization: Basic base64(username:password)
//!   Padding: <random 30-61 char value>
//!
//! The password field of Basic Auth contains the user's UUID.  On
//! successful auth the server responds 200 (with a Padding header) and
//! relays padded bytes for the first 8 frames then raw bytes thereafter.
//!
//! `process_h2_request_pingora` is the H2 entry; `process_h3_request_quiche`
//! is the H3 entry.  Both converge on the shared `process_tunnel<T:
//! AsyncRead + AsyncWrite + Send + 'static>`.

use crate::acl;
use crate::core::{copy_bidirectional_with_stats, hooks, Address, Server, UserId};
use crate::logger::log;
use crate::transport::pingora_session::{run_session_bridge, BRIDGE_BUF};
use crate::transport::quiche_stream::{H3StreamReader, H3StreamWriter};
use crate::transport::{generate_padding_header, NaivePaddedTransport};
use crate::uot;

use anyhow::{anyhow, Result};
use base64::Engine as _;
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

// ── H2 entry point (pingora backend) ──────────────────────────────────────────

/// Send a status-only error response and close the response side.
///
/// Errors are intentionally swallowed (best-effort): if pingora cannot
/// flush a 4xx back to the peer the connection is already broken, so
/// surfacing the error to the caller would only obscure the *original*
/// failure that prompted the error response.  We trace-log so the
/// silent-drop path is observable when needed.
async fn send_pingora_status(session: &mut pingora::proxy::Session, status: u16) {
    let resp = match pingora::http::ResponseHeader::build(status, None) {
        Ok(r) => r,
        Err(e) => {
            log::debug!(status = status, error = %e, "send_pingora_status: build failed");
            return;
        }
    };
    if let Err(e) = session.write_response_header(Box::new(resp), true).await {
        log::debug!(status = status, error = %e, "send_pingora_status: write failed");
    }
}

/// Process a CONNECT request that arrived on the pingora backend.
///
/// Mirrors the legacy hyperium/h2 entry but adapts to pingora's `Session`:
/// pseudo-headers and body framing live on `session.downstream_session`, and
/// the body has to be pumped through a duplex bridge so the shared
/// `process_tunnel` keeps its `T: AsyncRead + AsyncWrite + Unpin + Send +
/// 'static` bound.
pub async fn process_h2_request_pingora(
    server: Arc<Server>,
    session: &mut pingora::proxy::Session,
    peer_addr: SocketAddr,
) -> Result<()> {
    use pingora::http::ResponseHeader;

    // Validate method — only CONNECT is accepted.  Build the err message
    // BEFORE the &mut session call so we don't borrow-conflict (and don't
    // need to clone Method).
    if session.req_header().method != http::Method::CONNECT {
        let err = anyhow!(
            "Expected CONNECT method, got {}",
            session.req_header().method
        );
        send_pingora_status(session, 405).await;
        return Err(err);
    }

    // Require the naive Padding header.
    if session.req_header().headers.get("padding").is_none() {
        send_pingora_status(session, 400).await;
        return Err(anyhow!("Missing naive Padding header from {peer_addr}"));
    }

    // Parse target authority from the CONNECT URI.
    let authority = session
        .req_header()
        .uri
        .authority()
        .map(|a| a.to_string())
        .ok_or_else(|| anyhow!("Missing authority in CONNECT request from {peer_addr}"))?;
    let target = Address::from_authority(&authority)
        .ok_or_else(|| anyhow!("Invalid target address: {authority}"))?;

    // Parse and authenticate.
    let auth_header_str = match session
        .req_header()
        .headers
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(v) => v,
        None => {
            log::authentication(peer_addr, false);
            send_pingora_status(session, 407).await;
            return Err(anyhow!("Missing Proxy-Authorization header"));
        }
    };
    let credential = match parse_basic_auth(&auth_header_str) {
        Ok(c) => c,
        Err(e) => {
            send_pingora_status(session, 407).await;
            return Err(e);
        }
    };
    let user_id = match server.authenticator.authenticate(&credential) {
        Some(id) => id,
        None => {
            log::authentication(peer_addr, false);
            send_pingora_status(session, 407).await;
            return Err(anyhow!("Authentication failed for peer {peer_addr}"));
        }
    };
    log::authentication(peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, target = %target, "H2-pingora CONNECT authenticated");

    // Route the connection.
    let outbound_type = server.router.route(&target).await;
    if matches!(outbound_type, hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "H2-pingora rejected by router");
        send_pingora_status(session, 403).await;
        return Ok(());
    }

    // Send 200 with naive Padding response header.
    let mut resp =
        ResponseHeader::build(200, None).map_err(|e| anyhow!("build ResponseHeader: {e}"))?;
    resp.append_header("padding", generate_padding_header())
        .map_err(|e| anyhow!("append padding header: {e}"))?;
    session
        .write_response_header(Box::new(resp), false)
        .await
        .map_err(|e| anyhow!("write 200 response header: {e}"))?;

    // Duplex pair: relay sees `client_io` as a normal AsyncRead+AsyncWrite,
    // the body bridge shuttles bytes between the pingora `Session` and
    // `server_half`.
    //
    // Cancel-safety rationale: spawn the tunnel onto a separate task and
    // run the bridge inline.  When `process_tunnel` completes it drops
    // `padded` (and the duplex's client_io with it), so the bridge's
    // server-half `io_read` returns EOF on its next poll and the bridge
    // exits cleanly.  If the bridge ends first (e.g., peer closed the H2
    // session), dropping `server_half` causes `client_io` reads/writes to
    // surface broken-pipe to the relay, which then ends `process_tunnel`.
    // Either way both futures terminate on their own boundary instead of
    // being abruptly dropped mid-await, which would have left the pingora
    // Session in an undefined partial-write state.
    let buf = std::cmp::max(server.conn_config.buffer_size, BRIDGE_BUF);
    let (client_io, server_half) = tokio::io::duplex(buf);
    let padded = NaivePaddedTransport::new(client_io);

    let server_for_tunnel = Arc::clone(&server);
    let tunnel = tokio::spawn(async move {
        process_tunnel(
            &server_for_tunnel,
            padded,
            target,
            peer_addr,
            user_id,
            outbound_type,
        )
        .await
    });

    run_session_bridge(session, server_half).await;

    match tunnel.await {
        Ok(result) => result?,
        Err(join_err) => return Err(anyhow!("tunnel task join failed: {join_err}")),
    }

    Ok(())
}

// ── H3 entry point (tokio-quiche backend) ─────────────────────────────────────

/// Process a CONNECT request that arrived on the new tokio-quiche backend.
///
/// Mirrors [`process_h3_request`] but adapts to tokio-quiche's
/// `IncomingH3Headers`: pseudo-headers + raw headers come as `Vec<h3::Header>`
/// (not `http::HeaderMap`), and the body channels are mpsc-shaped instead of
/// the hyperium/h3 `RequestStream`.  Once the 200 response is emitted, the
/// stream is wrapped via [`H3StreamReader`] + [`H3StreamWriter`] +
/// [`tokio::io::join`] and handed to the shared [`process_tunnel`].
pub async fn process_h3_request_quiche(
    server: &crate::core::Server,
    headers: tokio_quiche::http3::driver::IncomingH3Headers,
    peer_addr: SocketAddr,
) -> Result<()> {
    use futures_util::SinkExt as _;
    use quiche::h3::{Header, NameValue as _};
    use tokio_quiche::http3::driver::OutboundFrame;

    let tokio_quiche::http3::driver::IncomingH3Headers {
        headers: header_list,
        send: mut frame_sender,
        recv,
        ..
    } = headers;

    // Helper: find a header by name (case-sensitive for pseudo-headers; the
    // h3 crate already lower-cases regular headers on the wire).
    let find = |name: &[u8]| -> Option<&[u8]> {
        header_list
            .iter()
            .find(|h| h.name() == name)
            .map(|h| h.value())
    };

    async fn send_status(
        frame_sender: &mut tokio_quiche::http3::driver::OutboundFrameSender,
        status_bytes: &'static [u8],
    ) {
        use tokio_quiche::buf_factory::BufFactory;
        use tokio_quiche::quiche::BufFactory as _;
        let resp = vec![Header::new(b":status", status_bytes)];
        let empty = BufFactory::buf_from_slice(&[]);
        let _ = frame_sender.send(OutboundFrame::Headers(resp, None)).await;
        let _ = frame_sender.send(OutboundFrame::Body(empty, true)).await;
    }

    // Validate method = CONNECT.
    let method = find(b":method").unwrap_or(b"");
    if method != b"CONNECT" {
        send_status(&mut frame_sender, b"405").await;
        return Err(anyhow!(
            "Expected CONNECT method, got {}",
            String::from_utf8_lossy(method)
        ));
    }

    // Naive marker — every real client sends a `padding` header on the request.
    if find(b"padding").is_none() {
        send_status(&mut frame_sender, b"400").await;
        return Err(anyhow!("Missing naive Padding header from {peer_addr}"));
    }

    // Parse :authority into a target address.
    let authority = find(b":authority")
        .and_then(|v| std::str::from_utf8(v).ok())
        .ok_or_else(|| anyhow!("Missing :authority in H3 CONNECT request"))?;
    let target = crate::core::Address::from_authority(authority)
        .ok_or_else(|| anyhow!("Invalid target address: {authority}"))?;

    // Proxy-Authorization is the only place credentials live.
    let auth_header = match find(b"proxy-authorization").and_then(|v| std::str::from_utf8(v).ok()) {
        Some(v) => v,
        None => {
            log::authentication(peer_addr, false);
            send_status(&mut frame_sender, b"407").await;
            return Err(anyhow!("Missing Proxy-Authorization header"));
        }
    };
    let credential = match parse_basic_auth(auth_header) {
        Ok(c) => c,
        Err(e) => {
            send_status(&mut frame_sender, b"407").await;
            return Err(e);
        }
    };

    let user_id = match server.authenticator.authenticate(&credential) {
        Some(id) => id,
        None => {
            log::authentication(peer_addr, false);
            send_status(&mut frame_sender, b"407").await;
            return Err(anyhow!("Authentication failed for peer {peer_addr}"));
        }
    };
    log::authentication(peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, target = %target, "H3-quiche CONNECT authenticated");

    let outbound_type = server.router.route(&target).await;
    if matches!(outbound_type, hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "H3-quiche connection rejected");
        send_status(&mut frame_sender, b"403").await;
        return Ok(());
    }

    // Send 200 with Padding response header.  Naive expects this exact set.
    let padding_value = generate_padding_header();
    let response = vec![
        Header::new(b":status", b"200"),
        Header::new(b"padding", padding_value.as_bytes()),
    ];
    if let Err(e) = frame_sender
        .send(OutboundFrame::Headers(response, None))
        .await
    {
        return Err(anyhow!("Failed to send H3-quiche 200 response: {e}"));
    }

    // Wrap reader + writer into a single AsyncRead+AsyncWrite duplex, then
    // layer the naive padding.  `process_tunnel` is generic over T and
    // handles the rest (UoT detection, direct/proxy routing, relay+stats).
    let reader = H3StreamReader::new(recv);
    let writer = H3StreamWriter::new(frame_sender);
    let combined = tokio::io::join(reader, writer);
    let padded = NaivePaddedTransport::new(combined);

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
    // suppress_a_to_b_shutdown = false: propagate the client's half-close to
    // the origin via TCP FIN.  This matches sing-box's NaiveProxy server design
    // (its `CopyConn` calls `N.CloseWrite` on the destination once the source
    // reaches EOF) and is necessary for HTTP/1.1 + ooklaserver speedtest:
    //
    //   • Latency / download / upload all use one CONNECT tunnel per logical
    //     HTTP request.  The client sends its request, signals END_STREAM, and
    //     waits for the response; HTTP/1.1 servers reply with the full body
    //     once they see FIN.
    //
    //   • The relay has NO application-level half-close timer.  After EOF on
    //     one direction we just CloseWrite the peer and wait for natural EOF
    //     on the other direction (sing-box behaviour).  The QUIC idle timeout
    //     and the relay's coarse `idle_timeout` are the only safety nets — no
    //     `half_close_timeout` cuts the response mid-transfer anymore.
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
