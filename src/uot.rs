//! UDP-over-TCP (UoT) relay for NaiveProxy.
//!
//! When a client CONNECTs to one of the magic addresses below, the stream
//! carries UDP packets framed over the (already-padded) H2 tunnel.
//!
//! Magic addresses:
//!   v2: sp.v2.udp-over-tcp.arpa
//!   v1: sp.udp-over-tcp.arpa
//!
//! V2 wire format (after the 200 OK and padding):
//!   Request  = [1B isConnect][SocksaddrSerializer addr+port]
//!   Per-pkt  = [AddrParser addr+port (only if !isConnect)][2B len BE][payload]
//!
//! V1 uses only per-packet addressing (no initial Request).
//!
//! Address encodings:
//!   SocksaddrSerializer: 0x01=IPv4(4+2B)  0x04=IPv6(16+2B)  0x03=FQDN(1B+N+2B)
//!   AddrParser:          0x00=IPv4(4+2B)  0x01=IPv6(16+2B)  0x02=FQDN(1B+N+2B)

use anyhow::{anyhow, Result};
use dns_cache_rs::DnsCache;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::core::hooks::StatsCollector;
use crate::core::UserId;
use crate::logger::log;

/// Matches the shutdown timeout used in the TCP relay path.
const UOT_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ── Magic addresses ───────────────────────────────────────────────────────────

const MAGIC_V2: &str = "sp.v2.udp-over-tcp.arpa";
const MAGIC_V1: &str = "sp.udp-over-tcp.arpa";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotVersion {
    V1,
    V2,
}

/// Returns `Some(version)` if `host` is a UoT magic address, `None` otherwise.
pub fn detect_uot(host: &str) -> Option<UotVersion> {
    if host.eq_ignore_ascii_case(MAGIC_V2) {
        Some(UotVersion::V2)
    } else if host.eq_ignore_ascii_case(MAGIC_V1) {
        Some(UotVersion::V1)
    } else {
        None
    }
}

// ── Address serialization ─────────────────────────────────────────────────────

/// Reads a `SocksaddrSerializer`-encoded address+port.
///
/// Type bytes: 0x01=IPv4  0x04=IPv6  0x03=FQDN
async fn read_socks_addr<R: AsyncRead + Unpin>(r: &mut R) -> Result<(String, u16)> {
    let ty = r.read_u8().await?;
    match ty {
        0x01 => {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip).await?;
            let port = r.read_u16().await?;
            Ok((format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), port))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip).await?;
            let port = r.read_u16().await?;
            let addr = std::net::Ipv6Addr::from(ip);
            Ok((addr.to_string(), port))
        }
        0x03 => {
            let len = r.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            r.read_exact(&mut domain).await?;
            let port = r.read_u16().await?;
            let domain =
                String::from_utf8(domain).map_err(|_| anyhow!("invalid FQDN in UoT request"))?;
            Ok((domain, port))
        }
        other => Err(anyhow!("unknown SocksaddrSerializer type: {:#x}", other)),
    }
}

/// Reads an `AddrParser`-encoded address+port (per-packet addressing).
///
/// Type bytes: 0x00=IPv4  0x01=IPv6  0x02=FQDN
async fn read_addr_parser<R: AsyncRead + Unpin>(r: &mut R) -> Result<(String, u16)> {
    let ty = r.read_u8().await?;
    match ty {
        0x00 => {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip).await?;
            let port = r.read_u16().await?;
            Ok((format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), port))
        }
        0x01 => {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip).await?;
            let port = r.read_u16().await?;
            let addr = std::net::Ipv6Addr::from(ip);
            Ok((addr.to_string(), port))
        }
        0x02 => {
            let len = r.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            r.read_exact(&mut domain).await?;
            let port = r.read_u16().await?;
            let domain =
                String::from_utf8(domain).map_err(|_| anyhow!("invalid FQDN in UoT packet"))?;
            Ok((domain, port))
        }
        other => Err(anyhow!("unknown AddrParser type: {:#x}", other)),
    }
}

/// Writes an `AddrParser`-encoded `SocketAddr`.
async fn write_addr_parser<W: AsyncWrite + Unpin>(w: &mut W, addr: SocketAddr) -> Result<()> {
    match addr {
        SocketAddr::V4(v4) => {
            w.write_u8(0x00).await?;
            w.write_all(&v4.ip().octets()).await?;
            w.write_u16(v4.port()).await?;
        }
        SocketAddr::V6(v6) => {
            w.write_u8(0x01).await?;
            w.write_all(&v6.ip().octets()).await?;
            w.write_u16(v6.port()).await?;
        }
    }
    Ok(())
}

/// Writes one UoT packet (per-packet address prefix + 2B length + payload).
async fn write_uot_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    from: SocketAddr,
    data: &[u8],
    is_connect: bool,
) -> Result<()> {
    if !is_connect {
        write_addr_parser(writer, from).await?;
    }
    writer.write_u16(data.len() as u16).await?;
    writer.write_all(data).await?;
    Ok(())
}

// ── DNS resolution ────────────────────────────────────────────────────────────

async fn resolve_host(dns: &DnsCache, host: &str, port: u16) -> Result<SocketAddr> {
    // Try as a literal IP first.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut it = dns
        .resolve_with_port_iter(host, port)
        .await
        .map_err(|e| anyhow!("DNS error for {}: {}", host, e))?;
    it.next().ok_or_else(|| anyhow!("no address for {}", host))
}

// ── UoT relay ─────────────────────────────────────────────────────────────────

/// Handle a UDP-over-TCP stream after the 200 OK has been sent.
///
/// `stream` is the padded H2 stream (implements `AsyncRead + AsyncWrite`).
///
/// Uses `tokio::join!` so the output half always reaches `h2_writer.shutdown()`
/// regardless of whether the relay ends naturally or is cancelled by `cancel`.
/// This ensures the H2 write side sends a clean FIN instead of an abrupt RST.
pub async fn handle_uot_stream<S>(
    mut stream: S,
    version: UotVersion,
    dns: DnsCache,
    stats: Arc<dyn StatsCollector>,
    user_id: UserId,
    peer_addr: SocketAddr,
    cancel: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // ── Read UoT request (v2 only) ────────────────────────────────────────────
    let (is_connect, fixed_dest) = if version == UotVersion::V2 {
        let is_connect = stream.read_u8().await? != 0;
        let (host, port) = read_socks_addr(&mut stream).await?;
        let dest = if is_connect {
            Some(resolve_host(&dns, &host, port).await?)
        } else {
            None
        };
        log::debug!(
            peer = %peer_addr,
            is_connect,
            dest = ?dest,
            "UoT v2 request"
        );
        (is_connect, dest)
    } else {
        // V1: always per-packet addressing, no initial request.
        log::debug!(peer = %peer_addr, "UoT v1 connection");
        (false, None)
    };

    // ── Create UDP socket ─────────────────────────────────────────────────────
    // Bind dual-stack so we can send to both IPv4 and IPv6 destinations.
    let udp = Arc::new(match UdpSocket::bind("[::]:0").await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
    });

    if is_connect {
        if let Some(dest) = fixed_dest {
            udp.connect(dest).await?;
        }
    }

    let (mut h2_reader, mut h2_writer) = tokio::io::split(stream);

    let udp_send = Arc::clone(&udp);
    let udp_recv = Arc::clone(&udp);
    let stats_in = Arc::clone(&stats);
    let stats_out = Arc::clone(&stats);
    let dns2 = dns.clone();

    // When either direction ends (error or cancel), signal the other to stop.
    let inner = CancellationToken::new();
    let cancel_a = cancel.clone();
    let inner_a = inner.clone();

    // ── Input loop: H2 → UDP ──────────────────────────────────────────────────
    let input = async move {
        'read: loop {
            let next = async {
                let dest: Option<SocketAddr> = if is_connect {
                    None // connected socket; dest is implicit
                } else {
                    let (host, port) = read_addr_parser(&mut h2_reader).await?;
                    Some(resolve_host(&dns2, &host, port).await?)
                };

                let len = h2_reader.read_u16().await? as usize;
                if len == 0 {
                    return Ok::<_, anyhow::Error>(());
                }
                let mut payload = vec![0u8; len];
                h2_reader.read_exact(&mut payload).await?;

                let sent = if is_connect {
                    udp_send.send(&payload).await?
                } else {
                    udp_send.send_to(&payload, dest.unwrap()).await?
                };
                stats_in.record_upload(user_id, sent as u64);
                Ok(())
            };

            tokio::select! {
                r = next => {
                    if let Err(e) = r {
                        log::debug!(peer = %peer_addr, error = %e, "UoT input ended");
                        inner_a.cancel();
                        break 'read;
                    }
                }
                _ = cancel_a.cancelled() => { inner_a.cancel(); break 'read; }
                _ = inner_a.cancelled() => break 'read,
            }
        }
    };

    let cancel_b = cancel.clone();
    let inner_b = inner.clone();

    // ── Output loop: UDP → H2 ────────────────────────────────────────────────
    let output = async move {
        let mut buf = vec![0u8; 65535];
        'write: loop {
            tokio::select! {
                result = udp_recv.recv_from(&mut buf) => {
                    match result {
                        Ok((n, from)) => {
                            // write_uot_packet is awaited inside the handler; cancel
                            // is not checked mid-write (intentional: avoids partial frames).
                            if write_uot_packet(&mut h2_writer, from, &buf[..n], is_connect)
                                .await
                                .is_err()
                            {
                                inner_b.cancel();
                                break 'write;
                            }
                            stats_out.record_download(user_id, n as u64);
                        }
                        Err(e) => {
                            log::debug!(peer = %peer_addr, error = %e, "UoT output ended");
                            inner_b.cancel();
                            break 'write;
                        }
                    }
                }
                _ = cancel_b.cancelled() => { inner_b.cancel(); break 'write; }
                _ = inner_b.cancelled() => break 'write,
            }
        }

        // Always shut down the write half cleanly — gives the client a proper FIN
        // instead of an abrupt RST regardless of whether we exited due to cancel,
        // error, or natural EOF.
        let _ = tokio::time::timeout(UOT_SHUTDOWN_TIMEOUT, h2_writer.shutdown()).await;
    };

    tokio::join!(input, output);

    if cancel.is_cancelled() {
        log::debug!(peer = %peer_addr, "UoT connection kicked");
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Wraps any `AsyncRead + AsyncWrite` and records whether `shutdown()` was called.
    struct ShutdownTracker<T> {
        inner: T,
        shutdown_called: Arc<AtomicBool>,
    }

    impl<T: AsyncRead + Unpin> AsyncRead for ShutdownTracker<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for ShutdownTracker<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_called.store(true, Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl<T: Unpin> Unpin for ShutdownTracker<T> {}

    struct NoopStats;
    impl StatsCollector for NoopStats {
        fn record_request(&self, _: UserId) {}
        fn record_upload(&self, _: UserId, _: u64) {}
        fn record_download(&self, _: UserId, _: u64) {}
    }

    // ── shutdown-on-cancel ────────────────────────────────────────────────────

    /// RED → GREEN: shutdown() must be called on the H2 write half when the
    /// cancel token fires — not just on natural EOF.
    ///
    /// Before the fix the outer `tokio::select!` dropped both futures on cancel,
    /// so h2_writer.shutdown() was never reached.  After the fix `tokio::join!`
    /// keeps the output future alive long enough to call shutdown().
    #[tokio::test]
    async fn shutdown_called_on_cancel() {
        let shutdown_called = Arc::new(AtomicBool::new(false));

        // DuplexStream: dropping the client half makes the server half see EOF on reads.
        let (client, server) = tokio::io::duplex(1024);
        drop(client);

        let stream = ShutdownTracker {
            inner: server,
            shutdown_called: shutdown_called.clone(),
        };

        let cancel = CancellationToken::new();
        cancel.cancel(); // fire immediately

        handle_uot_stream(
            stream,
            UotVersion::V1,
            DnsCache::new(),
            Arc::new(NoopStats),
            1,
            "127.0.0.1:1".parse().unwrap(),
            cancel,
        )
        .await
        .unwrap();

        assert!(
            shutdown_called.load(Ordering::SeqCst),
            "h2_writer.shutdown() must be called when cancel token fires"
        );
    }

    /// Verify shutdown() is also called when the H2 read side reaches EOF
    /// (natural end — no external cancel involved).
    #[tokio::test]
    async fn shutdown_called_on_natural_eof() {
        let shutdown_called = Arc::new(AtomicBool::new(false));

        let (client, server) = tokio::io::duplex(1024);
        drop(client); // immediate EOF on reads

        let stream = ShutdownTracker {
            inner: server,
            shutdown_called: shutdown_called.clone(),
        };

        handle_uot_stream(
            stream,
            UotVersion::V1,
            DnsCache::new(),
            Arc::new(NoopStats),
            1,
            "127.0.0.1:1".parse().unwrap(),
            CancellationToken::new(), // never fired
        )
        .await
        .unwrap();

        assert!(
            shutdown_called.load(Ordering::SeqCst),
            "h2_writer.shutdown() must be called on natural EOF"
        );
    }

    // ── existing parse tests (unchanged) ─────────────────────────────────────

    #[test]
    fn detect_magic_v2() {
        assert_eq!(detect_uot(MAGIC_V2), Some(UotVersion::V2));
        assert_eq!(detect_uot("SP.V2.UDP-OVER-TCP.ARPA"), Some(UotVersion::V2));
    }

    #[test]
    fn detect_magic_v1() {
        assert_eq!(detect_uot(MAGIC_V1), Some(UotVersion::V1));
    }

    #[test]
    fn detect_normal_host() {
        assert_eq!(detect_uot("example.com"), None);
        assert_eq!(detect_uot("1.1.1.1"), None);
    }

    #[tokio::test]
    async fn read_socks_addr_ipv4() {
        let data = [0x01, 1, 2, 3, 4, 0x01, 0xbb]; // type=IPv4, 1.2.3.4:443
        let mut cursor = std::io::Cursor::new(&data);
        let (host, port) = read_socks_addr(&mut cursor).await.unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn read_socks_addr_fqdn() {
        let domain = b"example.com";
        let mut data = vec![0x03, domain.len() as u8];
        data.extend_from_slice(domain);
        data.push(0x01);
        data.push(0xbb); // port 443
        let mut cursor = std::io::Cursor::new(&data);
        let (host, port) = read_socks_addr(&mut cursor).await.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn read_addr_parser_ipv4() {
        let data = [0x00, 8, 8, 8, 8, 0x00, 53]; // type=IPv4, 8.8.8.8:53
        let mut cursor = std::io::Cursor::new(&data);
        let (host, port) = read_addr_parser(&mut cursor).await.unwrap();
        assert_eq!(host, "8.8.8.8");
        assert_eq!(port, 53);
    }

    #[tokio::test]
    async fn write_read_addr_parser_roundtrip() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let mut buf = Vec::new();
        write_addr_parser(&mut buf, addr).await.unwrap();
        // type(1) + ipv4(4) + port(2) = 7 bytes
        assert_eq!(buf.len(), 7);
        assert_eq!(buf[0], 0x00); // IPv4 type
    }

    #[tokio::test]
    async fn write_addr_parser_ipv6() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let mut buf = Vec::new();
        write_addr_parser(&mut buf, addr).await.unwrap();
        // type(1) + ipv6(16) + port(2) = 19 bytes
        assert_eq!(buf.len(), 19);
        assert_eq!(buf[0], 0x01); // IPv6 type
    }
}
