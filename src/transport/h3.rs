//! HTTP/3 transport layer for NaiveProxy CONNECT tunneling over QUIC.
//!
//! Wraps an `h3::server::RequestStream` as `AsyncRead + AsyncWrite` using a
//! `tokio::io::duplex` pair bridged by two independent tasks:
//!
//!   [upload task]   h3.recv_data() → io_write (DuplexStream) → relay reads
//!   [download task] io_read (DuplexStream) ← relay writes → h3.send_data()
//!
//! Natural backpressure in both directions:
//! - Upload: when relay reads slowly, DuplexStream fills, recv_data() pauses,
//!   QUIC receive window exhausts → client self-throttles.
//! - Download: when QUIC is congested, send_data() blocks, io_read pauses,
//!   DuplexStream fills → relay writes block → TCP upstream self-throttles.
//!
//! Previous bugs fixed:
//!
//! Bug 1 (v0.1.2): SETTINGS_ENABLE_CONNECT_PROTOCOL=0 caused streams 2..N to be
//!   refused by strict clients.  Fix: enable_extended_connect(true) on the builder
//!   (in server_runner.rs, not here).
//!
//! Bug 2 (v0.1.3): write_all() inside a select! arm blocked recv_data().
//!   Fix (this version): upload runs in its own task; recv_data() is never held
//!   behind write_all() from the download task's perspective.
//!
//! Bug 3 (v0.1.5): send_data() blocked recv_data() when QUIC send window filled.
//!   Fix (this version): h3.split() → send and recv in independent tasks.

use bytes::{Buf, Bytes};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

/// Duplex buffer size: at least 64 KiB to hold a full naive padded frame
/// (up to 32 KiB data + 3 B header + 255 B padding) without stalling.
const BRIDGE_BUF: usize = 64 * 1024;

/// H3Transport exposes an HTTP/3 CONNECT stream as `AsyncRead + AsyncWrite`.
///
/// Internally it spawns two tasks that bridge the h3 `RequestStream` and a
/// `tokio::io::duplex` channel.  The caller must have already sent the 200
/// response on `stream` before constructing this type.
pub struct H3Transport {
    inner: DuplexStream,
    // Stored only in test builds for wait_closed() ordering.
    #[cfg(test)]
    bridge: tokio::task::JoinHandle<()>,
}

impl H3Transport {
    pub fn new<C>(stream: h3::server::RequestStream<C, Bytes>, buffer_size: usize) -> Self
    where
        C: h3::quic::BidiStream<Bytes> + Send + 'static,
        C::RecvStream: Send + 'static,
        C::SendStream: Send + 'static,
    {
        let buf = buffer_size.max(BRIDGE_BUF);
        let (client, server_half) = tokio::io::duplex(buf);
        #[cfg(test)]
        let bridge = tokio::spawn(bridge(stream, server_half));
        #[cfg(not(test))]
        tokio::spawn(bridge(stream, server_half));
        Self {
            inner: client,
            #[cfg(test)]
            bridge,
        }
    }

    /// Wait for the bridge tasks to complete.
    ///
    /// Call after `shutdown()` and before dropping the `h3::server::Connection`
    /// to ensure in-flight `send_data` / `finish()` calls complete before
    /// `CONNECTION_CLOSE` is sent.
    #[cfg(test)]
    pub async fn wait_closed(self) {
        // Do NOT drop inner before bridge completes: the download task may still
        // be reading buffered data from the DuplexStream.  transport.shutdown()
        // already closed the write side, which signals EOF to io_read after the
        // buffer is drained.  inner drops naturally when self goes out of scope.
        self.bridge.await.ok();
    }
}

/// Bridge an h3 `RequestStream` to a `DuplexStream` using two independent tasks.
async fn bridge<C>(h3: h3::server::RequestStream<C, Bytes>, io: DuplexStream)
where
    C: h3::quic::BidiStream<Bytes> + Send + 'static,
    C::RecvStream: Send + 'static,
    C::SendStream: Send + 'static,
{
    let (mut h3_send, mut h3_recv) = h3.split();
    let (mut io_read, mut io_write) = tokio::io::split(io);

    // Upload: QUIC recv_data → DuplexStream write → relay reads upstream data.
    // Backpressure: if write_all blocks (relay slow), recv_data is not polled →
    // QUIC receive window exhausts → client self-throttles (correct behaviour).
    let upload = tokio::spawn(async move {
        while let Ok(Some(mut data)) = h3_recv.recv_data().await {
            let bytes = data.copy_to_bytes(data.remaining());
            if io_write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        // Release the H3 stream receive slot before the write shutdown so the
        // connection can accept new streams sooner.
        drop(h3_recv);
        let _ = io_write.shutdown().await;
    });

    // Download: DuplexStream read ← relay writes downstream → QUIC send_data.
    // Backpressure: if send_data blocks (QUIC congested), io_read is not polled →
    // DuplexStream fills → relay writes block → TCP upstream self-throttles.
    let download = tokio::spawn(async move {
        let mut buf = vec![0u8; BRIDGE_BUF];
        loop {
            match io_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if h3_send
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = h3_send.finish().await;
    });

    let _ = tokio::join!(upload, download);
}

// ── AsyncRead / AsyncWrite — delegate to the duplex inner stream ──────────────

impl AsyncRead for H3Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for H3Transport {
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
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // ── H3Transport end-to-end integration tests (real QUIC loopback) ─────────
    //
    // These tests verify the full H3Transport bridge with real QUIC streams.
    // The h3 client `Connection` (driver) runs as a background Tokio task so
    // stream operations can be awaited directly — no select!/timer juggling.
    mod bridge_integration {
        use super::super::H3Transport;
        use bytes::{Buf as _, Bytes};
        use h3_quinn::Connection as H3Conn;
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::net::{Ipv6Addr, ToSocketAddrs};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(Duration::from_secs(10)).unwrap(),
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
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let cc = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
            let mut ep = quinn::Endpoint::client("[::]:0".parse().unwrap()).unwrap();
            ep.set_default_client_config(cc);
            H3Conn::new(ep.connect(addr, "localhost").unwrap().await.unwrap())
        }

        /// Verifies the upload path through H3Transport with N=8 parallel streams.
        ///
        /// Upload data flow:
        ///   client send_data → h3.recv_data → upload task → DuplexStream → H3Transport.read
        ///
        /// All 8 streams completing proves the 2-task bridge handles concurrent
        /// uploads without head-of-line blocking.
        #[tokio::test(flavor = "multi_thread")]
        async fn green_multi_stream_upload_via_bridge() {
            const N: usize = 8;
            const CHUNK: usize = 64 * 1024;

            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            let totals = Arc::new(Mutex::new(vec![0usize; N]));
            let totals_srv = Arc::clone(&totals);

            let server = tokio::spawn(async move {
                let quic = ep.accept().await.unwrap().await.unwrap();
                let mut h3conn = h3::server::builder()
                    .enable_extended_connect(true)
                    .build::<_, Bytes>(H3Conn::new(quic))
                    .await
                    .unwrap();

                let (resolver_tx, mut resolver_rx) = tokio::sync::mpsc::channel(N + 2);

                let accept_task = tokio::spawn(async move {
                    while let Ok(Some(resolver)) = h3conn.accept().await {
                        if resolver_tx.send(resolver).await.is_err() {
                            break;
                        }
                    }
                });

                let mut handles = Vec::with_capacity(N);
                for i in 0..N {
                    let resolver = resolver_rx.recv().await.expect("accept_task closed early");
                    let totals = Arc::clone(&totals_srv);
                    handles.push(tokio::spawn(async move {
                        let (_req, mut stream) = resolver.resolve_request().await.unwrap();
                        stream
                            .send_response(http::Response::builder().status(200).body(()).unwrap())
                            .await
                            .unwrap();
                        let mut transport = H3Transport::new(stream, 32 * 1024);
                        let mut total = 0usize;
                        let mut buf = vec![0u8; 4096];
                        loop {
                            let n = transport.read(&mut buf).await.unwrap();
                            if n == 0 {
                                break;
                            }
                            total += n;
                        }
                        totals.lock().unwrap()[i] = total;
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
                accept_task.abort();
            });

            let (mut driver, mut send_req) = h3::client::new(client_conn(cert, port).await)
                .await
                .unwrap();
            let _driver = tokio::spawn(std::future::poll_fn(move |cx| driver.poll_close(cx)));

            tokio::time::sleep(Duration::from_millis(100)).await;

            let payload = Bytes::from(vec![b'U'; CHUNK]);
            let mut streams = Vec::with_capacity(N);
            for _ in 0..N {
                let req = http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("example.com:80")
                    .body(())
                    .unwrap();
                streams.push(send_req.send_request(req).await.unwrap());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            let client_handles: Vec<_> = streams
                .into_iter()
                .map(|mut stream| {
                    let payload = payload.clone();
                    tokio::spawn(async move {
                        let status =
                            tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
                                .await
                                .expect("timeout waiting for 200")
                                .unwrap()
                                .status();
                        assert_eq!(status, 200);
                        tokio::time::timeout(Duration::from_secs(5), stream.send_data(payload))
                            .await
                            .expect("timeout on send_data")
                            .unwrap();
                        tokio::time::timeout(Duration::from_secs(5), stream.finish())
                            .await
                            .expect("timeout on finish")
                            .unwrap();
                    })
                })
                .collect();
            for h in client_handles {
                h.await.unwrap();
            }

            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("server task timed out")
                .unwrap();

            let counts = totals.lock().unwrap();
            for (i, &n) in counts.iter().enumerate() {
                assert_eq!(
                    n, CHUNK,
                    "stream {i}: upload expected {CHUNK} bytes via bridge, got {n}"
                );
            }
        }

        /// Verifies the download path through H3Transport with N=8 parallel streams.
        ///
        /// Download data flow:
        ///   relay writes → H3Transport.write → DuplexStream → download task → h3.send_data
        ///
        /// All 8 streams completing proves the 2-task bridge handles concurrent
        /// downloads without head-of-line blocking.
        #[tokio::test(flavor = "multi_thread")]
        async fn green_multi_stream_download_via_bridge() {
            const N: usize = 8;
            const CHUNK: usize = 64 * 1024;

            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            let server = tokio::spawn(async move {
                let quic = ep.accept().await.unwrap().await.unwrap();
                let mut h3conn = h3::server::builder()
                    .enable_extended_connect(true)
                    .build::<_, Bytes>(H3Conn::new(quic))
                    .await
                    .unwrap();

                let mut handles = Vec::with_capacity(N);
                for _ in 0..N {
                    let resolver = h3conn.accept().await.unwrap().unwrap();
                    handles.push(tokio::spawn(async move {
                        let (_req, mut stream) = resolver.resolve_request().await.unwrap();
                        stream
                            .send_response(http::Response::builder().status(200).body(()).unwrap())
                            .await
                            .unwrap();
                        let mut transport = H3Transport::new(stream, 32 * 1024);
                        let payload = vec![b'D'; CHUNK];
                        transport.write_all(&payload).await.unwrap();
                        transport.shutdown().await.unwrap();
                        transport.wait_closed().await;
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
            });

            let (mut driver, mut send_req) = h3::client::new(client_conn(cert, port).await)
                .await
                .unwrap();
            let _driver = tokio::spawn(std::future::poll_fn(move |cx| driver.poll_close(cx)));

            tokio::time::sleep(Duration::from_millis(100)).await;

            let mut streams = Vec::with_capacity(N);
            for _ in 0..N {
                let req = http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("example.com:80")
                    .body(())
                    .unwrap();
                streams.push(send_req.send_request(req).await.unwrap());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            let client_handles: Vec<_> = streams
                .into_iter()
                .enumerate()
                .map(|(idx, mut stream)| {
                    tokio::spawn(async move {
                        let status =
                            tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
                                .await
                                .expect("timeout waiting for 200")
                                .unwrap()
                                .status();
                        assert_eq!(status, 200, "stream {idx}: expected 200");

                        let mut total = 0usize;
                        loop {
                            let chunk =
                                tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
                                    .await
                                    .unwrap_or_else(|_| {
                                        panic!(
                                            "stream {idx}: download stalled after {total} bytes \
                                         (expected {CHUNK})"
                                        )
                                    })
                                    .unwrap();
                            match chunk {
                                Some(mut data) => {
                                    total += data.remaining();
                                    data.advance(data.remaining());
                                }
                                None => break,
                            }
                        }
                        (idx, total)
                    })
                })
                .collect();

            let mut totals = [0usize; N];
            for h in client_handles {
                let (idx, n) = h.await.unwrap();
                totals[idx] = n;
            }

            tokio::time::timeout(Duration::from_secs(15), server)
                .await
                .expect("server task timed out")
                .unwrap();

            for (i, &n) in totals.iter().enumerate() {
                assert_eq!(
                    n, CHUNK,
                    "stream {i}: download expected {CHUNK} bytes via bridge, got {n}"
                );
            }
        }

        /// Single-stream bidirectional: upload and download on the same CONNECT stream.
        ///
        /// Client sends UPLOAD bytes, server reads them and then sends DOWNLOAD bytes,
        /// client reads them back.  Exercises both bridge tasks (upload + download)
        /// on one real QUIC stream.
        ///
        /// Flow:
        ///   client.send_data(UPLOAD) → server H3Transport.read_exact
        ///   server H3Transport.write_all(DOWNLOAD) → client.recv_data loop
        #[tokio::test(flavor = "multi_thread")]
        async fn test_bidirectional_single_stream() {
            const UP_SIZE: usize = 32 * 1024;
            const DOWN_SIZE: usize = 48 * 1024;

            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            let server = tokio::spawn(async move {
                let quic = ep.accept().await.unwrap().await.unwrap();
                let mut h3conn = h3::server::builder()
                    .enable_extended_connect(true)
                    .build::<_, Bytes>(H3Conn::new(quic))
                    .await
                    .unwrap();

                let resolver = h3conn.accept().await.unwrap().unwrap();
                // Spawn a detached driver that keeps h3conn polled so the QUIC
                // layer can flush outgoing send_data frames.  h3conn is moved here;
                // the task stays alive until the connection closes naturally, giving
                // the bridge's download task time to deliver all data before
                // CONNECTION_CLOSE is sent.
                tokio::spawn(async move {
                    while let Ok(Some(_)) = h3conn.accept().await {}
                });

                let (_req, mut stream) = resolver.resolve_request().await.unwrap();
                stream
                    .send_response(http::Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();

                let mut transport = H3Transport::new(stream, 32 * 1024);

                // Read all upload bytes.
                let mut up_buf = vec![0u8; UP_SIZE];
                transport.read_exact(&mut up_buf).await.unwrap();

                // Send download bytes.
                let down_payload = vec![0xCDu8; DOWN_SIZE];
                transport.write_all(&down_payload).await.unwrap();
                transport.shutdown().await.unwrap();
                // Wait for bridge tasks to flush send_data + finish().
                transport.wait_closed().await;

                // Return the first and last upload bytes for verification.
                (up_buf[0], up_buf[UP_SIZE - 1])
            });

            let (mut driver, mut send_req) = h3::client::new(client_conn(cert, port).await)
                .await
                .unwrap();
            let _driver = tokio::spawn(std::future::poll_fn(move |cx| driver.poll_close(cx)));

            tokio::time::sleep(Duration::from_millis(100)).await;

            let req = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("example.com:80")
                .body(())
                .unwrap();
            let mut stream = send_req.send_request(req).await.unwrap();

            // Receive 200 OK.
            let status = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
                .await
                .expect("timeout waiting for 200")
                .unwrap()
                .status();
            assert_eq!(status, 200);

            // Send upload data then signal end-of-send (half-close).
            let up_payload = Bytes::from(vec![0xABu8; UP_SIZE]);
            tokio::time::timeout(Duration::from_secs(5), stream.send_data(up_payload))
                .await
                .expect("timeout on send_data")
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), stream.finish())
                .await
                .expect("timeout on finish")
                .unwrap();

            // Receive download data.  After finish() the receive side remains open.
            let mut down_total = 0usize;
            loop {
                let chunk = tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
                    .await
                    .expect("download stalled")
                    .unwrap();
                match chunk {
                    Some(mut data) => {
                        down_total += data.remaining();
                        data.advance(data.remaining());
                    }
                    None => break,
                }
            }

            let (first_up, last_up) = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("server task timed out")
                .unwrap();

            assert_eq!(first_up, 0xAB, "first upload byte must match");
            assert_eq!(last_up, 0xAB, "last upload byte must match");
            assert_eq!(down_total, DOWN_SIZE, "download byte count must match");
        }

        /// EOF propagation: when the H3 client sends END_STREAM, relay reads 0 bytes.
        #[tokio::test(flavor = "multi_thread")]
        async fn test_upload_eof_propagates() {
            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            let server = tokio::spawn(async move {
                let quic = ep.accept().await.unwrap().await.unwrap();
                let mut h3conn = h3::server::builder()
                    .enable_extended_connect(true)
                    .build::<_, Bytes>(H3Conn::new(quic))
                    .await
                    .unwrap();

                let resolver = h3conn.accept().await.unwrap().unwrap();
                let (_req, mut stream) = resolver.resolve_request().await.unwrap();
                stream
                    .send_response(http::Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();

                let mut transport = H3Transport::new(stream, 32 * 1024);
                let mut buf = vec![0u8; 1024];
                let mut total = 0usize;
                loop {
                    let n = transport.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break; // EOF from client
                    }
                    total += n;
                }
                total
            });

            let (mut driver, mut send_req) = h3::client::new(client_conn(cert, port).await)
                .await
                .unwrap();
            let _driver = tokio::spawn(std::future::poll_fn(move |cx| driver.poll_close(cx)));

            tokio::time::sleep(Duration::from_millis(100)).await;

            let req = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("example.com:80")
                .body(())
                .unwrap();
            let mut stream = send_req.send_request(req).await.unwrap();

            tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
                .await
                .expect("timeout waiting for 200")
                .unwrap();

            let payload = Bytes::from(b"eof-test".to_vec());
            let sent = payload.len();
            stream.send_data(payload).await.unwrap();
            stream.finish().await.unwrap();

            let received = tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("server timed out")
                .unwrap();

            assert_eq!(received, sent, "server must receive exactly the bytes sent");
        }
    }
}
