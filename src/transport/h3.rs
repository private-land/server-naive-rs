//! HTTP/3 transport layer for NaiveProxy CONNECT tunneling over QUIC.
//!
//! Wraps an `h3::server::RequestStream` as `AsyncRead + AsyncWrite` using a
//! `tokio::io::duplex` pair bridged by a background task.
//!
//! Data flow:
//!   H3 recv_data → upload channel (unbounded) → ul_task → io_write → relay
//!   relay writes → io_read → dl_task → download channel (unbounded) → H3 send_data
//!
//! Both channels are **unbounded** to decouple the H3 layer from the relay:
//!
//! Upload channel: `h3.recv_data()` is never blocked waiting for `io_write`.
//!   The previous design ran `io_write.write_all()` inside the `select!` arm,
//!   which prevented `recv_data()` from being polled while the duplex was full.
//!   With 8 parallel upload streams the duplex filled whenever the relay was
//!   slow, exhausting the QUIC stream receive window and stalling all streams.
//!
//! Download channel: the relay is never blocked waiting for `h3.send_data()`.
//!   `send_data()` executes inside the `select!` arm body, so while it awaits
//!   (QUIC send window temporarily full on real-network RTT > 0) the dl_rx is
//!   not drained.  With a bounded channel (capacity 16 × 32 KB = 512 KB) the
//!   relay's DuplexStream fills in ~46 ms at 100 Mbit/s, stalling the relay
//!   and ultimately the TCP connection to the remote — causing speedtest
//!   "test failed to complete" errors on real-network deployments.  An
//!   unbounded channel absorbs temporary send_data() delays without stalling.

use bytes::{Buf, Bytes};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::mpsc;

/// Bridge buffer size — matches NaivePaddedTransport's default frame size.
const BRIDGE_BUF: usize = 32 * 1024;

/// H3Transport exposes an HTTP/3 CONNECT stream as `AsyncRead + AsyncWrite`.
///
/// Internally it spawns a bridge task that ferries data between the h3
/// `RequestStream` and a `tokio::io::duplex` channel.
pub struct H3Transport {
    inner: DuplexStream,
}

impl H3Transport {
    /// Create a new H3Transport from an h3 request stream.
    ///
    /// `buffer_size` controls the duplex channel capacity.
    /// The caller must have already sent the 200 response on `stream`.
    pub fn new<C>(stream: h3::server::RequestStream<C, Bytes>, buffer_size: usize) -> Self
    where
        C: h3::quic::BidiStream<Bytes> + Send + 'static,
        C::RecvStream: Send + 'static,
        C::SendStream: Send + 'static,
    {
        let (client, server_half) = tokio::io::duplex(buffer_size);
        tokio::spawn(bridge(stream, server_half));
        Self { inner: client }
    }
}

/// Bridge an h3 `RequestStream` to a `DuplexStream`.
///
/// Runs until either side closes or errors.
async fn bridge<C>(mut h3: h3::server::RequestStream<C, Bytes>, io: DuplexStream)
where
    C: h3::quic::BidiStream<Bytes> + Send + 'static,
    C::RecvStream: Send + 'static,
    C::SendStream: Send + 'static,
{
    // Download channel: unbounded so dl_task never blocks waiting for main loop.
    // Memory growth is bounded by TCP throughput × QUIC send stall duration: dl_task
    // drains the DuplexStream (32 KiB) immediately without waiting for send_data(), so
    // the relay is never throttled by QUIC congestion.  In practice this is a few hundred
    // KiB (100 Mbit/s × 50 ms RTT) to a few MB under heavy congestion — acceptable for a
    // proxy.  A bounded channel would reintroduce the relay stall we are fixing here.
    let (dl_tx, mut dl_rx) = mpsc::unbounded_channel::<Bytes>();
    // Upload channel: unbounded so recv_data() never blocks waiting for io_write.
    // Memory growth is bounded in practice by the QUIC stream receive window
    // (Quinn defaults to 64 KiB per stream): once the window fills the peer stops
    // sending, so at most one window's worth of data can pile up here.  A
    // code-level bound is not added because it would reintroduce the stall.
    let (ul_tx, ul_rx) = mpsc::unbounded_channel::<Option<Bytes>>();
    let (mut io_read, io_write) = tokio::io::split(io);

    // ul_task: drains the upload channel and writes to the relay.
    // Running in its own task means write_all blocking never prevents recv_data()
    // from being polled — fixing the multi-thread upload stall.
    let ul_task = tokio::spawn(async move {
        let mut io_write = io_write;
        let mut ul_rx: mpsc::UnboundedReceiver<Option<Bytes>> = ul_rx;
        while let Some(Some(bytes)) = ul_rx.recv().await {
            if io_write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        // Explicitly shut down the write side so the relay's transport.read() sees EOF.
        // Dropping WriteHalf<DuplexStream> WITHOUT calling shutdown does NOT close the
        // underlying channel: the Arc is shared with io_read (held by dl_task), so the
        // DuplexStream itself is still alive and the write pipe is still open.  The relay
        // would block on transport.read() forever after client FIN without this call.
        let _ = io_write.shutdown().await;
    });

    // dl_task: reads from relay and queues bytes for h3 send_data.
    let dl_task = tokio::spawn(async move {
        let mut buf = vec![0u8; BRIDGE_BUF];
        loop {
            match io_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if dl_tx.send(Bytes::copy_from_slice(&buf[..n])).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Main loop: select between incoming H3 data and queued outgoing data.
    //
    // Half-close handling: when the client sends FIN (recv_data returns None),
    // we send a None sentinel through ul_tx (causes ul_task to drop io_write,
    // signalling EOF to the relay's read side) but keep the loop alive to
    // forward any pending server→client data through the dl_rx channel.
    // The loop exits only when the relay finishes (dl_rx channel closes) or on error.
    let mut client_fin = false;
    loop {
        if !client_fin {
            tokio::select! {
                // H3 client → relay: enqueue DATA frames for ul_task (non-blocking).
                result = h3.recv_data() => {
                    match result {
                        Ok(Some(mut data)) => {
                            let bytes = data.copy_to_bytes(data.remaining());
                            if ul_tx.send(Some(bytes)).is_err() {
                                break;
                            }
                        }
                        // Client sent FIN: send sentinel so ul_task drops io_write → EOF to relay.
                        // Ignored if ul_task already exited (write error); either way io_write
                        // will be dropped and the relay will see EOF.
                        Ok(None) | Err(_) => {
                            let _ = ul_tx.send(None);
                            client_fin = true;
                        }
                    }
                }
                // Relay → H3 client: forward queued bytes as DATA frames.
                data = dl_rx.recv() => {
                    match data {
                        Some(bytes) => {
                            if h3.send_data(bytes).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        } else {
            // Client FIN received; drain remaining relay→client data.
            match dl_rx.recv().await {
                Some(bytes) => {
                    if h3.send_data(bytes).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    ul_task.abort();
    dl_task.abort();

    // Close the H3 send side cleanly so the client sees a proper stream end.
    let _ = h3.finish().await;
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::time::Duration;

    // ── Upload-side tests (ul_tx unbounded fix) ───────────────────────────────

    /// RED: documents the concurrency bug in the old bridge design.
    ///
    /// When `write_all` runs inside a `select!` arm, the executor cannot poll
    /// `recv_data()` until `write_all` completes.  This test shows that with a
    /// slow writer only 1 of 10 items is consumed within a short window — the
    /// remaining 9 are blocked behind the in-progress write.
    #[tokio::test(start_paused = true)]
    async fn red_old_bridge_recv_gated_by_write() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(10);
        for _ in 0..10 {
            tx.try_send(()).unwrap();
        }
        drop(tx);

        let recv_calls = Arc::new(AtomicUsize::new(0));
        let rc = Arc::clone(&recv_calls);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    item = rx.recv() => {
                        match item {
                            Some(()) => {
                                rc.fetch_add(1, Ordering::Relaxed);
                                // Simulates write_all blocking inside the select! arm.
                                // While this sleep runs, recv() is not polled.
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        tokio::time::advance(Duration::from_millis(50)).await;
        assert_eq!(
            recv_calls.load(Ordering::Relaxed),
            1,
            "RED: old bridge — recv_data() blocked after 1 call; write_all is still running"
        );
    }

    /// GREEN: proves that unbounded channel + separate write task keeps
    /// recv_data() running even when io_write is backed up.
    ///
    /// The fix: `recv_data()` only does a non-blocking channel send; a separate
    /// `ul_task` calls `write_all`.  Even with a slow writer, all 10 receives
    /// complete instantly.
    #[tokio::test(start_paused = true)]
    async fn green_new_bridge_recv_unblocked_by_write() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(10);
        for _ in 0..10 {
            tx.try_send(()).unwrap();
        }
        drop(tx);

        let recv_calls = Arc::new(AtomicUsize::new(0));
        let rc = Arc::clone(&recv_calls);

        let (upload_tx, mut upload_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

        // Slow writer running in its own task — does not block the recv loop.
        tokio::spawn(async move {
            while let Some(()) = upload_rx.recv().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Recv loop: non-blocking enqueue to upload_tx, no awaiting write.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    item = rx.recv() => {
                        match item {
                            Some(()) => {
                                rc.fetch_add(1, Ordering::Relaxed);
                                upload_tx.send(()).unwrap();
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        tokio::time::advance(Duration::from_millis(5)).await;
        assert_eq!(
            recv_calls.load(Ordering::Relaxed),
            10,
            "GREEN: new bridge — all 10 recv_data() calls complete immediately; \
             write_all blocking does not stall recv"
        );
    }

    // ── Download-side tests (dl_tx unbounded fix) ─────────────────────────────

    /// RED: documents the download stall in the old bounded dl_tx design.
    ///
    /// When `dl_tx` is bounded and `h3.send_data()` blocks inside the main-loop
    /// select! arm, `dl_rx` stops being drained.  `dl_task` then blocks on
    /// `dl_tx.send().await` once the channel is full — stalling `io_read` and
    /// ultimately the remote TCP connection (speedtest "Test failed to complete").
    ///
    /// With capacity 4, dl_task stalls after CAPACITY+1 sends: it fills the
    /// channel, the slow consumer frees one slot, dl_task fills it again, then
    /// blocks until the consumer finishes its 100 ms sleep — which our 50 ms
    /// advance never reaches.
    #[tokio::test(start_paused = true)]
    async fn red_old_bridge_dl_gated_by_bounded_channel() {
        const CAPACITY: usize = 4;
        let (dl_tx, mut dl_rx) = tokio::sync::mpsc::channel::<()>(CAPACITY);
        let sent = Arc::new(AtomicUsize::new(0));
        let sc = Arc::clone(&sent);

        // Simulates dl_task: reads are instant, but bounded send may block.
        tokio::spawn(async move {
            for _ in 0..10 {
                if dl_tx.send(()).await.is_err() {
                    break;
                }
                sc.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Simulates main loop: slow h3.send_data() — 100 ms per chunk.
        tokio::spawn(async move {
            while let Some(()) = dl_rx.recv().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        tokio::time::advance(Duration::from_millis(50)).await;
        let n = sent.load(Ordering::Relaxed);
        assert!(
            n < 10,
            "RED: bounded dl channel — dl_task stalled at {n} sends; \
             slow send_data blocks io_read and ultimately the remote TCP"
        );
    }

    /// GREEN: proves that an unbounded dl_tx with a non-blocking send lets
    /// dl_task drain `io_read` without ever waiting for the main loop.
    ///
    /// All 10 reads complete immediately because `dl_tx.send()` never blocks,
    /// regardless of how slow `h3.send_data()` is.
    #[tokio::test(start_paused = true)]
    async fn green_new_bridge_dl_task_unblocked_by_unbounded_channel() {
        let (dl_tx, mut dl_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let sent = Arc::new(AtomicUsize::new(0));
        let sc = Arc::clone(&sent);

        // Simulates new dl_task: non-blocking unbounded send.
        tokio::spawn(async move {
            for _ in 0..10 {
                if dl_tx.send(()).is_err() {
                    break;
                }
                sc.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Simulates slow h3.send_data() in the main loop.
        tokio::spawn(async move {
            while let Some(()) = dl_rx.recv().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        tokio::time::advance(Duration::from_millis(5)).await;
        assert_eq!(
            sent.load(Ordering::Relaxed),
            10,
            "GREEN: unbounded dl channel — all 10 reads complete immediately; \
             slow send_data does not stall dl_task"
        );
    }

    // ── H3Transport end-to-end integration tests (real QUIC loopback) ─────────
    //
    // The channel-pattern tests above prove the mechanism is correct in isolation.
    // These tests verify the full H3Transport::new() bridge with real QUIC streams.
    //
    // Design: the h3 client `Connection` (driver) runs as a background Tokio task
    // so stream operations can be awaited directly — no select!/timer juggling.
    // Sequential per-stream processing keeps client-side logic simple while server
    // tasks run concurrently via Tokio spawn.
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
        /// Data flow: client send_data → h3.recv_data → ul_tx (unbounded) →
        /// ul_task → io_write → DuplexStream → relay reads via H3Transport.
        ///
        /// With the old design (write_all inside select! arm), io_write backpressure
        /// blocked recv_data() — stalling all streams when the relay was slow.
        /// All 8 streams completing proves the ul_tx fix holds end-to-end.
        ///
        /// Multi-thread runtime: bridge tasks, relay tasks, and client tasks run
        /// truly in parallel, avoiding single-thread scheduling deadlocks on the
        /// DuplexStream ping-pong.
        #[tokio::test(flavor = "multi_thread")]
        async fn green_multi_stream_upload_via_bridge() {
            const N: usize = 8;
            const CHUNK: usize = 64 * 1024;

            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            let totals = Arc::new(Mutex::new(vec![0usize; N]));
            let totals_srv = Arc::clone(&totals);

            // Server: accept N streams via a background task that keeps h3conn
            // driven after all N streams are accepted.  Without continued polling,
            // h3 control/QPACK stream processing stalls and recv_data() never
            // delivers the client-side stream FIN to the bridge.
            let server = tokio::spawn(async move {
                let quic = ep.accept().await.unwrap().await.unwrap();
                let mut h3conn = h3::server::builder()
                    .enable_extended_connect(true)
                    .build::<_, Bytes>(H3Conn::new(quic))
                    .await
                    .unwrap();

                let (resolver_tx, mut resolver_rx) = tokio::sync::mpsc::channel(N + 2);

                // Background accept loop: delivers new streams AND keeps h3conn driven.
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

            // Client: background driver frees stream operations from select!/timer juggling.
            let (mut driver, mut send_req) = h3::client::new(client_conn(cert, port).await)
                .await
                .unwrap();
            let _driver = tokio::spawn(std::future::poll_fn(move |cx| driver.poll_close(cx)));

            // Wait for server SETTINGS (SETTINGS_ENABLE_CONNECT_PROTOCOL=1).
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

            // Wait for all N CONNECT HEADERS to be delivered to the server.
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Process all N streams concurrently: avoids single-stream sequential
            // blocking that can stall when relay/bridge tasks compete for DuplexStream.
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
        /// Data flow: relay writes → H3Transport → io_read → dl_task →
        /// dl_tx (unbounded, non-blocking) → main loop → h3.send_data() → QUIC → client.
        ///
        /// With the old bounded dl_tx, dl_task would stall on dl_tx.send().await once
        /// the channel filled (when h3.send_data() was slow), backing up the DuplexStream
        /// and stalling relay writes.  All 8 streams completing proves the fix.
        ///
        /// Multi-thread runtime: bridge tasks can flush h3.send_data() while client
        /// tasks are receiving on other streams — no single-thread head-of-line blocking.
        /// Server sleeps after relay handles finish to keep h3conn alive until all bridge
        /// tasks have called h3.finish() on their streams (bridge runs as a separate
        /// spawned task; the relay handle completes before the bridge flushes).
        #[tokio::test(flavor = "multi_thread")]
        async fn green_multi_stream_download_via_bridge() {
            const N: usize = 8;
            const CHUNK: usize = 64 * 1024;

            install_crypto();
            let (cert, key) = gen_certs();
            let (ep, port) = server_endpoint(cert.clone(), key);

            // Server: each task writes CHUNK bytes through H3Transport, then shuts down.
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
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
                // H3Transport::new() spawns a bridge task that outlives the relay handle.
                // The bridge needs to finish flushing data and calling h3.finish() before
                // h3conn is dropped (drop sends H3_NO_ERROR CONNECTION_CLOSE, which races
                // with in-flight stream FINs on the client side).
                tokio::time::sleep(Duration::from_millis(500)).await;
                drop(h3conn);
            });

            // Client with background driver.
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

            // Process all N streams concurrently: avoids sequential head-of-line blocking
            // where reading stream 0 delays stream 1..N-1 past the connection close window.
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
                                         (expected {CHUNK}); dl_tx or bridge may be blocked"
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
    }
}
