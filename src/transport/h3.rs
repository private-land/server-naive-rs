//! HTTP/3 transport layer for NaiveProxy CONNECT tunneling over QUIC.
//!
//! Wraps an `h3::server::RequestStream` as `AsyncRead + AsyncWrite` using a
//! `tokio::io::duplex` pair bridged by a background task.
//!
//! Data flow (four independent tasks):
//!
//!   [recv loop]  h3.recv_data() → ul_tx (unbounded) → [ul_task] io_write → relay
//!   [dl_task]    io_read ← relay → dl_tx (unbounded) → [send_task] h3.send_data()
//!
//! All four paths run concurrently — no path can block another:
//!
//! Bug 1 (fixed in v0.1.2): SETTINGS_ENABLE_CONNECT_PROTOCOL=0 caused streams 2..N
//!   to be refused by strict clients.  Fix: enable_extended_connect(true) on builder.
//!
//! Bug 2 (fixed in v0.1.3): `write_all()` inside the select! arm blocked recv_data().
//!   Fix: ul_task runs write_all in its own task; recv loop only does non-blocking sends.
//!
//! Bug 3 (fixed in v0.1.5): `send_data()` inside the select! arm blocked recv_data().
//!   When both upload and download are active simultaneously (real speedtest), QUIC send
//!   window fills → send_data() awaits → recv_data() is never polled → upload window
//!   exhausted → both directions stall.
//!   Fix: split the RequestStream into send/recv halves; send_task calls send_data()
//!   independently so recv_data() is never delayed by QUIC congestion on the send side.

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
/// Four tasks run independently so no path can block another:
///   recv loop → ul_tx → ul_task → io_write (relay upstream)
///   dl_task ← io_read (relay downstream) → dl_tx → send_task → h3.send_data
async fn bridge<C>(h3: h3::server::RequestStream<C, Bytes>, io: DuplexStream)
where
    C: h3::quic::BidiStream<Bytes> + Send + 'static,
    C::RecvStream: Send + 'static,
    C::SendStream: Send + 'static,
{
    // Upload channel: recv loop enqueues non-blocking; ul_task drains with write_all.
    // Bounded in practice by the QUIC stream receive window (~64 KiB per stream).
    let (ul_tx, mut ul_rx) = mpsc::unbounded_channel::<Option<Bytes>>();
    // Download channel: dl_task enqueues non-blocking; send_task drains with send_data.
    // Bounded in practice by TCP throughput × QUIC send stall duration (a few MB max).
    let (dl_tx, dl_rx) = mpsc::unbounded_channel::<Bytes>();
    let (mut io_read, mut io_write) = tokio::io::split(io);

    // Split the h3 stream so send and recv run in independent tasks (Bug 3 fix).
    // Without splitting, send_data() inside a select! arm would block recv_data()
    // whenever the QUIC send window filled — stalling upload during heavy download.
    let (mut h3_send, mut h3_recv) = h3.split();

    // ul_task: write_all never prevents recv_data() from being polled (Bug 2 fix).
    let ul_task = tokio::spawn(async move {
        while let Some(Some(bytes)) = ul_rx.recv().await {
            if io_write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        // Shutdown signals EOF to the relay's read side (dropping WriteHalf alone
        // does not close the DuplexStream while io_read is still alive).
        let _ = io_write.shutdown().await;
    });

    // dl_task: reads relay downstream output and queues for send_task.
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

    // send_task: drains dl_rx and calls h3.send_data — independent of recv loop.
    // Running in its own task means QUIC congestion on the send side never delays
    // recv_data() in the recv loop below (Bug 3 fix).
    //
    // On send_data error: remaining dl_rx items are dropped (the loop breaks, dl_rx
    // goes out of scope).  This is intentional — the QUIC stream is already broken so
    // the peer cannot receive those bytes anyway.  dl_task detects the dropped dl_rx
    // (dl_tx.send returns Err) and exits, after which io_read is dropped, signalling
    // the relay that the downstream channel is gone.
    let send_task = tokio::spawn(async move {
        let mut dl_rx = dl_rx;
        while let Some(bytes) = dl_rx.recv().await {
            if h3_send.send_data(bytes).await.is_err() {
                break;
            }
        }
        let _ = h3_send.finish().await;
    });

    // Recv loop: h3.recv_data() → ul_tx (non-blocking enqueue).
    // Never blocked by send_data() because h3_send is in send_task.
    loop {
        match h3_recv.recv_data().await {
            Ok(Some(mut data)) => {
                let bytes = data.copy_to_bytes(data.remaining());
                if ul_tx.send(Some(bytes)).is_err() {
                    break;
                }
            }
            // Client FIN: sentinel causes ul_task to call io_write.shutdown() → relay EOF.
            Ok(None) | Err(_) => {
                let _ = ul_tx.send(None);
                break;
            }
        }
    }
    // Drop h3_recv now, before awaiting the tasks.
    // h3::server::RequestStream::split() clones RequestEnd into both halves; each
    // half notifies the H3 connection (releases its stream slot) when dropped.
    // Dropping h3_recv here — rather than letting it live until bridge() returns —
    // tells the H3 connection that the recv side of this request is done as soon as
    // the client FIN is processed, allowing the connection to accept new streams
    // sooner instead of holding the slot for the duration of ul/dl/send tasks.
    drop(h3_recv);

    ul_task.await.ok();
    dl_task.await.ok();
    send_task.await.ok();
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

    // ── send_task error-path tests ─────────────────────────────────────────────
    //
    // Verify that when send_data() fails mid-bridge:
    //   1. (RED)   pending items in dl_rx are dropped, not delivered
    //   2. (GREEN) dl_task terminates promptly once dl_rx is gone (no deadlock)

    /// RED: shows that dropping dl_rx (send_task exiting on error) causes a
    /// concurrent dl_task to see Err on its next send and exit.
    /// Remaining items queued BEFORE the drop are discarded — they can't be
    /// delivered because the QUIC stream is already broken.
    #[tokio::test(start_paused = true)]
    async fn red_send_task_exit_drops_pending_dl_bytes() {
        let (dl_tx, dl_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
        let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let q = Arc::clone(&queued);

        // dl_task equivalent: keeps sending until dl_tx is gone.
        let dl_task = tokio::spawn(async move {
            for i in 0..10usize {
                let payload = bytes::Bytes::from(vec![i as u8; 64]);
                if dl_tx.send(payload).is_err() {
                    break;
                }
                q.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });

        // Let dl_task queue all 10 items.
        tokio::time::advance(std::time::Duration::from_millis(1)).await;
        dl_task.await.unwrap();
        assert_eq!(queued.load(std::sync::atomic::Ordering::Relaxed), 10);

        // send_task exits on error: drop dl_rx without draining.
        // The 10 queued items are abandoned — this is the documented behaviour.
        drop(dl_rx);
        // If we reach here the items were silently discarded (no panic/deadlock).
    }

    /// GREEN: once dl_rx is dropped by send_task, a concurrent dl_task that is
    /// mid-send terminates promptly (next dl_tx.send returns Err → task exits).
    #[tokio::test]
    async fn green_dl_task_exits_promptly_when_dl_rx_dropped() {
        let (dl_tx, dl_rx) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let e = Arc::clone(&exited);

        // dl_task: streams continuously until channel is closed.
        let dl_task = tokio::spawn(async move {
            loop {
                let payload = bytes::Bytes::from(vec![0u8; 64]);
                if dl_tx.send(payload).is_err() {
                    break;
                }
                tokio::task::yield_now().await; // give other tasks a chance to run
            }
            e.store(true, std::sync::atomic::Ordering::Release);
        });

        // Allow dl_task to run a few iterations.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Simulate send_task exiting on error: drop the receiver.
        drop(dl_rx);

        // dl_task should see Err on its next send and exit within the test timeout.
        tokio::time::timeout(std::time::Duration::from_secs(1), dl_task)
            .await
            .expect("dl_task did not exit within 1s after dl_rx was dropped")
            .unwrap();

        assert!(
            exited.load(std::sync::atomic::Ordering::Acquire),
            "GREEN: dl_task exited promptly after dl_rx was dropped by send_task"
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
