//! HTTP/3 transport layer for NaiveProxy CONNECT tunneling over QUIC.
//!
//! Wraps an `h3::server::RequestStream` as `AsyncRead + AsyncWrite` using a
//! `tokio::io::duplex` pair bridged by a background task.
//!
//! Data flow:
//!   H3 recv_data → upload channel (unbounded) → ul_task → io_write → relay
//!   relay writes → io_read → dl_task → download channel → H3 send_data
//!
//! The upload channel is **unbounded** so `h3.recv_data()` is never blocked
//! waiting for `io_write`.  The previous design ran `io_write.write_all()`
//! inside the `select!` arm, which prevented `recv_data()` from being polled
//! while the duplex was full.  With 8 parallel upload streams the duplex
//! filled whenever the relay was slow, exhausting the QUIC stream receive
//! window and stalling all streams — the multi-thread upload bug.

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
    // Channel: io reader task → main loop → h3 send_data
    // Bounded to 16 to limit buffered data and apply backpressure.
    let (dl_tx, mut dl_rx) = mpsc::channel::<Bytes>(16);
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
        // None payload = FIN sentinel or channel closed: io_write dropped here → EOF to relay.
    });

    // dl_task: reads from relay and queues bytes for h3 send_data.
    let dl_task = tokio::spawn(async move {
        let mut buf = vec![0u8; BRIDGE_BUF];
        loop {
            match io_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if dl_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
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
}
