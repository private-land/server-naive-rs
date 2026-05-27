//! Bidirectional relay with idle timeout and traffic statistics.
//!
//! Design notes (sing-box parity)
//! ──────────────────────────────
//! After a directional buffer reaches EOF on its reader, we either:
//!
//!   • call `poll_shutdown` on the peer writer (TCP FIN, default), or
//!   • mark the side as done without shutting down (`suppress_shutdown=true`,
//!     reserved for protocols where forwarding FIN is wrong).
//!
//! Then we *wait indefinitely* for the other direction to finish — there is
//! no application-level half-close timer.  This mirrors sing-box's
//! `bufio.CopyConn`, whose `task.Group` simply waits for both upload and
//! download goroutines to complete.  Earlier revisions had an
//! `uplink_only_timeout` that fired N seconds after client EOF; it
//! prematurely cut HTTP/1.1 keep-alive responses (ooklaserver speedtest
//! upload ACKs, in particular) and is now gone.  The coarse
//! `idle_timeout` — which only fires when *both* directions are silent —
//! plus the QUIC/TCP transport idle timeouts are the sole safety nets.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::hooks::{StatsCollector, UserId};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTermination {
    Completed,
    IdleTimeout,
    Error,
}

impl std::fmt::Display for RelayTermination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => f.write_str("completed"),
            Self::IdleTimeout => f.write_str("idle_timeout"),
            Self::Error => f.write_str("error"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CopyResult {
    pub a_to_b: u64,
    pub b_to_a: u64,
    #[allow(dead_code)]
    pub completed: bool,
    pub termination: RelayTermination,
    #[allow(dead_code)]
    pub client_eof: bool,
    #[allow(dead_code)]
    pub remote_eof: bool,
}

struct DirectionalBuffer {
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
    amt: u64,
    read_done: bool,
    shutdown_done: bool,
    /// When true, skip calling `poll_shutdown` on the writer when the reader
    /// reaches EOF — i.e. do NOT forward the half-close to the peer.
    ///
    /// In production this is `false` for the A→B direction so that client
    /// END_STREAM is propagated as a TCP FIN, matching sing-box's CopyConn +
    /// N.CloseWrite design.  The flag is retained for protocols where FIN
    /// forwarding would be wrong (none currently in use).
    suppress_shutdown: bool,
}

impl DirectionalBuffer {
    fn new(buf_size: usize, suppress_shutdown: bool) -> Self {
        Self {
            buf: vec![0u8; buf_size],
            pos: 0,
            cap: 0,
            amt: 0,
            read_done: false,
            shutdown_done: false,
            suppress_shutdown,
        }
    }

    #[inline]
    fn is_done(&self) -> bool {
        self.shutdown_done
    }

    #[inline]
    fn has_read_eof(&self) -> bool {
        self.read_done
    }

    #[inline]
    fn bytes_transferred(&self) -> u64 {
        self.amt
    }

    fn poll_copy<R: AsyncRead, W: AsyncWrite>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }

        loop {
            while self.pos < self.cap {
                match writer
                    .as_mut()
                    .poll_write(cx, &self.buf[self.pos..self.cap])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero bytes",
                        )));
                    }
                    Poll::Ready(Ok(i)) => {
                        self.pos += i;
                        self.amt += i as u64;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        if !self.read_done && self.cap < self.buf.len() {
                            let mut read_buf = ReadBuf::new(&mut self.buf[self.cap..]);
                            match reader.as_mut().poll_read(cx, &mut read_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = read_buf.filled().len();
                                    if n == 0 {
                                        self.read_done = true;
                                    } else {
                                        self.cap += n;
                                    }
                                }
                                Poll::Ready(Err(_)) => {
                                    self.read_done = true;
                                }
                                Poll::Pending => {}
                            }
                        }
                        return Poll::Pending;
                    }
                }
            }

            match writer.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }

            if self.read_done {
                if !self.suppress_shutdown {
                    let _ = ready!(writer.as_mut().poll_shutdown(cx));
                }
                self.shutdown_done = true;
                return Poll::Ready(Ok(()));
            }

            let mut buf = ReadBuf::new(&mut self.buf);
            ready!(reader.as_mut().poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                self.read_done = true;
            } else {
                self.pos = 0;
                self.cap = n;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)] // all 8 params are distinct knobs; a config struct is a future refactor
pub async fn copy_bidirectional_with_stats<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout_secs: u64,
    uplink_only_secs: u64,
    downlink_only_secs: u64,
    buffer_size: usize,
    stats: Option<(UserId, Arc<dyn StatsCollector>)>,
    // When `true`, a half-close from the A (client) side is NOT forwarded as a
    // TCP FIN to the B (server) side.  Use for CONNECT tunnelling so that a
    // sing-box / NaiveProxy client closing its QUIC upload stream after a GET
    // request does not cause origin servers to truncate their response.
    suppress_a_to_b_shutdown: bool,
) -> io::Result<CopyResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // The `uplink_only_secs` / `downlink_only_secs` parameters are retained for
    // API compatibility but intentionally ignored: sing-box's reference NaiveProxy
    // server has no application-level half-close timer, and adding one cuts
    // ooklaserver speedtest uploads/downloads mid-transfer when the origin uses
    // HTTP/1.1 keep-alive.  We rely on the coarse `idle_timeout` (and, in
    // production, on QUIC's own idle timeout) as the sole safety net.
    let _ = (uplink_only_secs, downlink_only_secs);

    let mut a_to_b = DirectionalBuffer::new(buffer_size, suppress_a_to_b_shutdown);
    let mut b_to_a = DirectionalBuffer::new(buffer_size, false);

    let idle_timeout = tokio::time::Duration::from_secs(idle_timeout_secs);
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    let mut termination = RelayTermination::Completed;

    let result: io::Result<bool> = std::future::poll_fn(|cx| {
        let a_bytes_before = a_to_b.bytes_transferred();
        let b_bytes_before = b_to_a.bytes_transferred();

        if !a_to_b.is_done() {
            match a_to_b.poll_copy(cx, Pin::new(&mut *a), Pin::new(&mut *b)) {
                Poll::Ready(Ok(())) | Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    termination = RelayTermination::Error;
                    return Poll::Ready(Err(e));
                }
            }
        }

        if !b_to_a.is_done() {
            match b_to_a.poll_copy(cx, Pin::new(&mut *b), Pin::new(&mut *a)) {
                Poll::Ready(Ok(())) | Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    termination = RelayTermination::Error;
                    return Poll::Ready(Err(e));
                }
            }
        }

        let a_progress = a_to_b.bytes_transferred() > a_bytes_before;
        let b_progress = b_to_a.bytes_transferred() > b_bytes_before;
        if a_progress || b_progress {
            idle_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + idle_timeout);
        }

        if a_to_b.is_done() && b_to_a.is_done() {
            termination = RelayTermination::Completed;
            return Poll::Ready(Ok(true));
        }

        if idle_sleep.as_mut().poll(cx).is_ready() {
            termination = RelayTermination::IdleTimeout;
            return Poll::Ready(Ok(false));
        }

        Poll::Pending
    })
    .await;

    let a_to_b_bytes = a_to_b.bytes_transferred();
    let b_to_a_bytes = b_to_a.bytes_transferred();

    if let Some((user_id, collector)) = stats {
        if a_to_b_bytes > 0 {
            collector.record_upload(user_id, a_to_b_bytes);
        }
        if b_to_a_bytes > 0 {
            collector.record_download(user_id, b_to_a_bytes);
        }
    }

    let client_eof = a_to_b.has_read_eof();
    let remote_eof = b_to_a.has_read_eof();

    match result {
        Ok(completed) => Ok(CopyResult {
            a_to_b: a_to_b_bytes,
            b_to_a: b_to_a_bytes,
            completed,
            termination,
            client_eof,
            remote_eof,
        }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_basic_bidirectional_copy() {
        let data = b"hello world";
        let mut client = Cursor::new(data.to_vec());
        let mut remote = Cursor::new(Vec::new());

        let result =
            copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None, false)
                .await
                .unwrap();

        assert!(result.completed);
        assert!(result.a_to_b > 0);
    }

    /// A stream that never returns data or EOF (keeps connection open).
    struct NeverEofSink;

    impl AsyncRead for NeverEofSink {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for NeverEofSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Sing-box parity: after the client closes its upload (a_to_b reaches EOF),
    /// the relay forwards FIN to the peer and then waits for the peer to finish
    /// — there is no half-close timer.  Earlier revisions fired
    /// `uplink_only_timeout` 30 s after client EOF, which severed slow
    /// HTTP/1.1 keep-alive responses such as ooklaserver speedtest upload ACKs.
    ///
    /// The regression test below verifies the timer is gone: the relay must
    /// still be alive 60 s after client EOF (well past the historical 30 s
    /// window), assuming the peer is still open.
    #[tokio::test(start_paused = true)]
    async fn test_no_half_close_timer_after_client_eof() {
        use tokio::time::Duration;

        let relay_task = tokio::spawn(async move {
            let mut client = Cursor::new(b"hello".to_vec());
            let mut remote = NeverEofSink;
            copy_bidirectional_with_stats(
                &mut client,
                &mut remote,
                300, // idle_timeout = 5 min — must NOT fire in this test
                1,   // (ignored) historical uplink_only_timeout
                1,   // (ignored) historical downlink_only_timeout
                1024,
                None,
                false,
            )
            .await
        });

        // Drive the relay to its first poll so the idle timer is armed.
        tokio::task::yield_now().await;
        // Advance 60 s — twice the historical half-close window.
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;

        assert!(
            !relay_task.is_finished(),
            "relay must still be running 60 s after client EOF — the half-close \
             timer was removed in v0.2.9 to match sing-box behaviour"
        );
        relay_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_fires() {
        let mut client = NeverEofSink;
        let mut remote = NeverEofSink;

        let result =
            copy_bidirectional_with_stats(&mut client, &mut remote, 3, 100, 100, 1024, None, false)
                .await
                .unwrap();

        assert_eq!(result.termination, RelayTermination::IdleTimeout);
    }

    #[tokio::test]
    async fn test_stats_recorded() {
        use std::sync::atomic::{AtomicU64, Ordering};

        struct RecordingCollector {
            upload: AtomicU64,
            download: AtomicU64,
        }
        impl StatsCollector for RecordingCollector {
            fn record_request(&self, _: UserId) {}
            fn record_upload(&self, _: UserId, bytes: u64) {
                self.upload.fetch_add(bytes, Ordering::Relaxed);
            }
            fn record_download(&self, _: UserId, bytes: u64) {
                self.download.fetch_add(bytes, Ordering::Relaxed);
            }
        }

        let collector = Arc::new(RecordingCollector {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        });

        let mut client = Cursor::new(b"upload".to_vec());
        let mut remote = Cursor::new(b"download".to_vec());

        let result = copy_bidirectional_with_stats(
            &mut client,
            &mut remote,
            300,
            2,
            5,
            1024,
            Some((1, Arc::clone(&collector) as Arc<dyn StatsCollector>)),
            false,
        )
        .await
        .unwrap();

        assert!(result.a_to_b > 0, "upload bytes should be counted");
        assert!(result.b_to_a > 0, "download bytes should be counted");
        assert_eq!(
            collector.upload.load(Ordering::Relaxed),
            result.a_to_b,
            "recorded upload must match relay count"
        );
        assert_eq!(
            collector.download.load(Ordering::Relaxed),
            result.b_to_a,
            "recorded download must match relay count"
        );
    }

    // ── RED: flush_ok false-negative on idle timer ────────────────────────────
    //
    // A writer whose poll_flush always returns Pending keeps flush_ok = false
    // even when bytes ARE transferred.  With the current progress check:
    //
    //   a_progress = bytes_transferred > before && has_flushed()
    //
    // the idle timer is NEVER reset despite active data flow, causing a
    // premature IdleTimeout.
    //
    // Setup:
    //   t = 0.0  relay starts, idle_sleep fires at t = 1.0
    //   t = 0.5  we inject 64 bytes → relay transfers them → flush_ok = false
    //            → timer NOT reset (bug) or reset to t = 1.5 (fix)
    //   t = 1.2  advance past original deadline but before reset deadline
    //            bug:  relay finished (IdleTimeout at t = 1.0)
    //            fix:  relay alive   (timer at t = 1.5, not yet fired)

    /// Accepts all bytes, but poll_flush always returns Pending.
    /// Used to keep flush_ok = false while bytes flow freely.
    struct PendingFlushWriter;

    impl AsyncRead for PendingFlushWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingFlushWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending // keeps flush_ok = false
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn red_idle_timer_not_reset_when_flush_always_pending() {
        use tokio::time::Duration;

        let (client_tx, client_rx) = tokio::io::duplex(8192);

        let relay = tokio::spawn(async move {
            let mut a = client_rx;
            let mut b = PendingFlushWriter;
            copy_bidirectional_with_stats(
                &mut a, &mut b, 1, // idle_timeout = 1 s
                10, 10, 1024, None, false,
            )
            .await
        });

        // ── CRITICAL: let the relay task run at t = 0 so idle_sleep is armed
        // at t = 0 + 1 = 1.0 s, not at the time of the first advance.
        // Without this yield the relay first runs during advance(500ms) and the
        // sleep starts at t = 0.5 → fires at t = 1.5 regardless of the bug.
        tokio::task::yield_now().await; // relay first poll: idle_sleep armed at t = 1.0

        // t = 0.0 → 0.5: relay waits (no data yet), idle_sleep deadline = t = 1.0
        tokio::time::advance(Duration::from_millis(500)).await;

        // inject bytes at t = 0.5 (WITHOUT closing the pipe)
        // FIX: a_progress = bytes(64) > before(0) → idle_sleep reset to t = 1.5
        // BUG: flush_ok = false → a_progress = false → idle_sleep stays at t = 1.0
        {
            use tokio::io::AsyncWriteExt;
            let mut tx = client_tx;
            tx.write_all(&[0u8; 64]).await.unwrap();
            tokio::task::yield_now().await; // relay processes the 64 bytes
            std::mem::forget(tx); // prevent EOF: keep write side alive (leaked)
        }

        // t = 0.5 → 1.2: advance past the original deadline (1.0) but not yet
        // past the reset deadline (1.5).
        tokio::time::advance(Duration::from_millis(700)).await;
        tokio::task::yield_now().await; // allow relay to process any fired timers

        let timed_out = relay.is_finished();

        // BUG:  idle_sleep fired at t = 1.0 (timer never reset because flush_ok = false
        //       blocked the progress check) → relay terminated → is_finished() = true
        //       → !true = false → assertion FAILS  ← RED
        // FIX:  timer was reset to t = 1.5 > t = 1.2 → relay still alive
        //       → is_finished() = false → !false = true → assertion PASSES  ← GREEN
        assert!(
            !timed_out,
            "relay timed out at t=1.2s: bytes were transferred at t=0.5s so the \
             idle timer should have been reset to t=1.5s, but flush_ok=false \
             prevented the progress check from registering the transfer"
        );

        relay.abort();
    }

    // ── TCP half-close / FIN propagation tests ───────────────────────────────
    //
    // When a NaiveProxy / sing-box client closes its QUIC upload stream
    // (END_STREAM) after forwarding a proxied HTTP request, the H3 bridge
    // propagates that as an EOF through the relay's A→B DirectionalBuffer.
    // With `suppress_a_to_b_shutdown = false` (production setting, matching
    // sing-box's `CopyConn` + `N.CloseWrite`), the relay calls `poll_shutdown`
    // on the B writer, sending a TCP FIN to the origin server.  HTTP/1.1
    // servers (including ooklaserver) reply with the full response body once
    // they see FIN — it just signals "client is done writing".
    //
    // `suppress_a_to_b_shutdown = true` is retained for protocols where FIN
    // forwarding is incorrect; the second test below documents its mechanics.

    /// `ShutdownRecorder` wraps any `AsyncRead + AsyncWrite` and sets a flag the
    /// moment `poll_shutdown` is called on its write side.  Use it to assert
    /// whether the relay propagated a client EOF as a FIN to the server.
    struct ShutdownRecorder<T> {
        inner: T,
        shutdown_called: Arc<std::sync::atomic::AtomicBool>,
    }

    impl<T: AsyncRead + Unpin> AsyncRead for ShutdownRecorder<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for ShutdownRecorder<T> {
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
            self.shutdown_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Verifies that `suppress_a_to_b_shutdown = false` (the production setting)
    /// propagates the client's half-close as a TCP FIN to the origin server.
    ///
    /// This is the correct and expected behaviour for HTTP CONNECT tunnelling:
    /// when the client closes its upload stream (QUIC END_STREAM), the relay
    /// forwards that as a FIN so the origin server knows the client is done
    /// writing.  HTTP servers then send the full response and close.
    #[tokio::test]
    async fn test_relay_propagates_client_eof_as_fin_when_suppress_disabled() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut a_relay, a_client) = tokio::io::duplex(8192);
        let (b_inner, mut b_server) = tokio::io::duplex(8192);

        let shutdown_called = Arc::new(AtomicBool::new(false));
        let mut b_relay = ShutdownRecorder {
            inner: b_inner,
            shutdown_called: shutdown_called.clone(),
        };

        // Client: write a GET-like request, then close the upload direction.
        // This mirrors sing-box H3 behaviour: upload stream END_STREAM fires
        // after the request body is sent.
        let client_task = tokio::spawn(async move {
            let (mut cr, mut cw) = tokio::io::split(a_client);
            cw.write_all(b"GET /download HTTP/1.1\r\nHost: test\r\n\r\n")
                .await
                .unwrap();
            cw.shutdown().await.unwrap(); // half-close upload only
                                          // Keep reading so the relay can write the (empty) server response
                                          // and complete normally without hitting a downlink-only timeout.
            let mut buf = Vec::new();
            cr.read_to_end(&mut buf).await.ok();
        });

        // Server: read the request then immediately close — no response body.
        // We only care whether the relay called poll_shutdown on b_relay, not
        // about what the server sends.
        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 256];
            let _ = b_server.read(&mut buf).await;
            // drop b_server → EOF on b_relay read side → relay b_to_a completes
        });

        let _ = copy_bidirectional_with_stats(
            &mut a_relay,
            &mut b_relay,
            5, // idle_timeout
            5, // uplink_only_timeout
            5, // downlink_only_timeout
            4096,
            None,
            false, // suppress_a_to_b_shutdown = false → relay DOES send FIN
        )
        .await;

        client_task.await.unwrap();
        server_task.await.unwrap();

        assert!(
            shutdown_called.load(Ordering::SeqCst),
            "suppress=false: relay must call poll_shutdown on the server writer \
             when the client closes its upload direction (FIN propagated)"
        );
    }

    /// Verifies the `suppress_a_to_b_shutdown = true` flag mechanics.
    ///
    /// When suppress=true, a client half-close does NOT send a FIN to the origin.
    /// The relay marks a_to_b as done immediately and continues delivering the
    /// origin's response without forwarding the upload EOF.
    ///
    /// Note: this flag is NOT used in production (suppress=false is correct for
    /// HTTP CONNECT tunnelling).  This test documents the flag's contract in case
    /// it's ever needed for a specific outbound type.
    #[tokio::test]
    async fn test_suppress_flag_prevents_fin_and_delivers_full_download() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const BODY: &[u8] = &[b'X'; 100_000];
        const HEADER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n";
        let expected: u64 = (HEADER.len() + BODY.len()) as u64;

        let (mut a_relay, a_client) = tokio::io::duplex(8192);
        let (b_inner, b_server) = tokio::io::duplex(128 * 1024);

        let shutdown_called = Arc::new(AtomicBool::new(false));
        let mut b_relay = ShutdownRecorder {
            inner: b_inner,
            shutdown_called: shutdown_called.clone(),
        };

        // Mock origin server: receives the GET request, sends the full body,
        // then closes.  It does not check for FIN — just like a server that
        // always sends the response once it has read the request headers.
        let server_task = tokio::spawn(async move {
            let mut b = b_server;
            let mut req = vec![0u8; 256];
            let _ = b.read(&mut req).await; // consume the GET request
            b.write_all(HEADER).await.unwrap();
            b.write_all(BODY).await.unwrap();
            b.shutdown().await.unwrap(); // server closes after sending body
        });

        // Client: simulates sing-box H3 — sends GET, closes upload direction,
        // then reads the download body until EOF.
        let received = Arc::new(AtomicU64::new(0));
        let received_clone = received.clone();
        let client_task = tokio::spawn(async move {
            let (mut cr, mut cw) = tokio::io::split(a_client);
            cw.write_all(b"GET /download HTTP/1.1\r\nHost: test\r\n\r\n")
                .await
                .unwrap();
            cw.shutdown().await.unwrap(); // upload END_STREAM
            let mut buf = Vec::new();
            cr.read_to_end(&mut buf).await.ok();
            received_clone.store(buf.len() as u64, Ordering::Relaxed);
        });

        let r = copy_bidirectional_with_stats(
            &mut a_relay,
            &mut b_relay,
            60, // idle_timeout: generous — server is fast in tests
            30, // uplink_only_timeout: time allowed for server to respond after
            // client closes upload (must be > 0 to let server finish)
            30, // downlink_only_timeout
            4096,
            None,
            true, // suppress_a_to_b_shutdown = true → do NOT send FIN to server
        )
        .await
        .unwrap();

        server_task.await.unwrap();
        client_task.await.unwrap();

        // 1. FIN must NOT have been propagated to the origin server.
        assert!(
            !shutdown_called.load(Ordering::SeqCst),
            "suppress=true: relay must NOT call poll_shutdown on the server writer \
             when the client closes its upload direction"
        );

        // 2. Client must have received the complete download body.
        assert_eq!(
            received.load(Ordering::Relaxed),
            expected,
            "client must receive the full {expected}-byte download body \
             (header + body) when FIN propagation is suppressed; \
             relay stats: a_to_b={}, b_to_a={}",
            r.a_to_b,
            r.b_to_a,
        );
    }

    /// Sing-box parity regression: a long upload (client streams body + closes
    /// upload), followed by a long server pause before the small response, must
    /// NOT be terminated prematurely.  Historical bug: `uplink_only_timeout`
    /// fired 30 s after client EOF, killing ooklaserver speedtest upload tests.
    #[tokio::test(start_paused = true)]
    async fn test_long_post_upload_server_pause_is_not_truncated() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::Duration;

        let (a_relay, a_client) = tokio::io::duplex(64 * 1024);
        let (b_relay, b_server) = tokio::io::duplex(64 * 1024);

        // Server: drain the upload, then pause 90 s (3× the old half-close
        // window) before sending a tiny ACK, then close.
        let server_task = tokio::spawn(async move {
            let mut b = b_server;
            let mut sink = [0u8; 4096];
            loop {
                match b.read(&mut sink).await {
                    Ok(0) | Err(_) => break, // client FIN received
                    Ok(_) => {}
                }
            }
            tokio::time::sleep(Duration::from_secs(90)).await;
            b.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            b.shutdown().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let (mut cr, mut cw) = tokio::io::split(a_client);
            cw.write_all(b"POST /upload HTTP/1.1\r\nContent-Length: 4096\r\n\r\n")
                .await
                .unwrap();
            cw.write_all(&[0u8; 4096]).await.unwrap();
            cw.shutdown().await.unwrap();
            let mut buf = Vec::new();
            cr.read_to_end(&mut buf).await.ok();
            buf.len()
        });

        let relay_task = tokio::spawn(async move {
            let mut a = a_relay;
            let mut b = b_relay;
            copy_bidirectional_with_stats(
                &mut a, &mut b, 300, // idle_timeout
                1, 1, // (ignored) historical half-close timeouts
                4096, None, false, // suppress=false → propagate FIN
            )
            .await
        });

        // Pump time forward across the server's 90 s pause + a small margin.
        for _ in 0..120 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        let r = relay_task.await.unwrap().unwrap();
        let received = client_task.await.unwrap();
        server_task.await.unwrap();

        assert_eq!(
            r.termination,
            RelayTermination::Completed,
            "relay must finish Completed even after a 90 s post-upload server \
             pause — no half-close timer should be cutting it off",
        );
        assert!(received > 0, "client must receive the server's ACK");
    }
}
