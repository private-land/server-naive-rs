//! Naive proxy padding transport layer.
//!
//! Wraps any `AsyncRead + AsyncWrite` stream with the naive padding protocol:
//! the first 8 frames in each direction use
//! `[2B data_size BE][1B padding_size][data][random padding]` framing.
//! After 8 frames, raw bytes flow without any extra framing.
//!
//! `NaivePaddedH2Transport` and `NaivePaddedH3Transport` are type aliases for
//! the two concrete transport types used in this codebase.

use bytes::{BufMut, Bytes, BytesMut};
use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Number of padding frames before switching to raw mode.
const PADDING_FRAMES: u8 = 8;
/// Maximum data payload per padding frame (matches sing-box).
const MAX_PADDED_PAYLOAD: usize = 65535;

// ── Thread-local xorshift64 PRNG (non-crypto; padding only) ──────────────────

fn gen_random_bytes(buf: &mut [u8]) {
    thread_local! {
        static RNG: Cell<u64> = const { Cell::new(0) };
    }
    RNG.with(|rng| {
        let mut s = rng.get();
        if s == 0 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0x9e37) as u64;
            s = nanos ^ (nanos << 17) ^ 0x9e3779b97f4a7c15;
            if s == 0 {
                s = 0x9e3779b97f4a7c15;
            }
        }
        for b in buf.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = s as u8;
        }
        rng.set(s);
    });
}

fn random_u8() -> u8 {
    let mut b = [0u8];
    gen_random_bytes(&mut b);
    b[0]
}

/// Generates the value for the `Padding` HTTP response header (30–61 chars).
///
/// Mirrors `generateNaivePaddingHeader` from sing-box:
/// first 16 chars from `"!#$()+<>?@[]^`{}"`, remainder `'~'`.
pub fn generate_padding_header() -> String {
    const CHARS: &[u8] = b"!#$()+<>?@[]^`{}";
    let len = (random_u8() % 32 + 30) as usize; // 30–61
    let mut bits_buf = [0u8; 8];
    gen_random_bytes(&mut bits_buf);
    let mut bits = u64::from_le_bytes(bits_buf);
    let mut s = String::with_capacity(len);
    for _ in 0..16 {
        s.push(CHARS[(bits & 15) as usize] as char);
        bits >>= 4;
    }
    for _ in 16..len {
        s.push('~');
    }
    s
}

// ── NaivePaddedTransport<T> ───────────────────────────────────────────────────

/// Wraps any `AsyncRead + AsyncWrite` stream `T` with the naive padding protocol
/// for the first 8 frames in each direction before switching to raw passthrough.
pub struct NaivePaddedTransport<T> {
    inner: T,

    // ── Read state ──────────────────────────────────────────────────────────
    /// Number of padding frames fully consumed from the client.
    read_frames_done: u8,
    /// Partial header buffer and fill position.
    read_hdr: [u8; 3],
    read_hdr_pos: usize,
    /// Data bytes still to be delivered from the current frame.
    read_data_rem: usize,
    /// Padding bytes to discard *right now* (from the frame currently being read).
    read_skip_rem: usize,
    /// Padding bytes to discard *after* the current frame's data is fully read.
    read_pending_skip: usize,

    // ── Write state ─────────────────────────────────────────────────────────
    /// Number of padding frames already sent to the client.
    write_frames_done: u8,
    /// Padded frame bytes pending write to `inner`.
    write_pending: Option<Bytes>,
    write_pending_off: usize,
}

impl<T> NaivePaddedTransport<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            read_frames_done: 0,
            read_hdr: [0; 3],
            read_hdr_pos: 0,
            read_data_rem: 0,
            read_skip_rem: 0,
            read_pending_skip: 0,
            write_frames_done: 0,
            write_pending: None,
            write_pending_off: 0,
        }
    }
}

// ── AsyncRead ─────────────────────────────────────────────────────────────────
//
// State machine (mirrors naiveH2Conn.read in sing-box):
//   1. If read_data_rem > 0  → return data bytes from current frame.
//   2. If read_skip_rem > 0  → discard padding bytes.
//   3. If frames_done >= 8   → raw passthrough.
//   4. Read 3-byte header    → parse next frame, loop back to 1/2.

impl<T: AsyncRead + Unpin> AsyncRead for NaivePaddedTransport<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            // ── Phase 1: deliver data bytes from the current padding frame ──
            if this.read_data_rem > 0 {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                let n = if buf.remaining() > this.read_data_rem {
                    // Caller's buffer is larger — limit to avoid consuming
                    // the next frame's header/padding bytes.
                    // buf.take() shares the parent buffer's memory: zero-copy, no size cap.
                    // Mirrors the pattern in tokio's own Take::poll_read.
                    let mut limited = buf.take(this.read_data_rem);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
                    let n = limited.filled().len();
                    if n > 0 {
                        // Safety: `limited` was backed by the unfilled portion of `buf`;
                        // those `n` bytes were written there and are now initialised.
                        unsafe { buf.assume_init(n) };
                        buf.advance(n);
                    }
                    n
                } else {
                    // buf.remaining() <= read_data_rem: can't overshoot the frame boundary.
                    let before = buf.filled().len();
                    ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
                    buf.filled().len() - before
                };
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }
                this.read_data_rem -= n;
                if this.read_data_rem == 0 {
                    this.read_skip_rem = this.read_pending_skip;
                    this.read_pending_skip = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // ── Phase 2: skip padding bytes from the previous frame ──────────
            if this.read_skip_rem > 0 {
                let mut scratch = [0u8; 256];
                let to_skip = this.read_skip_rem.min(256);
                let mut sbuf = ReadBuf::new(&mut scratch[..to_skip]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sbuf))?;
                let n = sbuf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }
                this.read_skip_rem -= n;
                continue;
            }

            // ── Phase 3: raw passthrough ─────────────────────────────────────
            if this.read_frames_done >= PADDING_FRAMES {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // ── Phase 4: read the 3-byte naive frame header ──────────────────
            while this.read_hdr_pos < 3 {
                let mut hbuf = ReadBuf::new(&mut this.read_hdr[this.read_hdr_pos..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut hbuf))?;
                let n = hbuf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }
                this.read_hdr_pos += n;
            }

            // Parse: [u16 data_size BE][u8 padding_size]
            let data_size = u16::from_be_bytes([this.read_hdr[0], this.read_hdr[1]]) as usize;
            let padding_size = this.read_hdr[2] as usize;
            this.read_hdr_pos = 0;
            this.read_frames_done += 1;
            this.read_data_rem = data_size;
            this.read_pending_skip = padding_size;

            if data_size == 0 {
                // Empty data frame — skip padding immediately.
                this.read_skip_rem = padding_size;
                this.read_pending_skip = 0;
                this.read_data_rem = 0;
            }
            // Loop: phase 1 or 2 will handle the rest.
        }
    }
}

// ── AsyncWrite ────────────────────────────────────────────────────────────────
//
// For the first 8 frames the writer prepends `[u16 data_size BE][u8 pad_size]`
// and appends random padding bytes, then buffers the whole padded frame as
// `write_pending`.  Subsequent calls flush the pending bytes before accepting
// new data.  After 8 frames, writes pass through to `inner` unmodified.

impl<T: AsyncWrite + Unpin> AsyncWrite for NaivePaddedTransport<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Flush any in-progress padded frame before accepting new data.
        // Use a while-loop (mirrors poll_flush) so a partial Ready(Ok(n)) keeps
        // trying instead of returning Pending without a registered waker.
        while this.write_pending.is_some() {
            let pending = this.write_pending.as_ref().unwrap().clone();
            let remaining = &pending[this.write_pending_off..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "transport write returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_pending_off += n;
                    if this.write_pending_off >= pending.len() {
                        this.write_pending = None;
                        this.write_pending_off = 0;
                    }
                    // partial write: loop continues until cleared or Pending
                }
            }
        }

        // Raw passthrough once all padding frames are sent.
        if this.write_frames_done >= PADDING_FRAMES {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // Build the padded frame: [u16 data_len][u8 pad_size][data][padding].
        let data_len = buf.len().min(MAX_PADDED_PAYLOAD);
        let pad_size = random_u8() as usize;
        let mut frame = BytesMut::with_capacity(3 + data_len + pad_size);
        frame.put_u16(data_len as u16);
        frame.put_u8(pad_size as u8);
        frame.put_slice(&buf[..data_len]);
        let pre_pad_len = frame.len();
        frame.resize(pre_pad_len + pad_size, 0);
        gen_random_bytes(&mut frame[pre_pad_len..]);

        this.write_pending = Some(frame.freeze());
        this.write_pending_off = 0;
        this.write_frames_done += 1;

        // Try to flush immediately (common case: window is open).
        let pending = this.write_pending.as_ref().unwrap().clone();
        match Pin::new(&mut this.inner).poll_write(cx, &pending) {
            Poll::Ready(Ok(n)) if n > 0 => {
                this.write_pending_off = n;
                if n >= pending.len() {
                    this.write_pending = None;
                    this.write_pending_off = 0;
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            _ => {} // Pending or Ok(0): leave write_pending for next call
        }

        Poll::Ready(Ok(data_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Drain any buffered padded frame.
        while this.write_pending.is_some() {
            let pending = this.write_pending.as_ref().unwrap().clone();
            let remaining = &pending[this.write_pending_off..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "transport write returned zero during flush",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_pending_off += n;
                    if this.write_pending_off >= pending.len() {
                        this.write_pending = None;
                        this.write_pending_off = 0;
                    }
                }
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drain any buffered padded frame before shutting down; otherwise bytes
        // still in write_pending would be silently dropped.
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct CapWriter {
        cap: usize,
    }

    impl tokio::io::AsyncRead for CapWriter {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for CapWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len().min(self.cap)))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// RED → GREEN regression for the partial-write stall.
    ///
    /// payload = 100 bytes → frame = 3 + 100 + pad ≥ 103 bytes > cap = 50,
    /// so the immediate-flush attempt always leaves write_pending non-empty.
    /// The second write_all enters Phase 1 and must drain those bytes.
    ///
    /// BUG (before fix): Phase 1 did `Ready(Ok(50))` with bytes remaining →
    ///   returned `Poll::Pending` without registering a waker → task parked
    ///   forever → timeout fires.
    /// FIX (after fix): Phase 1 uses a while-loop → keeps writing until
    ///   write_pending is cleared → no stall.
    #[tokio::test(start_paused = true)]
    async fn test_poll_write_partial_write_no_stall() {
        use tokio::io::AsyncWriteExt;

        let mut transport = NaivePaddedTransport::new(CapWriter { cap: 50 });
        let payload = vec![0xABu8; 100];

        // Frame 1: accepted by poll_write (returns Ready(Ok(100))).
        // Leaves write_pending with ≥53 unflushed bytes.
        transport.write_all(&payload).await.unwrap();

        // Frame 2: Phase 1 must drain the leftover bytes from frame 1.
        // Without fix: returns Pending with no waker → timeout fires.
        // With fix: while-loop drains → proceeds normally.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.write_all(&payload),
        )
        .await;

        assert!(
            result.is_ok(),
            "poll_write stalled: Phase 1 returned Pending without waker on partial write"
        );
    }

    /// Boundary: cap=1 forces the while-loop to iterate byte-by-byte through the
    /// entire frame, exercising the "exactly 1 byte remaining" path on every frame.
    #[tokio::test(start_paused = true)]
    async fn test_poll_write_partial_write_byte_by_byte() {
        use tokio::io::AsyncWriteExt;

        let mut transport = NaivePaddedTransport::new(CapWriter { cap: 1 });
        let payload = vec![0xCDu8; 5];

        for _ in 0..8 {
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                transport.write_all(&payload),
            )
            .await;
            assert!(result.is_ok(), "stalled on byte-by-byte drain");
        }
    }

    #[test]
    fn padding_header_length() {
        for _ in 0..100 {
            let h = generate_padding_header();
            assert!(h.len() >= 30 && h.len() <= 61, "bad length: {}", h.len());
        }
    }

    #[test]
    fn padding_header_chars() {
        const VALID_LEAD: &str = "!#$()+<>?@[]^`{}";
        for _ in 0..20 {
            let h = generate_padding_header();
            for (i, c) in h.chars().enumerate() {
                if i < 16 {
                    assert!(
                        VALID_LEAD.contains(c),
                        "unexpected char '{c}' at position {i}"
                    );
                } else {
                    assert_eq!(c, '~', "expected '~' at position {i}");
                }
            }
        }
    }

    #[test]
    fn random_u8_varies() {
        let vals: Vec<u8> = (0..20).map(|_| random_u8()).collect();
        // Not all the same (astronomically unlikely to fail)
        let all_same = vals.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "PRNG appears stuck");
    }

    /// Regression for the `poll_shutdown` data-loss bug: when the inner transport
    /// is slow (4-byte capacity), `write_all` leaves frame bytes in `write_pending`.
    /// Before the fix, `shutdown()` skipped flushing them and the receiver lost data.
    #[tokio::test]
    async fn test_poll_shutdown_flushes_write_pending() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 4-byte capacity forces the padded frame (≥8 bytes) into write_pending.
        let (a, b) = tokio::io::duplex(4);
        let mut enc = NaivePaddedTransport::new(a);

        // Drain concurrently so writes don't deadlock.
        let reader = tokio::spawn(async move {
            let mut total = 0usize;
            let mut buf = [0u8; 512];
            let mut b = b;
            loop {
                let n = b.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
            }
            total
        });

        enc.write_all(b"hello").await.unwrap();
        enc.shutdown().await.unwrap(); // must flush leftover frame bytes

        let on_wire = reader.await.unwrap();
        // minimum frame = 3 B header + 5 B data + 0 B padding = 8 bytes
        assert!(
            on_wire >= 8,
            "shutdown lost bytes: got {on_wire} on wire, expected ≥8"
        );
    }

    // ── Encode / decode roundtrip tests ──────────────────────────────────────────
    //
    // These tests connect two `NaivePaddedTransport` instances back-to-back over
    // a `tokio::io::duplex` pipe.  One side encodes (writes padded frames) and the
    // other decodes (strips framing and returns original bytes).

    /// Single-frame encode→decode: the simplest possible roundtrip.
    #[tokio::test]
    async fn test_roundtrip_single_frame() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (a, b) = tokio::io::duplex(1024 * 1024);
        let mut enc = NaivePaddedTransport::new(a);
        let mut dec = NaivePaddedTransport::new(b);

        let original: &[u8] = b"hello naive proxy roundtrip";
        enc.write_all(original).await.unwrap();
        enc.shutdown().await.unwrap();

        let mut decoded = Vec::new();
        dec.read_to_end(&mut decoded).await.unwrap();

        assert_eq!(decoded, original);
    }

    /// Eight padded frames (indices 0-7) plus one raw frame (index 8) must all
    /// decode to the original bytes.
    ///
    /// Both encoder (write_frames_done) and decoder (read_frames_done)
    /// independently count to 8 and then switch to raw passthrough — they stay
    /// in sync because the framed bytes on the wire change at the same boundary.
    #[tokio::test]
    async fn test_roundtrip_nine_frames() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (a, b) = tokio::io::duplex(4 * 1024 * 1024);
        let mut enc = NaivePaddedTransport::new(a);
        let mut dec = NaivePaddedTransport::new(b);

        const CHUNK: usize = 128;
        let mut expected = Vec::new();

        for i in 0u8..9 {
            let chunk = vec![i; CHUNK];
            expected.extend_from_slice(&chunk);
            enc.write_all(&chunk).await.unwrap();
        }
        enc.shutdown().await.unwrap();

        let mut decoded = Vec::new();
        dec.read_to_end(&mut decoded).await.unwrap();

        assert_eq!(
            decoded, expected,
            "all 9 frames (8 padded + 1 raw) must decode correctly"
        );
    }

    /// A→B and B→A are encoded / decoded independently.
    /// Each side maintains its own frame counters so the two directions
    /// never interfere with each other.
    #[tokio::test]
    async fn test_roundtrip_bidirectional() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (a, b) = tokio::io::duplex(4 * 1024 * 1024);
        let mut ta = NaivePaddedTransport::new(a);
        let mut tb = NaivePaddedTransport::new(b);

        let a_to_b: &[u8] = b"transport A sends this";
        let b_to_a: &[u8] = b"transport B sends this";

        // A→B
        ta.write_all(a_to_b).await.unwrap();
        let mut buf = vec![0u8; a_to_b.len()];
        tb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, a_to_b, "A→B data mismatch");

        // B→A
        tb.write_all(b_to_a).await.unwrap();
        let mut buf = vec![0u8; b_to_a.len()];
        ta.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b_to_a, "B→A data mismatch");
    }

    /// Data arriving one byte at a time still decodes correctly.
    ///
    /// Exercises the partial-header accumulation path (read_hdr_pos advances
    /// 0→1→2→3 across separate poll_read calls) and the partial-data path
    /// (read_data_rem decrements one byte at a time).
    #[tokio::test]
    async fn test_decode_byte_by_byte_arrival() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let original: &[u8] = b"byte-by-byte decoding";
        let pad_size: u8 = 4;

        // Build one raw padded frame manually: [u16 BE data_len][u8 pad_size][data][pad]
        let mut frame = Vec::new();
        frame.extend_from_slice(&(original.len() as u16).to_be_bytes());
        frame.push(pad_size);
        frame.extend_from_slice(original);
        frame.extend(std::iter::repeat_n(0xAA, pad_size as usize));

        // Feed the encoded frame into the decoder one byte at a time via a spawn.
        let (tx, rx) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut w = tx;
            for byte in &frame {
                w.write_all(&[*byte]).await.unwrap();
            }
            w.shutdown().await.unwrap();
        });

        let mut dec = NaivePaddedTransport::new(rx);
        let mut decoded = Vec::new();
        dec.read_to_end(&mut decoded).await.unwrap();

        assert_eq!(decoded, original);
    }

    /// read_data_rem path where caller's buffer is larger than one frame:
    /// data is delivered without reading past the frame boundary into the
    /// next header.
    #[tokio::test]
    async fn test_roundtrip_small_frame_large_read_buf() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (a, b) = tokio::io::duplex(1024 * 1024);
        let mut enc = NaivePaddedTransport::new(a);
        let mut dec = NaivePaddedTransport::new(b);

        // Two small frames written sequentially; read with a buffer bigger than both.
        let frame1: &[u8] = b"first";
        let frame2: &[u8] = b"second";

        enc.write_all(frame1).await.unwrap();
        enc.write_all(frame2).await.unwrap();
        enc.shutdown().await.unwrap();

        // Use a 4 KB buffer — much larger than either frame.
        let mut buf = vec![0u8; 4096];
        let mut decoded = Vec::new();
        loop {
            let n = dec.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            decoded.extend_from_slice(&buf[..n]);
        }

        let mut expected = frame1.to_vec();
        expected.extend_from_slice(frame2);
        assert_eq!(decoded, expected);
    }

    // ── Phase 1 scratch-buffer regression tests ───────────────────────────────

    /// RED → GREEN: Phase 1 must deliver the entire frame in a single poll_read
    /// when the caller's buffer is large enough.
    ///
    /// BUG (scratch buffer): poll_read limited each read to
    ///   `min(read_data_rem, 4096)` bytes.  For a 32 KB frame with a 64 KB
    ///   caller buffer, only 4096 bytes were returned per call.
    ///
    /// FIX (buf.take): reads up to `read_data_rem` bytes directly into the
    ///   caller's buffer — all 32 KB in one call.
    ///
    /// Assertion: a single `read` on a pre-filled 32 KB frame returns > 4096 bytes.
    #[tokio::test]
    async fn red_phase1_large_frame_not_capped_at_4096() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const DATA_SIZE: usize = 32 * 1024; // 32 KB > 4096

        // Build one raw padded frame manually: [u16 BE data_len][u8 pad=0][data]
        let mut frame = Vec::with_capacity(3 + DATA_SIZE);
        frame.extend_from_slice(&(DATA_SIZE as u16).to_be_bytes());
        frame.push(0u8);
        frame.extend(std::iter::repeat_n(0xABu8, DATA_SIZE));

        // 1 MB pipe ensures all frame bytes are available before first read.
        let (tx, rx) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let mut w = tx;
            w.write_all(&frame).await.unwrap();
            w.shutdown().await.unwrap();
        });

        let mut dec = NaivePaddedTransport::new(rx);

        // Buffer is LARGER than the frame so poll_read hits the "limit" branch.
        let mut buf = vec![0u8; DATA_SIZE * 2];
        let n = dec.read(&mut buf).await.unwrap();

        // BUG: old code returns exactly 4096 bytes; fix returns the full 32 KB.
        assert!(
            n > 4096,
            "poll_read must return more than 4096 bytes from a 32 KB frame \
             in one call (old scratch-buffer bug returned exactly 4096); got {n}"
        );
    }

    /// RED → GREEN: total inner poll_read calls to consume one 32 KB frame
    /// must be far fewer with the fix than with the scratch-buffer bug.
    ///
    /// BUG: scratch buffer caps each Phase 1 read at 4 096 bytes.
    ///   To consume 32 768 bytes of frame data: ⌈32768/4096⌉ = 8 data reads.
    ///   Plus 1 header read + 1 initial Pending = 10 inner reads total.
    ///
    /// FIX (buf.take): one Phase 1 read delivers the entire 32 KB frame.
    ///   1 header read + 1 data read + 1 initial Pending = 3 inner reads total.
    ///
    /// Threshold: ≤ 4 inner reads separates fix (3) from bug (10).
    #[tokio::test]
    async fn red_phase1_large_frame_inner_read_count() {
        use std::pin::Pin;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll};
        use tokio::io::{AsyncReadExt, ReadBuf};

        struct CountingReader<R> {
            inner: R,
            calls: std::sync::Arc<AtomicUsize>,
        }
        impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountingReader<R> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }

        const DATA_SIZE: usize = 32 * 1024;

        let mut frame = Vec::with_capacity(3 + DATA_SIZE);
        frame.extend_from_slice(&(DATA_SIZE as u16).to_be_bytes());
        frame.push(0u8);
        frame.extend(std::iter::repeat_n(0xCDu8, DATA_SIZE));

        let (tx, rx) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let mut w = tx;
            tokio::io::AsyncWriteExt::write_all(&mut w, &frame)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::shutdown(&mut w).await.unwrap();
        });

        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let counting = CountingReader {
            inner: rx,
            calls: calls.clone(),
        };
        let mut dec = NaivePaddedTransport::new(counting);
        let mut buf = vec![0u8; DATA_SIZE * 2];

        // Consume the full frame, accumulating inner-read counts across all outer reads.
        let mut total_consumed = 0usize;
        loop {
            let n = dec.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total_consumed += n;
            if total_consumed >= DATA_SIZE {
                break;
            }
        }
        let total_inner_reads = calls.load(Ordering::SeqCst);

        assert_eq!(
            total_consumed, DATA_SIZE,
            "must consume exactly {DATA_SIZE} bytes"
        );

        // Fix: 1 Pending + 1 header + 1 data = 3 inner reads.
        // Bug: 1 Pending + 1 header + 8 data = 10 inner reads.
        // Threshold 5 clearly separates fix (≤4) from bug (≥10).
        assert!(
            total_inner_reads <= 5,
            "total inner reads to consume {DATA_SIZE} bytes should be ≤5 with fix \
             (old scratch-buffer bug needed ≥10); got {total_inner_reads}"
        );
    }
}
