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
                if buf.remaining() >= this.read_data_rem {
                    // Caller's buffer is larger — must limit to avoid consuming
                    // the next frame's header/padding bytes.
                    let chunk = this.read_data_rem.min(4096);
                    let mut scratch = [0u8; 4096];
                    let mut sbuf = ReadBuf::new(&mut scratch[..chunk]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut sbuf))?;
                    let n = sbuf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    buf.put_slice(&scratch[..n]);
                    this.read_data_rem -= n;
                } else {
                    // Caller's buffer is smaller — safe to read directly (won't
                    // overshoot the frame boundary).
                    let before = buf.filled().len();
                    ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
                    let n = buf.filled().len() - before;
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.read_data_rem -= n;
                }
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
}
