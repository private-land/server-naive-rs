//! `AsyncRead` / `AsyncWrite` adapters over tokio-quiche's per-stream
//! mpsc channels.
//!
//! Architecture is deliberately split into two independent types:
//!
//!   * `H3StreamReader` wraps the inbound `mpsc::Receiver<InboundFrame>`.
//!   * `H3StreamWriter` (A9) wraps the outbound `OutboundFrameSender`.
//!
//! This is simpler than the legacy `transport/h3.rs` bridge (which uses
//! `tokio::io::duplex` + two background tasks) because tokio-quiche's API
//! already gives us poll-friendly half-streams.  No background tasks, no
//! duplex buffer, fewer ownership headaches.
//!
//! Reference: `private-land/naive-rs` / `src/h3/stream.rs`.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;
use tokio_quiche::http3::driver::InboundFrame;

/// AsyncRead half over an H3 stream's inbound frame channel.
///
/// `recv` yields `InboundFrame::Body(buf, fin)` chunks until either the
/// remote peer sends FIN or the driver drops the sender.  Datagrams (if any)
/// are ignored — NaiveProxy does not use H3 datagrams.
pub struct H3StreamReader {
    recv: mpsc::Receiver<InboundFrame>,
    buf: Option<bytes::Bytes>,
    fin: bool,
}

impl H3StreamReader {
    #[allow(dead_code)] // wired into handler in A10
    pub fn new(recv: mpsc::Receiver<InboundFrame>) -> Self {
        Self {
            recv,
            buf: None,
            fin: false,
        }
    }
}

impl AsyncRead for H3StreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // A8 stub — always signal EOF before reading anything.  The test
        // expects 2 bytes ("hi") followed by EOF, so this fails on the first
        // assertion (n == 2).  The green commit replaces this with the real
        // chunked read.
        let _ = &mut self.buf;
        let _ = &mut self.fin;
        let _ = &mut self.recv;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;

    /// A8 — Feeding `Body(b"hi", false)` followed by `Body(empty, true)` to
    /// the reader must yield exactly the bytes "hi" then EOF (0 bytes).
    #[tokio::test]
    async fn h3_stream_reader_yields_inbound_bytes_then_eof() {
        let (tx, rx) = mpsc::channel(8);
        let mut reader = H3StreamReader::new(rx);

        tx.send(InboundFrame::Body(BytesMut::from(&b"hi"[..]), false))
            .await
            .unwrap();
        tx.send(InboundFrame::Body(BytesMut::new(), true))
            .await
            .unwrap();
        drop(tx);

        let mut buf = vec![0u8; 16];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 2, "first read should return the 2 body bytes");
        assert_eq!(&buf[..n], b"hi");

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "second read must signal EOF after fin");
    }
}
