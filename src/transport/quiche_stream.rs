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
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_quiche::http3::driver::{InboundFrame, OutboundFrame, OutboundFrameSender};

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
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // 1. Drain any leftover bytes from the previous frame first.
            if let Some(ref mut b) = self.buf {
                if !b.is_empty() {
                    let len = std::cmp::min(b.len(), buf.remaining());
                    buf.put_slice(&b[..len]);
                    *b = b.slice(len..);
                    if b.is_empty() {
                        self.buf = None;
                    }
                    return Poll::Ready(Ok(()));
                } else {
                    self.buf = None;
                }
            }

            // 2. If the peer's FIN has already arrived and the buffer is
            //    drained, surface EOF (poll_read returns Ok with no bytes
            //    written — tokio's AsyncRead EOF contract).
            if self.fin {
                return Poll::Ready(Ok(()));
            }

            // 3. Pull the next frame from the channel.  Datagrams are
            //    ignored (NaiveProxy doesn't use H3 datagrams).  Sender drop
            //    is treated as a clean EOF — the driver shut down.
            match self.recv.poll_recv(cx) {
                Poll::Ready(Some(InboundFrame::Body(data, fin))) => {
                    if fin {
                        self.fin = true;
                    }
                    if !data.is_empty() {
                        self.buf = Some(bytes::Bytes::copy_from_slice(&data));
                    }
                    // Loop to either serve from buf or hit the fin EOF check.
                }
                Poll::Ready(Some(InboundFrame::Datagram(_))) => continue,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// AsyncWrite half over an H3 stream's outbound `OutboundFrameSender`
/// (`PollSender<OutboundFrame>`).
///
/// Each `poll_write` reserves channel capacity (which is what tokio-quiche
/// uses to translate downstream QUIC flow-control back to the caller — when
/// the QUIC send window is exhausted, the channel doesn't drain and our
/// reservation Pends), then enqueues `OutboundFrame::Body(buf, false)`.
/// `poll_shutdown` enqueues `OutboundFrame::Body(empty, true)` so the peer
/// observes a clean FIN on the response side.
pub struct H3StreamWriter {
    send: OutboundFrameSender,
}

impl H3StreamWriter {
    #[allow(dead_code)] // wired into handler in A10
    pub fn new(send: OutboundFrameSender) -> Self {
        Self { send }
    }
}

impl AsyncWrite for H3StreamWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // A9 stub — pretend the write succeeded but never enqueue an
        // `OutboundFrame::Body` on `self.send`.  The test's `mpsc_rx.recv()`
        // therefore returns nothing and the assertion fails.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // A9 stub — same shape as poll_write.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::PollSender;

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

    /// A9 — write_all + shutdown must enqueue
    ///   Body("hi", fin=false)
    ///   Body(empty, fin=true)
    /// on the outbound frame channel, in order.
    #[tokio::test]
    async fn h3_stream_writer_emits_outbound_then_fin() {
        let (mpsc_tx, mut mpsc_rx) = mpsc::channel::<OutboundFrame>(8);
        let send: OutboundFrameSender = PollSender::new(mpsc_tx);
        let mut writer = H3StreamWriter::new(send);

        writer.write_all(b"hi").await.unwrap();
        writer.shutdown().await.unwrap();
        // Drop the writer so the PollSender closes its mpsc channel — without
        // this `mpsc_rx.recv()` would block forever waiting on a sender that
        // the test still holds via `writer`.
        drop(writer);

        let body = mpsc_rx.recv().await.expect("first frame must be the body");
        match body {
            OutboundFrame::Body(buf, fin) => {
                assert_eq!(&buf[..], b"hi", "first body must be the written bytes");
                assert!(!fin, "first body must not signal fin");
            }
            other => panic!("first frame should be Body, got {other:?}"),
        }

        let fin_frame = mpsc_rx.recv().await.expect("second frame must be the fin");
        match fin_frame {
            OutboundFrame::Body(buf, fin) => {
                assert!(buf.is_empty(), "fin frame body must be empty");
                assert!(fin, "fin frame must signal fin=true");
            }
            other => panic!("second frame should be Body(_,true), got {other:?}"),
        }
    }
}
