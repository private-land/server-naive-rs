//! HTTP/2 transport layer for NaiveProxy CONNECT tunneling
//!
//! Implements AsyncRead + AsyncWrite over h2 RecvStream + SendStream.
//! Unlike gRPC transport, there is no message framing — raw bytes are sent directly.

use bytes::Bytes;
use h2::{Reason, RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum single send frame size (64KB, matching H2 max frame default)
const MAX_FRAME_SIZE: usize = 64 * 1024;

/// H2Transport wraps an HTTP/2 stream as an AsyncRead + AsyncWrite stream.
///
/// Used for NaiveProxy CONNECT tunneling: raw bytes are relayed without
/// any additional framing (no gRPC length-prefix, no WebSocket frames).
pub struct H2Transport {
    recv: RecvStream,
    send: SendStream<Bytes>,
    /// Leftover bytes from the current received chunk not yet consumed
    read_buf: Bytes,
    /// Flow control bytes pending release to the remote peer
    pending_release: usize,
    closed: bool,
}

impl H2Transport {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            read_buf: Bytes::new(),
            pending_release: 0,
            closed: false,
        }
    }
}

fn is_normal_close(e: &h2::Error) -> bool {
    if let Some(reason) = e.reason() {
        matches!(reason, Reason::NO_ERROR | Reason::CANCEL)
    } else {
        false
    }
}

impl AsyncRead for H2Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        // Drain leftover buffer from previous read first
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);

            // Release flow control for bytes handed to the caller
            let to_release = self.pending_release.min(n);
            if to_release > 0 {
                let _ = self.recv.flow_control().release_capacity(to_release);
                self.pending_release -= to_release;
            }

            self.read_buf = self.read_buf.slice(n..);
            return Poll::Ready(Ok(()));
        }

        // Poll for the next H2 data chunk
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_len = chunk.len();
                let n = chunk_len.min(buf.remaining());
                buf.put_slice(&chunk[..n]);

                // Track bytes for flow control release
                self.pending_release += chunk_len;
                let to_release = self.pending_release.min(n);
                if to_release > 0 {
                    let _ = self.recv.flow_control().release_capacity(to_release);
                    self.pending_release -= to_release;
                }

                if n < chunk_len {
                    // Save remainder for the next poll_read call
                    self.read_buf = chunk.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                self.closed = true;
                if is_normal_close(&e) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::Error::other(format!("H2 recv error: {}", e))))
                }
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 transport closed",
            )));
        }

        // Check available flow-control window
        let mut cap = self.send.capacity();
        if cap == 0 {
            // Request capacity and wait
            self.send.reserve_capacity(buf.len().min(MAX_FRAME_SIZE));
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(n))) if n > 0 => {
                    cap = n;
                }
                Poll::Ready(Some(Ok(_))) => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("H2 capacity error: {}", e))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "H2 stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Send up to `cap` bytes (no extra framing for Naive)
        let n = buf.len().min(cap).min(MAX_FRAME_SIZE);
        let data = Bytes::copy_from_slice(&buf[..n]);
        match self.send.send_data(data, false) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(io::Error::other(format!("H2 send error: {}", e)))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // H2 sends data immediately in send_data; nothing to flush
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        // Send empty data frame with end_of_stream=true to close the send half
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 64 * 1024);
    }

    #[tokio::test]
    async fn test_rst_no_error_reads_as_eof() {
        use tokio::io::{duplex, AsyncReadExt};

        let (client_io, server_io) = duplex(64 * 1024);
        let (stream_tx, stream_rx) =
            tokio::sync::oneshot::channel::<(h2::RecvStream, h2::server::SendResponse<Bytes>)>();

        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (req, respond) = conn.accept().await.unwrap().unwrap();
            stream_tx.send((req.into_body(), respond)).ok();
            while conn.accept().await.is_some() {} // drive I/O until closed
        });

        let (mut h2_client, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(conn);
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .unwrap();
        let (resp_fut, mut send_stream) = h2_client.send_request(req, false).unwrap();

        let (recv, mut respond) = stream_rx.await.unwrap();
        let h2_send = respond
            .send_response(
                http::Response::builder().status(200).body(()).unwrap(),
                false,
            )
            .unwrap();
        let _ = resp_fut.await.unwrap(); // client sees 200

        send_stream.send_reset(h2::Reason::NO_ERROR);

        let mut transport = H2Transport::new(recv, h2_send);
        let mut buf = vec![0u8; 1024];
        let n = transport.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "RST_STREAM NO_ERROR must read as clean EOF");
    }

    #[tokio::test]
    async fn test_rst_internal_error_reads_as_io_error() {
        use tokio::io::{duplex, AsyncReadExt};

        let (client_io, server_io) = duplex(64 * 1024);
        let (stream_tx, stream_rx) =
            tokio::sync::oneshot::channel::<(h2::RecvStream, h2::server::SendResponse<Bytes>)>();

        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (req, respond) = conn.accept().await.unwrap().unwrap();
            stream_tx.send((req.into_body(), respond)).ok();
            while conn.accept().await.is_some() {}
        });

        let (mut h2_client, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(conn);
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .unwrap();
        let (resp_fut, mut send_stream) = h2_client.send_request(req, false).unwrap();

        let (recv, mut respond) = stream_rx.await.unwrap();
        let h2_send = respond
            .send_response(
                http::Response::builder().status(200).body(()).unwrap(),
                false,
            )
            .unwrap();
        let _ = resp_fut.await.unwrap();

        send_stream.send_reset(h2::Reason::INTERNAL_ERROR);

        let mut transport = H2Transport::new(recv, h2_send);
        let mut buf = vec![0u8; 1024];
        let result = transport.read(&mut buf).await;
        assert!(
            result.is_err(),
            "RST_STREAM INTERNAL_ERROR must propagate as io::Error"
        );
    }
}
