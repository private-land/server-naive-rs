//! HTTP/3 transport layer for NaiveProxy CONNECT tunneling over QUIC.
//!
//! Wraps an `h3::server::RequestStream` as `AsyncRead + AsyncWrite` using a
//! `tokio::io::duplex` pair bridged by a background task.  The bridge handles
//! the impedance mismatch between h3's async API and the poll-based trait.
//!
//! Data flow (bridge task):
//!   H3 recv_data  →  io write half  →  relay reads from H3Transport
//!   relay writes  →  io read half   →  channel  →  H3 send_data

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
    let (tx, mut rx) = mpsc::channel::<Bytes>(16);
    let (mut io_read, io_write) = tokio::io::split(io);

    // Spawn a task that reads from the relay (io read half) and queues bytes
    // for h3 send_data.  Runs independently so it doesn't block h3 receive.
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; BRIDGE_BUF];
        loop {
            match io_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Main loop: select between incoming H3 data and queued outgoing data.
    //
    // Half-close handling: when the client sends FIN (recv_data returns None),
    // we drop io_write (signals EOF to the relay's read side) but keep the loop
    // alive to forward any pending server→client data through the rx channel.
    // The loop exits only when the relay finishes (rx channel closes) or on error.
    let mut io_write_opt = Some(io_write);
    loop {
        if let Some(ref mut io_write) = io_write_opt {
            tokio::select! {
                // H3 client → relay: forward DATA frames to the duplex io_write half
                result = h3.recv_data() => {
                    match result {
                        Ok(Some(mut data)) => {
                            let bytes = data.copy_to_bytes(data.remaining());
                            if io_write.write_all(&bytes).await.is_err() {
                                break;
                            }
                        }
                        // Client sent FIN: signal EOF to relay, keep rx drain alive.
                        Ok(None) | Err(_) => {
                            io_write_opt = None; // drop io_write → EOF to relay read side
                        }
                    }
                }
                // Relay → H3 client: forward queued bytes as DATA frames
                data = rx.recv() => {
                    match data {
                        Some(bytes) => {
                            if h3.send_data(bytes).await.is_err() {
                                break;
                            }
                        }
                        None => break, // relay finished sending
                    }
                }
            }
        } else {
            // Client FIN received; drain remaining relay→client data.
            match rx.recv().await {
                Some(bytes) => {
                    if h3.send_data(bytes).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    read_task.abort();

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
