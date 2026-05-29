//! Bridge between a pingora `Session` and a `tokio::io::duplex` pair.
//!
//! Pingora's `ProxyHttp::request_filter` is invoked with `&mut Session`, so
//! we cannot move the session into a spawned task with the `'static` bound
//! `tokio::spawn` requires.  Instead we run the bridge as a non-spawned
//! future driven by the same async context as `request_filter`, using
//! `tokio::select!` to multiplex it against `process_tunnel`.
//!
//! The 200 response header MUST already have been sent on `session` before
//! this bridge is invoked — the bridge only handles body framing.
//!
//! Reference: `private-land/naive-rs` `src/h2/server.rs` body relay pattern.

use bytes::Bytes;
use pingora::proxy::Session;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Duplex buffer: at least 64 KiB to hold one full naive-padded frame
/// without stalling the bridge.
pub const BRIDGE_BUF: usize = 64 * 1024;

/// Drive a body-relay bridge between a pingora `Session` and the
/// `server_half` end of a duplex pair.  The relay (running concurrently in
/// `process_tunnel`) reads from / writes to the matching `client_io` half.
///
/// Direction state tracking:
///   - `up_eof`  : client signalled FIN; stop polling `read_body_or_idle`.
///   - `down_eof`: relay closed; we sent the response-side EOS frame.
///
/// Returns when both directions are EOF or the session errors.  Dropping
/// this future before completion is safe: the duplex halves cancel cleanly
/// and `Session` continues to be owned by the caller.
pub async fn run_session_bridge(session: &mut Session, io: DuplexStream) {
    let (mut io_read, mut io_write) = tokio::io::split(io);
    let mut up_eof = false;
    let mut down_eof = false;
    let mut read_buf = vec![0u8; BRIDGE_BUF];

    while !(up_eof && down_eof) {
        tokio::select! {
            biased;
            // ── Upload: client → upstream (via duplex.write).
            body = session.downstream_session.read_body_or_idle(false), if !up_eof => {
                match body {
                    Ok(Some(bytes)) => {
                        if io_write.write_all(&bytes).await.is_err() {
                            up_eof = true;
                        }
                    }
                    Ok(None) => {
                        let _ = io_write.shutdown().await;
                        up_eof = true;
                    }
                    Err(_) => {
                        let _ = io_write.shutdown().await;
                        up_eof = true;
                    }
                }
            }
            // ── Download: upstream (via duplex.read) → client.
            n = io_read.read(&mut read_buf), if !down_eof => {
                match n {
                    Ok(0) => {
                        let _ = session.write_response_body(None, true).await;
                        down_eof = true;
                    }
                    Ok(n) => {
                        let chunk = Bytes::copy_from_slice(&read_buf[..n]);
                        if session
                            .write_response_body(Some(chunk), false)
                            .await
                            .is_err()
                        {
                            down_eof = true;
                        }
                    }
                    Err(_) => {
                        let _ = session.write_response_body(None, true).await;
                        down_eof = true;
                    }
                }
            }
        }
    }
}
