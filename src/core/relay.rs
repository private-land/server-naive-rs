//! Bidirectional relay with idle timeout, half-close timeout, and traffic statistics

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
    HalfCloseTimeout,
    IdleTimeout,
    Error,
}

impl std::fmt::Display for RelayTermination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => f.write_str("completed"),
            Self::HalfCloseTimeout => f.write_str("half_close_timeout"),
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
    flush_ok: bool,
}

impl DirectionalBuffer {
    fn new(buf_size: usize) -> Self {
        Self {
            buf: vec![0u8; buf_size],
            pos: 0,
            cap: 0,
            amt: 0,
            read_done: false,
            shutdown_done: false,
            flush_ok: false,
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

    #[inline]
    fn has_flushed(&self) -> bool {
        self.flush_ok
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

        self.flush_ok = false;

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
                Poll::Ready(Ok(())) => {
                    self.flush_ok = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }

            if self.read_done {
                let _ = ready!(writer.as_mut().poll_shutdown(cx));
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

pub async fn copy_bidirectional_with_stats<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout_secs: u64,
    uplink_only_secs: u64,
    downlink_only_secs: u64,
    buffer_size: usize,
    stats: Option<(UserId, Arc<dyn StatsCollector>)>,
) -> io::Result<CopyResult>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a_to_b = DirectionalBuffer::new(buffer_size);
    let mut b_to_a = DirectionalBuffer::new(buffer_size);

    let idle_timeout = tokio::time::Duration::from_secs(idle_timeout_secs);
    let uplink_only_timeout = tokio::time::Duration::from_secs(uplink_only_secs);
    let downlink_only_timeout = tokio::time::Duration::from_secs(downlink_only_secs);

    let half_close_sleep = tokio::time::sleep(tokio::time::Duration::ZERO);
    tokio::pin!(half_close_sleep);
    let mut half_close_active = false;

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

        if a_to_b.has_read_eof() && !b_to_a.is_done() && !half_close_active {
            half_close_active = true;
            half_close_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + uplink_only_timeout);
        }
        if b_to_a.has_read_eof() && !a_to_b.is_done() && !half_close_active {
            half_close_active = true;
            half_close_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + downlink_only_timeout);
        }

        let a_progress = a_to_b.bytes_transferred() > a_bytes_before && a_to_b.has_flushed();
        let b_progress = b_to_a.bytes_transferred() > b_bytes_before && b_to_a.has_flushed();
        if a_progress || b_progress {
            idle_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + idle_timeout);
        }

        if a_to_b.is_done() && b_to_a.is_done() {
            termination = RelayTermination::Completed;
            return Poll::Ready(Ok(true));
        }

        if half_close_active && half_close_sleep.as_mut().poll(cx).is_ready() {
            termination = RelayTermination::HalfCloseTimeout;
            return Poll::Ready(Ok(false));
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

        let result = copy_bidirectional_with_stats(&mut client, &mut remote, 300, 2, 5, 1024, None)
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

    #[tokio::test(start_paused = true)]
    async fn test_uplink_only_timeout_on_client_eof() {
        let mut client = Cursor::new(b"hello".to_vec());
        let mut remote = NeverEofSink;

        let result =
            copy_bidirectional_with_stats(&mut client, &mut remote, 300, 1, 100, 1024, None)
                .await
                .unwrap();

        assert!(!result.completed);
        assert_eq!(result.termination, RelayTermination::HalfCloseTimeout);
    }

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_fires() {
        let mut client = NeverEofSink;
        let mut remote = NeverEofSink;

        let result =
            copy_bidirectional_with_stats(&mut client, &mut remote, 3, 100, 100, 1024, None)
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
}
