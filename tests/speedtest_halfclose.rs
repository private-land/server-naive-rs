//! 复现 speedtest.net 上传/下载测试失败问题
//!
//! ## 问题场景
//!
//! speedtest.net 上传测试的 TCP 流程（经过 naive 隧道后，relay 视角）：
//!
//!   客户端 (a)                                  远端服务器 (b)
//!   ─────────────────────────────────────────────────────────
//!   1. 发送 HTTP POST 大体（上传数据）  →   服务器接收
//!   2. 半关闭（发 FIN）              →   服务器收到 EOF
//!   3. 等待 HTTP 200 响应  ←←←    服务器计算吞吐量（耗时 1~5s）
//!   4.                       ←─    服务器发送 HTTP 200（此时 relay 还活着吗？）
//!
//! ## 关键参数
//!
//! - `uplink_only_timeout`：客户端半关闭后等待远端响应的宽限期（旧默认 2s，修复后 30s）
//! - `downlink_only_timeout`：服务器关闭后等待数据排空的宽限期（旧默认 5s，修复后 30s）
//!
//! ## Bug 复现
//!
//! 当远端响应时间 > uplink_only_timeout 时，relay 提前杀掉连接，
//! 客户端收不到 HTTP 200 → speedtest.net 报告"无法完成测试"。
//!
//! ## 对照
//!
//! singbox naive 服务端（Go 实现）没有 uplink-only 超时机制，所以不受此问题影响。
//!
//! ## downlink_only_timeout 测试说明
//!
//! relay 内部有一个关键优化：当对 writer 的 `poll_write` 返回 `Pending` 时，
//! relay 会在同一个 poll_fn 内对 reader 做 "concurrent read"（前提是 buf 未满）。
//!
//! 利用这一特性可以复现 downlink 超时场景：
//!   1. relay buffer (8KB) > server data (4KB)：relay 一次读完所有数据
//!   2. relay 尝试写向慢速客户端（SlowWriter，每次写 2s）→ Pending
//!   3. concurrent read：relay buffer 未满 → 再读 server → EOF → has_read_eof = true
//!   4. half_close 计时器立刻启动（此时数据还没写到客户端）
//!   5. downlink_only_timeout = 1s < write_delay 2s → 计时器提前触发，数据截断（RED）
//!   6. downlink_only_timeout = 3s > write_delay 2s → 写完后触发，数据完整（GREEN）

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use server_naive_rs::core::{copy_bidirectional_with_stats, RelayTermination};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Duration;

// ── SlowWriter：模拟 QUIC 拥塞的慢速写入器 ───────────────────────────────────
//
// 每次 `poll_write` 都等待 `delay` 才真正写入内部 DuplexStream，
// 等效于 QUIC 发送窗口被占满时 `h3_send.send_data()` 阻塞的行为。

struct SlowWriter {
    inner: tokio::io::DuplexStream,
    delay: Duration,
    pending: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl SlowWriter {
    fn new(inner: tokio::io::DuplexStream, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            pending: None,
        }
    }
}

impl AsyncRead for SlowWriter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SlowWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 初次调用：创建延迟计时器
        if self.pending.is_none() {
            self.pending = Some(Box::pin(tokio::time::sleep(self.delay)));
        }
        // 等待延迟结束
        if self
            .pending
            .as_mut()
            .unwrap()
            .as_mut()
            .poll(cx)
            .is_pending()
        {
            return Poll::Pending;
        }
        // 延迟结束：清除计时器，实际写入
        self.pending = None;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── 辅助：运行下载场景，返回客户端收到的字节数 ────────────────────────────────
//
// 布局（relay 视角）：
//
//   slow_client ←→ relay ←→ server_proxy ←→ server_ext
//       ↑                                        ↑
//   client_reader                        server 在此写数据
//
// relay 的 b_to_a 方向（server → client）是慢速写，用于触发 downlink_only_timeout。
async fn simulate_speedtest_download(
    server_data_size: usize,
    write_delay: Duration,
    downlink_only_secs: u64,
) -> (usize, RelayTermination) {
    // slow_write/client_reader：relay 下载数据经由 slow_client 写入，client_reader 读出
    let (slow_write, mut client_reader) = tokio::io::duplex(256 * 1024);
    let mut slow_client = SlowWriter::new(slow_write, write_delay);

    // server_proxy/server_ext：relay 从 server_proxy 读服务器数据
    let (mut server_proxy, mut server_ext) = tokio::io::duplex(256 * 1024);

    // 服务器任务：立即发送数据并关闭
    let server_task = tokio::spawn(async move {
        server_ext
            .write_all(&vec![0x44u8; server_data_size])
            .await
            .unwrap();
        server_ext.shutdown().await.unwrap();
        eprintln!("[服务器] {}B 数据已发，已关闭", server_data_size);
    });

    // 客户端任务：读取所有数据（或等到连接被关闭）
    let client_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        // 观察窗口 = downlink_only_secs + 5s，确保能捕获 relay 关闭后的 EOF
        let _ = tokio::time::timeout(
            Duration::from_secs(downlink_only_secs + 5),
            client_reader.read_to_end(&mut buf),
        )
        .await;
        let n = buf.len();
        eprintln!("[客户端] 共收到 {n} 字节（期望 {server_data_size}）");
        n
    });

    // relay 任务：
    // - a = slow_client（写端慢，模拟 QUIC 拥塞）
    // - b = server_proxy（读服务器数据）
    // - relay buffer = 16KB > server_data(4KB)：
    //   确保一次读完所有数据，使 concurrent read 在 poll_write Pending 时检测到 EOF，
    //   half_close 计时器在写操作完成前就开始倒数。
    let relay_buf = server_data_size * 4; // 远大于数据量，保证一次读完
    let relay_task = tokio::spawn(async move {
        let r = copy_bidirectional_with_stats(
            &mut slow_client,
            &mut server_proxy,
            300,                // idle_timeout: 5分钟（不干扰测试）
            10,                 // uplink_only_timeout: 宽松（不干扰测试）
            downlink_only_secs, // ← 被测参数
            relay_buf,
            None,
        )
        .await;
        if let Ok(ref r) = r {
            eprintln!("[relay] termination={} b_to_a={}B", r.termination, r.b_to_a);
        }
        r
    });

    let (bytes_received, _, relay_result) = tokio::join!(client_task, server_task, relay_task);

    let termination = relay_result.unwrap().unwrap().termination;
    (bytes_received.unwrap(), termination)
}

// ── 辅助：运行上传场景，返回客户端是否收到响应 ────────────────────────────────

async fn simulate_speedtest_upload(
    upload_size: usize,
    server_response_delay: Duration,
    uplink_only_secs: u64,
) -> bool {
    let (mut client_ext, mut client_proxy) = tokio::io::duplex(128 * 1024);
    let (mut server_proxy, mut server_ext) = tokio::io::duplex(128 * 1024);

    // 客户端：上传 → 半关闭 → 等待响应
    let upload_task = tokio::spawn(async move {
        client_ext
            .write_all(&vec![0x42u8; upload_size])
            .await
            .unwrap();
        client_ext.shutdown().await.unwrap();

        let mut buf = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(uplink_only_secs + 5),
            client_ext.read_to_end(&mut buf),
        )
        .await;
        match result {
            Ok(Ok(n)) if n > 0 => {
                eprintln!("[客户端] 收到响应 {n} 字节 ✓");
                true
            }
            Ok(Ok(_)) => {
                eprintln!("[客户端] 连接关闭但没有收到响应数据 ✗");
                false
            }
            Ok(Err(e)) => {
                eprintln!("[客户端] 读取响应出错: {e} ✗");
                false
            }
            Err(_) => {
                eprintln!("[客户端] 等待响应超时 ✗");
                false
            }
        }
    });

    // 服务器：接收上传 → 延迟 → 发响应
    let server_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        server_ext.read_to_end(&mut buf).await.unwrap();
        eprintln!("[服务器] 接收完毕 {} 字节，开始处理...", buf.len());
        tokio::time::sleep(server_response_delay).await;
        let _ = server_ext
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await;
        let _ = server_ext.shutdown().await;
        eprintln!("[服务器] 响应已发送（或被 relay 提前关闭）");
    });

    // relay
    let relay_task = tokio::spawn(async move {
        let r = copy_bidirectional_with_stats(
            &mut client_proxy,
            &mut server_proxy,
            300,
            uplink_only_secs,
            60,
            32 * 1024,
            None,
        )
        .await;
        if let Ok(ref r) = r {
            eprintln!(
                "[relay] termination={} up={}B down={}B",
                r.termination, r.a_to_b, r.b_to_a
            );
            if r.termination == RelayTermination::HalfCloseTimeout {
                eprintln!("[诊断] HalfCloseTimeout 触发！服务器响应被丢弃。");
            }
        }
        r
    });

    let (got_response, _, _) = tokio::join!(upload_task, server_task, relay_task);
    got_response.unwrap()
}

// ── 上传场景测试 ──────────────────────────────────────────────────────────────

/// RED: 复现生产 bug
///
/// `uplink_only_timeout = 2s`（旧默认值），服务器延迟 3s 响应
/// → relay 在响应到达前杀掉连接 → 客户端拿不到 HTTP 200
/// → speedtest.net 报告"无法完成测试"
#[tokio::test(start_paused = false)]
async fn red_uplink_only_2s_server_responds_in_3s_fails() {
    eprintln!("\n=== RED：复现 speedtest 上传失败（uplink_only=2s, 服务器延迟 3s）===");

    let got_response = simulate_speedtest_upload(
        1024,
        Duration::from_millis(3000), // 服务器 3s 后响应
        2,                           // uplink_only_timeout = 2s（旧默认值）
    )
    .await;

    assert!(
        !got_response,
        "期望客户端收不到响应（uplink_only=2s < server_delay=3s）\n\
         断言失败说明 bug 已修复或测试环境异常"
    );
    eprintln!("✓ 确认 bug：客户端确实收不到响应\n");
}

/// GREEN: 修复验证
///
/// `uplink_only_timeout = 30s`（新默认值），服务器延迟 3s 响应
/// → relay 有足够时间等待 → 客户端正常收到 HTTP 200
#[tokio::test(start_paused = false)]
async fn green_uplink_only_30s_server_responds_in_3s_succeeds() {
    eprintln!("\n=== GREEN：修复验证（uplink_only=30s, 服务器延迟 3s）===");

    let got_response = simulate_speedtest_upload(
        1024,
        Duration::from_millis(3000),
        30, // uplink_only_timeout = 30s（新默认值）
    )
    .await;

    assert!(
        got_response,
        "期望客户端收到响应（uplink_only=30s > server_delay=3s），但没有收到"
    );
    eprintln!("✓ 修复有效：客户端成功收到 HTTP 200 响应\n");
}

/// BOUNDARY: 最小安全裕量验证
///
/// `uplink_only_timeout = 5s` vs 服务器延迟 3s → 2s 裕量，勉强可行。
/// 说明旧默认的 2s 没有任何裕量，30s 是安全的生产默认值。
#[tokio::test(start_paused = false)]
async fn green_uplink_only_5s_has_2s_margin_over_3s_server_delay() {
    eprintln!("\n=== BOUNDARY：最小安全裕量测试（uplink_only=5s, 服务器延迟 3s）===");

    let got_response = simulate_speedtest_upload(1024, Duration::from_millis(3000), 5).await;

    assert!(
        got_response,
        "5s 超时应足以等待 3s 服务器延迟，但没有收到响应"
    );
    eprintln!("✓ 5s 在裕量充足时可行，但 30s 才是生产安全默认值\n");
}

// ── 下载场景测试 ──────────────────────────────────────────────────────────────

/// RED: 复现下载数据截断
///
/// 服务器发送 4KB 后关闭。relay 写向客户端每次延迟 2s（模拟 QUIC 拥塞写阻塞）。
/// relay buffer = 16KB > 4KB：一次读完所有数据 → concurrent read 立刻检测到 EOF
/// → half_close 计时器开始，此时数据尚未写到客户端。
/// `downlink_only_timeout = 1s < write_delay 2s` → 计时器提前触发，数据截断。
#[tokio::test(start_paused = false)]
async fn red_downlink_only_1s_slow_write_truncates_data() {
    eprintln!("\n=== RED：下载截断（downlink_only=1s < write_delay=2s）===");

    let (received, termination) = simulate_speedtest_download(
        4 * 1024,                    // server 发送 4KB
        Duration::from_millis(2000), // 每次写延迟 2s（QUIC 拥塞）
        1,                           // downlink_only_timeout = 1s（< 2s write delay）
    )
    .await;

    assert!(
        received < 4 * 1024,
        "期望数据截断（downlink_only=1s < write_delay=2s），但收到了完整 4096 字节"
    );
    assert_eq!(
        termination,
        RelayTermination::HalfCloseTimeout,
        "termination 应为 HalfCloseTimeout"
    );
    eprintln!(
        "✓ 确认 bug：数据截断，仅收到 {received}/4096 字节（termination=HalfCloseTimeout）\n"
    );
}

/// GREEN: 修复验证 — downlink_only_timeout=3s 足以等待 2s 写延迟完成
#[tokio::test(start_paused = false)]
async fn green_downlink_only_3s_slow_write_completes() {
    eprintln!("\n=== GREEN：下载修复验证（downlink_only=3s > write_delay=2s）===");

    let (received, _termination) = simulate_speedtest_download(
        4 * 1024,
        Duration::from_millis(2000), // 写延迟 2s
        3,                           // downlink_only_timeout = 3s（> 2s write delay）
    )
    .await;

    assert_eq!(
        received,
        4 * 1024,
        "期望收到完整 4096 字节，实际收到 {received} 字节"
    );
    eprintln!("✓ 修复有效：4096 字节完整收到\n");
}
