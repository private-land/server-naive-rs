//! Multi-stream H3 CONNECT end-to-end test.
//!
//! Verifies the two multi-thread bugs are fixed in a real environment:
//!
//!   Bug 1 — SETTINGS_ENABLE_CONNECT_PROTOCOL=0:
//!     Without `enable_extended_connect(true)` the server sends
//!     SETTINGS_ENABLE_CONNECT_PROTOCOL=0.  A strict client opens the first
//!     CONNECT stream before SETTINGS arrive (succeeds), then reads the
//!     SETTINGS and refuses streams 2..N.  This test opens all N streams
//!     *after* receiving SETTINGS — the exact case that exposed the bug.
//!
//!   Bug 2 — recv_data blocked by write_all (upload stall):
//!     When `io_write.write_all()` runs inside the `select!` arm, a slow relay
//!     prevents `recv_data()` from being polled on other concurrent streams.
//!     The `--upload-bytes` flag triggers parallel uploads so the stall is
//!     observable if the fix is reverted.
//!
//! Usage (two terminals):
//!
//!   # Terminal 1 — start standalone H3 server:
//!   cargo run --example h3_standalone_server -- \
//!     --uuid 448af35a-5445-474a-a1dc-fb98cc030eb4
//!
//!   # Terminal 2 — run multi-stream test:
//!   cargo run --example h3_multistream_test -- \
//!     --server 127.0.0.1:4443 \
//!     --uuid 448af35a-5445-474a-a1dc-fb98cc030eb4 \
//!     --streams 8

use base64::Engine as _;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::future::join_all;
use h3::ConnectionState as _;
use http::{Method, Request, Version};
use std::sync::Arc;
use std::time::Instant;

// ── TLS: no-verify (test server uses self-signed cert) ────────────────────────

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ── Naive padding (client side — mirrors sing-box's implementation) ───────────

const PADDING_FRAMES: u8 = 8;

struct PaddingWriter {
    frames_done: u8,
}

impl PaddingWriter {
    fn new() -> Self {
        Self { frames_done: 0 }
    }

    fn encode(&mut self, data: &[u8]) -> Bytes {
        if self.frames_done >= PADDING_FRAMES {
            return Bytes::copy_from_slice(data);
        }
        let data_len = data.len().min(65535);
        let pad_size = rand_u8() as usize;
        let mut frame = BytesMut::with_capacity(3 + data_len + pad_size);
        frame.extend_from_slice(&(data_len as u16).to_be_bytes());
        frame.extend_from_slice(&[pad_size as u8]);
        frame.extend_from_slice(&data[..data_len]);
        frame.resize(frame.len() + pad_size, 0xAB);
        self.frames_done += 1;
        frame.freeze()
    }
}

struct PaddingReader {
    frames_done: u8,
    data_rem: usize,
    skip_rem: usize,
    pending_skip: usize,
    hdr: [u8; 3],
    hdr_pos: usize,
}

impl PaddingReader {
    fn new() -> Self {
        Self {
            frames_done: 0,
            data_rem: 0,
            skip_rem: 0,
            pending_skip: 0,
            hdr: [0; 3],
            hdr_pos: 0,
        }
    }

    fn decode(&mut self, raw: &mut &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            if self.frames_done >= PADDING_FRAMES {
                out.extend_from_slice(raw);
                *raw = &[];
                return out;
            }
            if self.data_rem > 0 {
                let take = self.data_rem.min(raw.len());
                out.extend_from_slice(&raw[..take]);
                *raw = &raw[take..];
                self.data_rem -= take;
                if self.data_rem == 0 {
                    self.skip_rem = self.pending_skip;
                    self.pending_skip = 0;
                }
                if raw.is_empty() {
                    return out;
                }
                continue;
            }
            if self.skip_rem > 0 {
                let skip = self.skip_rem.min(raw.len());
                *raw = &raw[skip..];
                self.skip_rem -= skip;
                if raw.is_empty() {
                    return out;
                }
                continue;
            }
            while self.hdr_pos < 3 && !raw.is_empty() {
                self.hdr[self.hdr_pos] = raw[0];
                *raw = &raw[1..];
                self.hdr_pos += 1;
            }
            if self.hdr_pos < 3 {
                return out;
            }
            let data_size = u16::from_be_bytes([self.hdr[0], self.hdr[1]]) as usize;
            let pad_size = self.hdr[2] as usize;
            self.hdr_pos = 0;
            self.frames_done += 1;
            self.data_rem = data_size;
            self.pending_skip = pad_size;
            if data_size == 0 {
                self.skip_rem = pad_size;
                self.pending_skip = 0;
                self.data_rem = 0;
            }
        }
    }
}

fn rand_u8() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() & 0xFF) as u8)
        .unwrap_or(42)
}

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(clap::Parser, Debug)]
struct Args {
    /// H3 server address (host:port)
    #[clap(long, default_value = "127.0.0.1:4443")]
    server: String,

    /// User UUID for Proxy-Authorization
    #[clap(long)]
    uuid: String,

    /// Proxy target for CONNECT tunnels (host:port).
    /// Ignored when --local-echo is set (target is auto-assigned).
    #[clap(long, default_value = "1.1.1.1:80")]
    target: String,

    /// Number of parallel CONNECT streams (simulates multi-thread)
    #[clap(long, default_value_t = 8)]
    streams: usize,

    /// Bytes to upload per stream (0 = skip upload test)
    #[clap(long, default_value_t = 512 * 1024)]
    upload_bytes: usize,

    /// TLS server name (SNI)
    #[clap(long, default_value = "localhost")]
    sni: String,

    /// Wait this many milliseconds for SETTINGS before opening streams
    #[clap(long, default_value_t = 300)]
    settings_wait_ms: u64,

    /// Start a local TCP echo server and use it as the CONNECT target.
    /// The echo server reads all incoming bytes and mirrors them back, making
    /// this a true simultaneous upload+download test (speedtest simulation).
    /// --upload-bytes controls bytes sent per stream; the same amount is
    /// echoed back and verified.
    #[clap(long, default_value_t = false)]
    local_echo: bool,

    /// Per-stream download bytes when --local-echo is set (0 = echo upload bytes)
    #[clap(long, default_value_t = 0)]
    download_bytes: usize,
}

// ── Local echo server ─────────────────────────────────────────────────────────

/// Start a TCP server that echoes every byte back to the sender.
/// Returns the bound address (127.0.0.1:<random-port>).
async fn start_echo_server() -> anyhow::Result<std::net::SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = conn.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    Ok(addr)
}

// ── Speedtest stream handler (echo-server target) ──────────────────────────────

/// Simultaneously uploads and downloads `upload_bytes` through the tunnel,
/// using naive padding protocol (matching the proxy's NaivePaddedTransport).
///
/// Splits the h3 client stream into send/recv halves so upload and download
/// run in truly parallel tasks — this is the critical path for Bug 3 testing:
/// the bridge's send_task must not block the recv loop under backpressure.
async fn handle_echo_stream(
    idx: usize,
    mut stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upload_bytes: usize,
    _download_bytes: usize,
) -> StreamResult {
    let start = Instant::now();

    // Receive 200 CONNECT response
    let resp = match stream.recv_response().await {
        Ok(r) => r,
        Err(e) => {
            return StreamResult {
                idx,
                success: false,
                response: String::new(),
                elapsed_ms: start.elapsed().as_millis(),
                error: Some(format!("recv_response: {e}")),
            };
        }
    };
    if resp.status() != 200 {
        return StreamResult {
            idx,
            success: false,
            response: format!("status={}", resp.status()),
            elapsed_ms: start.elapsed().as_millis(),
            error: Some(format!("expected 200, got {}", resp.status())),
        };
    }

    // Split into independent send/recv halves — upload and download run in
    // separate tasks so both directions are active simultaneously (Bug 3 test).
    let (mut h3_send, mut h3_recv) = stream.split();

    // Upload task: PaddingWriter encodes data → proxy strips padding → echo server
    let upload_task = tokio::spawn(async move {
        let mut writer = PaddingWriter::new();
        let chunk = vec![0x55_u8; 4096.min(upload_bytes.max(1))];
        let mut sent = 0usize;
        while sent < upload_bytes {
            let remaining = upload_bytes - sent;
            let data = &chunk[..remaining.min(chunk.len())];
            let frame = writer.encode(data);
            sent += data.len();
            if h3_send.send_data(frame).await.is_err() {
                return Err(format!("send_data failed at {sent}/{upload_bytes} bytes"));
            }
        }
        if h3_send.finish().await.is_err() {
            return Err("finish failed".to_string());
        }
        Ok(sent)
    });

    // Download: echo server → proxy adds padding → PaddingReader decodes → count
    // Runs concurrently with upload task above (Bug 3: download must not stall upload).
    let mut reader = PaddingReader::new();
    let mut decoded = 0usize;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let dl_err: Option<String> = loop {
        if tokio::time::Instant::now() > deadline {
            break Some(format!(
                "download timeout after {decoded}/{upload_bytes} bytes"
            ));
        }
        match h3_recv.recv_data().await {
            Err(e) => break Some(format!("recv_data: {e}")),
            Ok(None) => break None, // stream closed cleanly
            Ok(Some(mut data)) => {
                let bytes = data.copy_to_bytes(data.remaining());
                let mut slice = bytes.as_ref();
                let out = reader.decode(&mut slice);
                decoded += out.len();
                if decoded >= upload_bytes {
                    break None;
                }
            }
        }
    };

    // Wait for upload to finish
    let ul_result = match upload_task.await {
        Ok(r) => r,
        Err(e) => Err(format!("upload task panic: {e}")),
    };

    let ul_err = ul_result.err();
    let success = dl_err.is_none() && ul_err.is_none() && decoded >= upload_bytes;
    let error = dl_err.or(ul_err).or_else(|| {
        if !success {
            Some(format!("decoded {decoded}/{upload_bytes} bytes"))
        } else {
            None
        }
    });

    StreamResult {
        idx,
        success,
        response: format!("echo decoded {decoded}/{upload_bytes} bytes"),
        elapsed_ms: start.elapsed().as_millis(),
        error,
    }
}

// ── Stream result ─────────────────────────────────────────────────────────────

struct StreamResult {
    idx: usize,
    success: bool,
    response: String,
    elapsed_ms: u128,
    error: Option<String>,
}

// ── Per-stream handler ────────────────────────────────────────────────────────

async fn handle_stream(
    idx: usize,
    mut stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    target: String,
    upload_bytes: usize,
) -> StreamResult {
    let start = Instant::now();

    // ── Receive the 200 response (or fail immediately) ────────────────────
    let resp = match stream.recv_response().await {
        Ok(r) => r,
        Err(e) => {
            return StreamResult {
                idx,
                success: false,
                response: String::new(),
                elapsed_ms: start.elapsed().as_millis(),
                error: Some(format!("recv_response: {e}")),
            };
        }
    };

    if resp.status() != 200 {
        return StreamResult {
            idx,
            success: false,
            response: format!("status={}", resp.status()),
            elapsed_ms: start.elapsed().as_millis(),
            error: Some(format!("expected 200, got {}", resp.status())),
        };
    }

    // ── Upload test: send N bytes through the tunnel ──────────────────────
    // This exercises Bug 2 (recv_data blocked by write_all).
    if upload_bytes > 0 {
        let mut writer = PaddingWriter::new();
        let chunk = vec![0xAA_u8; 4096.min(upload_bytes)];
        let mut sent = 0usize;
        while sent < upload_bytes {
            let remaining = upload_bytes - sent;
            let data = &chunk[..remaining.min(chunk.len())];
            let frame = writer.encode(data);
            sent += data.len();
            if stream.send_data(frame).await.is_err() {
                return StreamResult {
                    idx,
                    success: false,
                    response: String::new(),
                    elapsed_ms: start.elapsed().as_millis(),
                    error: Some("send_data failed during upload".into()),
                };
            }
        }
    }

    // ── Send HEAD request through the tunnel ─────────────────────────────
    let http_req = format!("HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    let mut writer = PaddingWriter::new();
    let frame = writer.encode(http_req.as_bytes());

    if stream.send_data(frame).await.is_err() {
        return StreamResult {
            idx,
            success: false,
            response: String::new(),
            elapsed_ms: start.elapsed().as_millis(),
            error: Some("send_data failed".into()),
        };
    }
    if stream.finish().await.is_err() {
        return StreamResult {
            idx,
            success: false,
            response: String::new(),
            elapsed_ms: start.elapsed().as_millis(),
            error: Some("finish failed".into()),
        };
    }

    // ── Read the proxied HTTP response headers ────────────────────────────
    let mut reader = PaddingReader::new();
    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);

    loop {
        if tokio::time::Instant::now() > deadline {
            return StreamResult {
                idx,
                success: false,
                response: String::from_utf8_lossy(&received)
                    .chars()
                    .take(120)
                    .collect(),
                elapsed_ms: start.elapsed().as_millis(),
                error: Some("timeout waiting for target response".into()),
            };
        }

        match stream.recv_data().await {
            Err(e) => {
                return StreamResult {
                    idx,
                    success: false,
                    response: String::new(),
                    elapsed_ms: start.elapsed().as_millis(),
                    error: Some(format!("recv_data: {e}")),
                };
            }
            Ok(None) => break, // stream closed
            Ok(Some(mut data)) => {
                let bytes = data.copy_to_bytes(data.remaining());
                let mut slice = bytes.as_ref();
                let decoded = reader.decode(&mut slice);
                received.extend_from_slice(&decoded);
                // Stop once we have at least the first response line
                if received.contains(&b'\n') {
                    break;
                }
            }
        }
    }

    let first_line: String = received
        .split(|b| *b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).trim().to_string())
        .unwrap_or_default();

    let success = first_line.starts_with("HTTP/");
    let error = if success {
        None
    } else {
        Some(format!(
            "unexpected first line: {:?}",
            first_line.chars().take(80).collect::<String>()
        ))
    };

    StreamResult {
        idx,
        success,
        response: first_line,
        elapsed_ms: start.elapsed().as_millis(),
        error,
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();

    // ── Optional: start local echo server ────────────────────────────────
    let effective_target = if args.local_echo {
        let echo_addr = start_echo_server().await?;
        println!("[+] Local echo server started on {echo_addr}");
        echo_addr.to_string()
    } else {
        args.target.clone()
    };

    println!("=== H3 Multi-Stream CONNECT Test ===");
    println!("server  : {}", args.server);
    println!(
        "target  : {} {}",
        effective_target,
        if args.local_echo { "(local echo)" } else { "" }
    );
    println!("streams : {}", args.streams);
    println!(
        "mode    : {}",
        if args.local_echo {
            format!(
                "speedtest (upload {} KB + echo download per stream)",
                args.upload_bytes / 1024
            )
        } else {
            format!(
                "HEAD via proxy (upload {} KB first)",
                args.upload_bytes / 1024
            )
        }
    );
    println!();

    // ── QUIC client setup ─────────────────────────────────────────────────
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let server_addr: std::net::SocketAddr = args.server.parse()?;
    let quic_conn = endpoint.connect(server_addr, &args.sni)?.await?;
    println!("[+] QUIC connected to {}", server_addr);

    // ── H3 connection ─────────────────────────────────────────────────────
    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let (mut driver, mut sender) = h3::client::new(h3_conn).await?;

    // Drive the H3 connection in background (processes QUIC frames,
    // delivers responses to the correct stream's internal buffer).
    tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // ── Wait for SETTINGS ─────────────────────────────────────────────────
    // This is the critical step: opening streams BEFORE settings = Bug 1
    // scenario.  We wait to ensure the client has processed the server's
    // SETTINGS frame, then open all N streams.
    tokio::time::sleep(std::time::Duration::from_millis(args.settings_wait_ms)).await;

    let extended_connect = sender.settings().enable_extended_connect();
    if extended_connect {
        println!("[OK] SETTINGS_ENABLE_CONNECT_PROTOCOL=1 advertised by server");
    } else {
        println!("[FAIL] SETTINGS_ENABLE_CONNECT_PROTOCOL=0 — Bug 1 is present!");
        println!("       Streams 2..N will be refused by a strict client.");
        println!("       Fix: use h3::server::builder().enable_extended_connect(true)");
        println!();
    }

    // ── Build auth header ─────────────────────────────────────────────────
    let auth_value = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("user:{}", args.uuid))
    );

    // ── Open N CONNECT streams (all AFTER SETTINGS) ───────────────────────
    println!(
        "[+] Opening {} parallel CONNECT streams after SETTINGS...",
        args.streams
    );
    let open_start = Instant::now();

    let mut streams = Vec::with_capacity(args.streams);
    for i in 0..args.streams {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{}", effective_target))
            .version(Version::HTTP_3)
            .header("host", &effective_target)
            .header("proxy-authorization", &auth_value)
            .header("padding", "!#$()+<>?@[]^`{}~~~~~~~~~~~~~~")
            .body(())
            .unwrap();

        match sender.send_request(req).await {
            Ok(stream) => {
                println!("  stream {i}: CONNECT queued");
                streams.push(stream);
            }
            Err(e) => {
                println!("  stream {i}: FAILED to open — {e}");
                println!();
                println!("[FAIL] Bug 1 confirmed: stream {i} was refused after SETTINGS.");
                println!("       Check SETTINGS_ENABLE_CONNECT_PROTOCOL in server logs.");
                std::process::exit(1);
            }
        }
    }

    println!(
        "[+] All {} streams opened in {:.1?}",
        args.streams,
        open_start.elapsed()
    );
    println!("[+] Running all streams concurrently...");
    println!();

    // ── Run all streams concurrently via join_all ─────────────────────────
    let relay_start = Instant::now();
    let upload = args.upload_bytes;
    let download = args.download_bytes;

    let results = if args.local_echo {
        join_all(
            streams
                .into_iter()
                .enumerate()
                .map(|(i, stream)| handle_echo_stream(i, stream, upload, download)),
        )
        .await
    } else {
        let target = effective_target.clone();
        join_all(
            streams
                .into_iter()
                .enumerate()
                .map(|(i, stream)| handle_stream(i, stream, target.clone(), upload)),
        )
        .await
    };

    let total_elapsed = relay_start.elapsed();

    // ── Report ────────────────────────────────────────────────────────────
    println!("━━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let mut passed = 0usize;
    for r in &results {
        if r.success {
            passed += 1;
            println!(
                "  [OK]   stream {:>2}: {} ({}ms)",
                r.idx, r.response, r.elapsed_ms
            );
        } else {
            println!(
                "  [FAIL] stream {:>2}: {} ({}ms)",
                r.idx,
                r.error.as_deref().unwrap_or("unknown"),
                r.elapsed_ms
            );
        }
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "Passed: {}/{} streams in {:.1?}",
        passed, args.streams, total_elapsed
    );
    println!();

    if passed == args.streams {
        println!("PASS: all {} streams completed successfully.", args.streams);
        println!("  Bug 1 (SETTINGS_ENABLE_CONNECT_PROTOCOL): FIXED");
        println!("  Bug 2 (recv_data blocked by write_all):    FIXED");
        println!("  Bug 3 (send_data blocks recv_data):        FIXED");
    } else {
        let failed = args.streams - passed;
        println!("FAIL: {failed} stream(s) did not complete.");
        if !extended_connect {
            println!("  → Bug 1 likely: server sent SETTINGS_ENABLE_CONNECT_PROTOCOL=0");
        }
        println!("  → Check server debug logs for details");
        std::process::exit(1);
    }

    endpoint.close(0u32.into(), b"done");
    Ok(())
}
