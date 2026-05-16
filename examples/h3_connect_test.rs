/// H3 CONNECT integration test client for the NaiveProxy H3 server.
///
/// Usage:
///   cargo run --example h3_connect_test -- \
///     --server 127.0.0.1:45132 \
///     --uuid eee6e8cb-2a42-4e5e-9b7d-09de7aff716d \
///     --target example.com:80
///
/// This example connects to the H3 NaiveProxy server over QUIC, performs HTTP/3
/// CONNECT tunneling with naive padding, and proxies a raw TCP connection through it.
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, Version};
use std::sync::Arc;

// ── TLS no-verify ─────────────────────────────────────────────────────────────

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

fn make_tls_client_config(
    server_name: &str,
) -> (rustls::ClientConfig, rustls::pki_types::ServerName<'static>) {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h3".to_vec()];

    let sni = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .expect("invalid server name");

    (config, sni)
}

// ── Naive padding (write side only — needed for client→server frames) ─────────

const PADDING_FRAMES: u8 = 8;

struct NaivePaddingWriter {
    frames_done: u8,
}

impl NaivePaddingWriter {
    fn new() -> Self {
        Self { frames_done: 0 }
    }

    fn wrap(&mut self, data: &[u8]) -> Bytes {
        if self.frames_done >= PADDING_FRAMES {
            return Bytes::copy_from_slice(data);
        }
        let data_len = data.len().min(65535);
        let pad_size = (rand_u8() as usize) % 256;
        let mut frame = BytesMut::with_capacity(3 + data_len + pad_size);
        frame.extend_from_slice(&(data_len as u16).to_be_bytes());
        frame.extend_from_slice(&[pad_size as u8]);
        frame.extend_from_slice(&data[..data_len]);
        frame.resize(frame.len() + pad_size, 0xAB);
        self.frames_done += 1;
        frame.freeze()
    }
}

fn rand_u8() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() & 0xFF) as u8)
        .unwrap_or(42)
}

// ── Naive padding (read side — strip headers from server→client frames) ───────

struct NaivePaddingReader {
    frames_done: u8,
    data_rem: usize,
    skip_rem: usize,
    pending_skip: usize,
    hdr: [u8; 3],
    hdr_pos: usize,
}

impl NaivePaddingReader {
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

    /// Feed raw bytes from the wire; returns decoded payload bytes.
    fn feed(&mut self, raw: &mut &[u8]) -> Vec<u8> {
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
            // read header
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
            }
        }
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[derive(clap::Parser, Debug)]
struct Args {
    /// H3 server address (host:port)
    #[clap(long, default_value = "127.0.0.1:45132")]
    server: String,

    /// User UUID for Proxy-Authorization
    #[clap(long)]
    uuid: String,

    /// CONNECT target (host:port)
    #[clap(long, default_value = "1.1.1.1:80")]
    target: String,

    /// TLS server name (SNI)
    #[clap(long, default_value = "localhost")]
    sni: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();

    let server_addr: std::net::SocketAddr = args.server.parse()?;
    println!("[test] connecting to H3 server at {}", server_addr);

    // ── QUIC client setup ────────────────────────────────────────────────────
    let (tls_config, _sni) = make_tls_client_config(&args.sni);

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

    let mut endpoint_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    endpoint_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(endpoint_config);

    // Connect
    let quic_conn = endpoint.connect(server_addr, &args.sni)?.await?;
    println!("[test] QUIC connected");

    // ── H3 connection ────────────────────────────────────────────────────────
    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;

    // Drive the H3 connection in background
    tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // ── HTTP/3 CONNECT ───────────────────────────────────────────────────────
    let auth_value = {
        let creds = format!("user:{}", args.uuid);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds)
        )
    };

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{}", args.target))
        .version(Version::HTTP_3)
        .header("host", &args.target)
        .header("proxy-authorization", &auth_value)
        .header("padding", "!#$()+<>?@[]^`{}~~~~~~~~~~~~~~")
        .body(())?;

    println!("[test] sending CONNECT {} via H3", args.target);
    let mut stream = send_request.send_request(req).await?;
    // Do NOT call finish() here — for CONNECT tunneling the request body IS the tunnel data.

    let resp = stream.recv_response().await?;
    println!(
        "[test] server response: {} {:?}",
        resp.status(),
        resp.headers()
    );

    if resp.status() != 200 {
        anyhow::bail!("Expected 200, got {}", resp.status());
    }

    println!("[test] tunnel established — sending test HTTP request through tunnel");

    // ── Send data through the tunnel ─────────────────────────────────────────
    let http_req = b"HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n";
    let mut padding_writer = NaivePaddingWriter::new();
    let mut padding_reader = NaivePaddingReader::new();

    let frame = padding_writer.wrap(http_req);
    stream.send_data(frame).await?;
    stream.finish().await?;
    println!("[test] {} bytes sent (with padding)", http_req.len());

    // Receive response frames
    let mut received = Vec::new();
    let mut deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::time::Instant::now() > deadline {
            println!("[test] timeout waiting for response data");
            break;
        }
        match stream.recv_data().await? {
            None => {
                println!("[test] stream closed by server");
                break;
            }
            Some(mut data) => {
                let bytes = data.copy_to_bytes(data.remaining());
                let mut slice = bytes.as_ref();
                let decoded = padding_reader.feed(&mut slice);
                received.extend_from_slice(&decoded);
                println!(
                    "[test] received {} raw bytes -> {} decoded bytes",
                    bytes.len(),
                    decoded.len()
                );
                if received.contains(&b'\n') {
                    break;
                }
                deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            }
        }
    }

    if !received.is_empty() {
        let s = String::from_utf8_lossy(&received);
        println!("[test] decoded response:\n{}", s.trim());
        println!("\n[test] H3 CONNECT tunnel test PASSED ✓");
    } else {
        println!("[test] WARNING: no data received through tunnel");
    }

    endpoint.close(0u32.into(), b"done");
    Ok(())
}
