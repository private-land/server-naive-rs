//! Standalone H3 NaiveProxy server — no panel dependency.
//!
//! Used for local end-to-end testing with sing-box.  Runs the H3/QUIC
//! accept loop directly without connecting to a panel, using a single
//! hardcoded UUID for authentication.
//!
//! Usage:
//!   cargo run --example h3_standalone_server -- \
//!     --port 4443 \
//!     --uuid 448af35a-5445-474a-a1dc-fb98cc030eb4 \
//!     --cert .cert/server.crt \
//!     --key .cert/server.key
//!
//! The sing-box config is printed on startup.

use server_naive_rs::{
    config::{ConnConfig, ServerConfig},
    core::{
        hooks::{Authenticator, DirectRouter, StatsCollector, UserId},
        Server,
    },
    logger,
    server_runner::run_h3_server,
};
use std::sync::Arc;

#[derive(clap::Parser, Debug)]
struct Args {
    /// UDP port for QUIC/H3 listener
    #[clap(long, default_value_t = 4443)]
    port: u16,

    /// UUID accepted as password in Proxy-Authorization
    #[clap(long)]
    uuid: String,

    /// TLS certificate (PEM)
    #[clap(long, default_value = ".cert/server.crt")]
    cert: String,

    /// TLS private key (PEM)
    #[clap(long, default_value = ".cert/server.key")]
    key: String,

    /// Log level: trace, debug, info, warn, error
    #[clap(long, default_value = "debug")]
    log_mode: String,

    /// Block connections to private/RFC1918 IP ranges
    #[clap(long, default_value_t = false)]
    block_private_ip: bool,
}

struct SingleUuidAuth(String);

impl Authenticator for SingleUuidAuth {
    fn authenticate(&self, credential: &str) -> Option<UserId> {
        if credential == self.0 {
            Some(1)
        } else {
            None
        }
    }
}

struct NoopStats;

impl StatsCollector for NoopStats {
    fn record_request(&self, _: UserId) {}
    fn record_upload(&self, _: UserId, _: u64) {}
    fn record_download(&self, _: UserId, _: u64) {}
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();
    logger::init_logger(&args.log_mode);

    let conn_config = ConnConfig {
        idle_timeout: std::time::Duration::from_secs(300),
        uplink_only_timeout: std::time::Duration::from_secs(10),
        downlink_only_timeout: std::time::Duration::from_secs(10),
        connect_timeout: std::time::Duration::from_secs(10),
        request_timeout: std::time::Duration::from_secs(10),
        tls_handshake_timeout: std::time::Duration::from_secs(10),
        buffer_size: 32 * 1024,
        tcp_backlog: 1024,
        tcp_nodelay: true,
        max_connections: 0, // unlimited for testing
    };

    let server_config = ServerConfig {
        port: args.port,
        cert: Some(args.cert.clone().into()),
        key: Some(args.key.clone().into()),
        acl_conf_file: None,
        data_dir: std::path::PathBuf::from("/tmp/naive-standalone"),
        block_private_ip: args.block_private_ip,
    };

    let dns_cache = dns_cache_rs::DnsCache::new();
    let router = Arc::new(DirectRouter::with_cache(
        args.block_private_ip,
        dns_cache.clone(),
    ));

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SingleUuidAuth(args.uuid.clone())))
            .stats(Arc::new(NoopStats) as Arc<dyn StatsCollector>)
            .router(router)
            .conn_config(conn_config)
            .dns_cache(dns_cache)
            .build(),
    );

    print_test_instructions(args.port, &args.uuid);

    run_h3_server(server, &server_config).await
}

fn print_test_instructions(port: u16, uuid: &str) {
    let singbox_cfg = format!(
        r#"{{
  "log": {{ "level": "debug", "output": "/tmp/singbox.log" }},
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "127.0.0.1",
    "listen_port": 1080
  }}],
  "outbounds": [
    {{
      "type": "naive",
      "tag": "naive-h3",
      "server": "127.0.0.1",
      "server_port": {port},
      "username": "user",
      "password": "{uuid}",
      "network": "udp",
      "tls": {{
        "enabled": true,
        "insecure": true,
        "server_name": "localhost"
      }}
    }},
    {{ "type": "direct", "tag": "direct" }}
  ],
  "route": {{
    "rules": [{{ "outbound": "naive-h3" }}],
    "final": "direct"
  }}
}}"#
    );

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  H3 Standalone Server — Local E2E Test Setup        ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!("\n[1] Save sing-box config:");
    println!("    cat > /tmp/singbox_naive_test.json << 'EOF'");
    println!("{singbox_cfg}");
    println!("EOF");
    println!("\n[2] Start sing-box:");
    println!("    sing-box run -c /tmp/singbox_naive_test.json");
    println!("\n[3] Single-thread test:");
    println!("    curl -x socks5://127.0.0.1:1080 -v http://httpbin.org/ip");
    println!("\n[4] Multi-thread test (8 parallel, simulates speedtest):");
    println!("    for i in $(seq 1 8); do");
    println!("      curl -x socks5://127.0.0.1:1080 -s -o /dev/null -w \"%{{time_total}} %{{http_code}}\\n\" http://httpbin.org/ip &");
    println!("    done; wait");
    println!("\n[5] Bulk transfer (download throughput via proxy):");
    println!(
        "    curl -x socks5://127.0.0.1:1080 -o /dev/null http://speedtest.tele2.net/10MB.zip"
    );
    println!("\nServer UUID: {uuid}");
    println!("Server port: {port} (UDP/QUIC)\n");
}
