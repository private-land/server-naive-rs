//! Configuration module for Naive proxy server (Agent version)

use anyhow::{anyhow, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

use crate::business::{IpVersion, NodeConfigEnum};
use crate::config_auto::MaxConnections;

fn parse_ip_version(s: &str) -> Result<IpVersion, String> {
    match s.to_lowercase().as_str() {
        "v4" | "ipv4" | "4" => Ok(IpVersion::V4),
        "v6" | "ipv6" | "6" => Ok(IpVersion::V6),
        "auto" => Ok(IpVersion::Auto),
        _ => Err(format!(
            "Invalid IP version '{}'. Use 'v4', 'v6', or 'auto'",
            s
        )),
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    if let Ok(d) = humantime::parse_duration(s) {
        return Ok(d);
    }
    s.parse::<u64>().map(Duration::from_secs).map_err(|_| {
        format!(
            "Invalid duration '{}'. Use formats like '60s', '2m', '1h' or plain seconds",
            s
        )
    })
}

const DEFAULT_DATA_DIR: &str = "/var/lib/naive-agent-node";

/// CLI arguments for the Naive proxy server (Agent version)
///
/// Supports environment variables with X_PANDA_NAIVE_ prefix
#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "Naive Proxy Server Agent with Panel Integration"
)]
#[command(rename_all = "snake_case")]
pub struct CliArgs {
    /// Panel server host (e.g. 127.0.0.1)
    #[arg(long, env = "X_PANDA_NAIVE_SERVER_HOST", default_value = "127.0.0.1")]
    pub server_host: String,

    /// Panel server port
    #[arg(long, env = "X_PANDA_NAIVE_PORT", default_value_t = 8082)]
    pub port: u16,

    /// Node ID from the panel (required)
    #[arg(long, env = "X_PANDA_NAIVE_NODE")]
    pub node: u32,

    /// TLS server name (SNI) for panel connection (defaults to server_host)
    #[arg(long, env = "X_PANDA_NAIVE_SERVER_NAME")]
    pub server_name: Option<String>,

    /// CA certificate path for panel TLS (None = system trust store)
    #[arg(long, env = "X_PANDA_NAIVE_CA_FILE")]
    pub ca_file: Option<String>,

    /// TLS certificate file path
    #[arg(
        long,
        env = "X_PANDA_NAIVE_CERT_FILE",
        default_value = "/root/.cert/server.crt"
    )]
    pub cert_file: String,

    /// TLS private key file path
    #[arg(
        long,
        env = "X_PANDA_NAIVE_KEY_FILE",
        default_value = "/root/.cert/server.key"
    )]
    pub key_file: String,

    /// Interval for fetching users
    #[arg(long, env = "X_PANDA_NAIVE_FETCH_USERS_INTERVAL", default_value = "60s", value_parser = parse_duration)]
    pub fetch_users_interval: Duration,

    /// Interval for reporting traffic
    #[arg(long, env = "X_PANDA_NAIVE_REPORT_TRAFFICS_INTERVAL", default_value = "100s", value_parser = parse_duration)]
    pub report_traffics_interval: Duration,

    /// Interval for sending heartbeat
    #[arg(long, env = "X_PANDA_NAIVE_HEARTBEAT_INTERVAL", default_value = "180s", value_parser = parse_duration)]
    pub heartbeat_interval: Duration,

    /// API request timeout
    #[arg(long, env = "X_PANDA_NAIVE_API_TIMEOUT", default_value = "15s", value_parser = parse_duration)]
    pub api_timeout: Duration,

    /// Log mode: debug, info, warn, error
    #[arg(long, env = "X_PANDA_NAIVE_LOG_MODE", default_value = "info")]
    pub log_mode: String,

    /// Data directory for state persistence
    #[arg(long, env = "X_PANDA_NAIVE_DATA_DIR", default_value = DEFAULT_DATA_DIR)]
    pub data_dir: PathBuf,

    /// ACL config file (.yaml format)
    #[arg(long, env = "X_PANDA_NAIVE_ACL_CONF_FILE")]
    pub acl_conf_file: Option<PathBuf>,

    /// Block connections to private/loopback IP addresses (SSRF protection)
    #[arg(long, env = "X_PANDA_NAIVE_BLOCK_PRIVATE_IP", default_value_t = true)]
    pub block_private_ip: bool,

    /// Force refresh geoip and geosite databases on startup
    #[arg(
        long = "refresh_geodata",
        env = "X_PANDA_NAIVE_REFRESH_GEODATA",
        default_value_t = false
    )]
    pub refresh_geodata: bool,

    /// IP version for panel API connections: v4, v6, or auto
    #[arg(
        long = "panel_ip_version",
        env = "X_PANDA_NAIVE_PANEL_IP_VERSION",
        default_value = "v4",
        value_parser = parse_ip_version,
        help_heading = "Network"
    )]
    pub panel_ip_version: IpVersion,

    // ==================== Performance Tuning ====================
    /// Connection idle timeout
    #[arg(long, env = "X_PANDA_NAIVE_CONN_IDLE_TIMEOUT", default_value = "5m", value_parser = parse_duration, help_heading = "Performance")]
    pub conn_idle_timeout: Duration,

    /// TCP connect timeout to target server
    #[arg(long, env = "X_PANDA_NAIVE_TCP_CONNECT_TIMEOUT", default_value = "5s", value_parser = parse_duration, help_heading = "Performance")]
    pub tcp_connect_timeout: Duration,

    /// Timeout for reading request headers
    #[arg(long, env = "X_PANDA_NAIVE_REQUEST_TIMEOUT", default_value = "5s", value_parser = parse_duration, help_heading = "Performance")]
    pub request_timeout: Duration,

    /// TLS handshake timeout
    #[arg(long, env = "X_PANDA_NAIVE_TLS_HANDSHAKE_TIMEOUT", default_value = "10s", value_parser = parse_duration, help_heading = "Performance")]
    pub tls_handshake_timeout: Duration,

    /// Buffer size for data transfer in bytes
    #[arg(long, env = "X_PANDA_NAIVE_BUFFER_SIZE", default_value_t = 32 * 1024, help_heading = "Performance")]
    pub buffer_size: usize,

    /// TCP listen backlog for pending connections
    #[arg(
        long,
        env = "X_PANDA_NAIVE_TCP_BACKLOG",
        default_value_t = 1024,
        help_heading = "Performance"
    )]
    pub tcp_backlog: i32,

    /// Enable TCP_NODELAY for lower latency
    #[arg(
        long,
        env = "X_PANDA_NAIVE_TCP_NODELAY",
        default_value_t = true,
        help_heading = "Performance"
    )]
    pub tcp_nodelay: bool,

    /// After client closes (upload EOF), wait this long for remote to finish.
    ///
    /// Must be long enough for the remote server to process the request and send
    /// back a response after the client finishes uploading (e.g. HTTP POST).
    /// speedtest.net upload typically needs 3–10s for the server to respond;
    /// 30s provides a safe margin without keeping truly dead connections alive
    /// (the idle_timeout handles genuinely silent connections).
    #[arg(long, env = "X_PANDA_NAIVE_UPLINK_ONLY_TIMEOUT", default_value = "30s", value_parser = parse_duration, help_heading = "Performance")]
    pub uplink_only_timeout: Duration,

    /// After remote closes (download EOF), wait this long for client to finish.
    ///
    /// Must be long enough to drain all in-flight data through the QUIC/H3
    /// pipeline to the client on high-latency international links.
    #[arg(long, env = "X_PANDA_NAIVE_DOWNLINK_ONLY_TIMEOUT", default_value = "30s", value_parser = parse_duration, help_heading = "Performance")]
    pub downlink_only_timeout: Duration,

    /// Maximum concurrent connections (use 'auto' to derive from system resources)
    #[arg(
        long,
        env = "X_PANDA_NAIVE_MAX_CONNECTIONS",
        default_value = "auto",
        help_heading = "Performance"
    )]
    pub max_connections: MaxConnections,
}

impl CliArgs {
    pub fn parse_args() -> Self {
        Self::parse()
    }

    pub fn validate(&self) -> Result<()> {
        if self.server_host.is_empty() {
            return Err(anyhow!("Server host is required (--server_host)"));
        }
        if self.port == 0 {
            return Err(anyhow!("Port must be a positive integer (--port)"));
        }
        if self.node == 0 {
            return Err(anyhow!("Node ID must be a positive integer"));
        }
        if self.cert_file.is_empty() {
            return Err(anyhow!(
                "TLS certificate file path is required (--cert_file)"
            ));
        }
        if self.key_file.is_empty() {
            return Err(anyhow!(
                "TLS private key file path is required (--key_file)"
            ));
        }

        let cert_path = std::path::Path::new(&self.cert_file);
        if !cert_path.exists() {
            return Err(anyhow!(
                "TLS certificate file not found: {}",
                self.cert_file
            ));
        }
        let key_path = std::path::Path::new(&self.key_file);
        if !key_path.exists() {
            return Err(anyhow!("TLS private key file not found: {}", self.key_file));
        }

        if self.fetch_users_interval.is_zero() {
            return Err(anyhow!("fetch_users_interval must be greater than 0"));
        }
        if self.report_traffics_interval.is_zero() {
            return Err(anyhow!("report_traffics_interval must be greater than 0"));
        }
        if self.heartbeat_interval.is_zero() {
            return Err(anyhow!("heartbeat_interval must be greater than 0"));
        }

        const VALID_LOG_MODES: &[&str] = &["trace", "debug", "info", "warn", "error"];
        if !VALID_LOG_MODES.contains(&self.log_mode.to_lowercase().as_str()) {
            return Err(anyhow!(
                "Invalid log_mode '{}'. Valid values: trace, debug, info, warn, error",
                self.log_mode
            ));
        }

        if let Some(ref ca) = self.ca_file {
            if !std::path::Path::new(ca).exists() {
                return Err(anyhow!("CA certificate file not found: {}", ca));
            }
        }

        if let Some(ref path) = self.acl_conf_file {
            if !path.exists() {
                return Err(anyhow!("ACL config file not found: {}", path.display()));
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
                return Err(anyhow!(
                    "Invalid ACL config file format: expected .yaml or .yml extension"
                ));
            }
        }

        Ok(())
    }
}

/// QUIC congestion control algorithm for a naive H3 node.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    /// BBR — bandwidth-delay product based; best for high-latency proxy links (default).
    #[default]
    Bbr,
    /// CUBIC — loss-based; Quinn's original default.
    Cubic,
    /// NewReno — classic loss-based algorithm.
    NewReno,
}

/// Transport network mode for a naive node.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NaiveNetwork {
    /// HTTP/2 over TLS (default).
    #[default]
    Tcp,
    /// HTTP/3 over QUIC.
    Udp,
}

impl std::fmt::Display for NaiveNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NaiveNetwork::Tcp => write!(f, "tcp"),
            NaiveNetwork::Udp => write!(f, "udp"),
        }
    }
}

/// Naive node configuration deserialized from panel API JSON.
///
/// The panel returns `NodeConfigEnum::Naive(json_string)`.
#[derive(Debug, Clone, Deserialize)]
pub struct NaiveConfig {
    pub server_port: u16,
    /// Transport mode: "tcp" (H2+TLS, default) or "udp" (H3+QUIC).
    #[serde(default)]
    pub network: NaiveNetwork,
    /// QUIC congestion control algorithm (H3 only). Defaults to BBR.
    #[serde(default)]
    pub congestion_control: CongestionControl,
}

/// Parse a `NodeConfigEnum` into a `NaiveConfig`.
pub fn parse_naive_config(config_enum: NodeConfigEnum) -> Result<NaiveConfig> {
    match config_enum {
        NodeConfigEnum::Naive(json) => {
            serde_json::from_str(&json).map_err(|e| anyhow!("Failed to parse NaiveConfig: {}", e))
        }
        other => Err(anyhow!(
            "Expected Naive config, got {:?}",
            std::mem::discriminant(&other)
        )),
    }
}

/// Connection performance configuration
#[derive(Debug, Clone, Copy)]
pub struct ConnConfig {
    pub idle_timeout: Duration,
    pub uplink_only_timeout: Duration,
    pub downlink_only_timeout: Duration,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub tls_handshake_timeout: Duration,
    pub buffer_size: usize,
    pub tcp_backlog: i32,
    pub tcp_nodelay: bool,
    pub max_connections: usize,
}

impl ConnConfig {
    pub fn from_cli(cli: &CliArgs, max_connections: usize) -> Self {
        Self {
            idle_timeout: cli.conn_idle_timeout,
            uplink_only_timeout: cli.uplink_only_timeout,
            downlink_only_timeout: cli.downlink_only_timeout,
            connect_timeout: cli.tcp_connect_timeout,
            request_timeout: cli.request_timeout,
            tls_handshake_timeout: cli.tls_handshake_timeout,
            buffer_size: cli.buffer_size,
            tcp_backlog: cli.tcp_backlog,
            tcp_nodelay: cli.tcp_nodelay,
            max_connections,
        }
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout.as_secs()
    }

    pub fn uplink_only_timeout_secs(&self) -> u64 {
        self.uplink_only_timeout.as_secs()
    }

    pub fn downlink_only_timeout_secs(&self) -> u64 {
        self.downlink_only_timeout.as_secs()
    }
}

/// Runtime server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub acl_conf_file: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub block_private_ip: bool,
    /// QUIC congestion control algorithm (H3 only).
    pub congestion_control: CongestionControl,
}

impl ServerConfig {
    pub fn from_remote(remote: &NaiveConfig, cli: &CliArgs) -> Result<Self> {
        Ok(Self {
            port: remote.server_port,
            cert: Some(PathBuf::from(&cli.cert_file)),
            key: Some(PathBuf::from(&cli.key_file)),
            acl_conf_file: cli.acl_conf_file.clone(),
            data_dir: cli.data_dir.clone(),
            block_private_ip: cli.block_private_ip,
            congestion_control: remote.congestion_control.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cli_args() -> CliArgs {
        CliArgs {
            server_host: "127.0.0.1".to_string(),
            port: 8082,
            node: 1,
            server_name: None,
            ca_file: None,
            cert_file: "/path/to/cert.pem".to_string(),
            key_file: "/path/to/key.pem".to_string(),
            fetch_users_interval: Duration::from_secs(60),
            report_traffics_interval: Duration::from_secs(100),
            heartbeat_interval: Duration::from_secs(180),
            api_timeout: Duration::from_secs(15),
            log_mode: "info".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            acl_conf_file: None,
            conn_idle_timeout: Duration::from_secs(300),
            tcp_connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            tls_handshake_timeout: Duration::from_secs(10),
            buffer_size: 32 * 1024,
            tcp_backlog: 1024,
            tcp_nodelay: true,
            uplink_only_timeout: Duration::from_secs(30),
            downlink_only_timeout: Duration::from_secs(30),
            max_connections: MaxConnections::Fixed(10_000),
            block_private_ip: true,
            refresh_geodata: false,
            panel_ip_version: IpVersion::V4,
        }
    }

    fn create_test_cli_args_with_temp_certs() -> (CliArgs, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        std::fs::write(&cert_path, "dummy cert").unwrap();
        std::fs::write(&key_path, "dummy key").unwrap();

        let cli = CliArgs {
            server_host: "127.0.0.1".to_string(),
            port: 8082,
            node: 1,
            server_name: None,
            ca_file: None,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            fetch_users_interval: Duration::from_secs(60),
            report_traffics_interval: Duration::from_secs(100),
            heartbeat_interval: Duration::from_secs(180),
            api_timeout: Duration::from_secs(15),
            log_mode: "info".to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            acl_conf_file: None,
            block_private_ip: true,
            refresh_geodata: false,
            conn_idle_timeout: Duration::from_secs(300),
            tcp_connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            tls_handshake_timeout: Duration::from_secs(10),
            buffer_size: 32 * 1024,
            tcp_backlog: 1024,
            tcp_nodelay: true,
            uplink_only_timeout: Duration::from_secs(30),
            downlink_only_timeout: Duration::from_secs(30),
            max_connections: MaxConnections::Fixed(10_000),
            panel_ip_version: IpVersion::V4,
        };
        (cli, temp_dir)
    }

    #[test]
    fn test_cli_args_validate_success() {
        let (cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_cli_args_validate_empty_server_host() {
        let mut cli = create_test_cli_args();
        cli.server_host = "".to_string();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_zero_port() {
        let mut cli = create_test_cli_args();
        cli.port = 0;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_invalid_node_id() {
        let mut cli = create_test_cli_args();
        cli.node = 0;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_cli_args_validate_ca_file_not_found() {
        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.ca_file = Some("/nonexistent/ca.pem".to_string());
        assert!(cli.validate().is_err());
    }

    // ── CongestionControl ────────────────────────────────────────────────────

    #[test]
    fn test_congestion_control_default_is_bbr() {
        let cc = CongestionControl::default();
        assert_eq!(cc, CongestionControl::Bbr);
    }

    #[test]
    fn test_congestion_control_deserialize_bbr() {
        let cc: CongestionControl = serde_json::from_str(r#""bbr""#).unwrap();
        assert_eq!(cc, CongestionControl::Bbr);
    }

    #[test]
    fn test_congestion_control_deserialize_cubic() {
        let cc: CongestionControl = serde_json::from_str(r#""cubic""#).unwrap();
        assert_eq!(cc, CongestionControl::Cubic);
    }

    #[test]
    fn test_congestion_control_deserialize_new_reno() {
        let cc: CongestionControl = serde_json::from_str(r#""new_reno""#).unwrap();
        assert_eq!(cc, CongestionControl::NewReno);
    }

    #[test]
    fn test_congestion_control_unknown_value_fails() {
        let result: Result<CongestionControl, _> = serde_json::from_str(r#""invalid""#);
        assert!(
            result.is_err(),
            "unknown congestion control value must fail"
        );
    }

    // ── NaiveConfig congestion_control ───────────────────────────────────────

    #[test]
    fn test_parse_naive_config_success() {
        let json = r#"{"server_port":443}"#;
        let config_enum = NodeConfigEnum::Naive(json.to_string());
        let config = parse_naive_config(config_enum).unwrap();
        assert_eq!(config.server_port, 443);
        assert_eq!(config.network, NaiveNetwork::Tcp);
        assert_eq!(config.congestion_control, CongestionControl::Bbr); // defaults to bbr
    }

    #[test]
    fn test_parse_naive_config_with_network() {
        let json = r#"{"server_port":443,"network":"udp"}"#;
        let config_enum = NodeConfigEnum::Naive(json.to_string());
        let config = parse_naive_config(config_enum).unwrap();
        assert_eq!(config.server_port, 443);
        assert_eq!(config.network, NaiveNetwork::Udp);
        assert_eq!(config.congestion_control, CongestionControl::Bbr); // still defaults
    }

    #[test]
    fn test_parse_naive_config_with_congestion_control_bbr() {
        let json = r#"{"server_port":443,"network":"udp","congestion_control":"bbr"}"#;
        let config = parse_naive_config(NodeConfigEnum::Naive(json.to_string())).unwrap();
        assert_eq!(config.congestion_control, CongestionControl::Bbr);
    }

    #[test]
    fn test_parse_naive_config_with_congestion_control_cubic() {
        let json = r#"{"server_port":443,"network":"udp","congestion_control":"cubic"}"#;
        let config = parse_naive_config(NodeConfigEnum::Naive(json.to_string())).unwrap();
        assert_eq!(config.congestion_control, CongestionControl::Cubic);
    }

    #[test]
    fn test_parse_naive_config_with_congestion_control_new_reno() {
        let json = r#"{"server_port":443,"network":"udp","congestion_control":"new_reno"}"#;
        let config = parse_naive_config(NodeConfigEnum::Naive(json.to_string())).unwrap();
        assert_eq!(config.congestion_control, CongestionControl::NewReno);
    }

    // ── ServerConfig propagation ─────────────────────────────────────────────

    #[test]
    fn test_parse_naive_config_wrong_variant() {
        let config_enum = NodeConfigEnum::Trojan("{}".to_string());
        assert!(parse_naive_config(config_enum).is_err());
    }

    #[test]
    fn test_server_config_from_remote() {
        let remote = NaiveConfig {
            server_port: 443,
            network: NaiveNetwork::Tcp,
            congestion_control: CongestionControl::Bbr,
        };
        let cli = create_test_cli_args();
        let config = ServerConfig::from_remote(&remote, &cli).unwrap();
        assert_eq!(config.port, 443);
        assert!(config.cert.is_some());
        assert!(config.key.is_some());
        assert_eq!(config.congestion_control, CongestionControl::Bbr);
    }

    #[test]
    fn test_server_config_propagates_cubic() {
        let remote = NaiveConfig {
            server_port: 443,
            network: NaiveNetwork::Udp,
            congestion_control: CongestionControl::Cubic,
        };
        let config = ServerConfig::from_remote(&remote, &create_test_cli_args()).unwrap();
        assert_eq!(config.congestion_control, CongestionControl::Cubic);
    }

    #[test]
    fn test_conn_config_from_cli() {
        let cli = create_test_cli_args();
        let config = ConnConfig::from_cli(&cli, 10_000);
        assert_eq!(config.max_connections, 10_000);
        assert_eq!(config.idle_timeout_secs(), 300);
        assert_eq!(config.uplink_only_timeout_secs(), 30);
        assert_eq!(config.downlink_only_timeout_secs(), 30);
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
        assert!(parse_duration("invalid").is_err());
    }

    #[test]
    fn test_parse_ip_version_valid() {
        assert_eq!(parse_ip_version("v4").unwrap(), IpVersion::V4);
        assert_eq!(parse_ip_version("v6").unwrap(), IpVersion::V6);
        assert_eq!(parse_ip_version("auto").unwrap(), IpVersion::Auto);
    }

    #[test]
    fn test_parse_ip_version_invalid() {
        assert!(parse_ip_version("invalid").is_err());
    }

    #[test]
    fn test_validate_rejects_invalid_log_mode() {
        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        cli.log_mode = "foobar".to_string();
        assert!(
            cli.validate().is_err(),
            "validate() must reject unknown log_mode values"
        );
    }

    #[test]
    fn test_validate_accepts_valid_log_modes() {
        let (mut cli, _temp_dir) = create_test_cli_args_with_temp_certs();
        for mode in &["trace", "debug", "info", "warn", "error"] {
            cli.log_mode = mode.to_string();
            assert!(
                cli.validate().is_ok(),
                "log_mode '{}' should be valid",
                mode
            );
        }
    }
}
