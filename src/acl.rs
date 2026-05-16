//! ACL (Access Control List) Engine integration
//!
//! Provides rule-based traffic routing with support for:
//! - Direct connections
//! - SOCKS5 proxy
//! - HTTP/HTTPS proxy
//! - Reject (block) connections
//!
//! Configuration format (YAML):
//! ```yaml
//! outbounds:
//!   - name: warp
//!     type: socks5
//!     socks5:
//!       addr: 127.0.0.1:40000
//!   - name: http-proxy
//!     type: http
//!     http:
//!       addr: 127.0.0.1:8080
//! acl:
//!   inline:
//!     - reject(all, udp/443)
//!     - warp(suffix:google.com)
//!     - direct(all)
//! ```

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use dns_cache_rs::DnsCache;
use serde::{Deserialize, Serialize};

pub use acl_engine_rs::{
    geo::{AutoGeoLoader, GeoIpFormat, GeoSiteFormat, NilGeoLoader},
    outbound::{
        Addr, AsyncOutbound, AsyncTcpConn, AsyncUdpConn, Direct, DirectMode, DirectOptions, Http,
        Reject, Socks5,
    },
    HostInfo, Protocol,
};

use crate::logger::log;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    #[serde(default)]
    pub outbounds: Vec<OutboundEntry>,
    #[serde(default)]
    pub acl: AclRules,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclRules {
    #[serde(default)]
    pub inline: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub outbound_type: String,
    #[serde(default)]
    pub socks5: Option<Socks5Config>,
    #[serde(default)]
    pub http: Option<HttpConfig>,
    #[serde(default)]
    pub direct: Option<DirectConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    pub addr: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_allow_udp")]
    pub allow_udp: bool,
}

fn default_allow_udp() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub addr: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub https: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectConfig {
    #[serde(default = "default_ip_mode")]
    pub mode: String,
    #[serde(rename = "bindIPv4", default)]
    pub bind_ipv4: Option<String>,
    #[serde(rename = "bindIPv6", default)]
    pub bind_ipv6: Option<String>,
    #[serde(rename = "bindDevice", default)]
    pub bind_device: Option<String>,
    #[serde(rename = "fastOpen", default)]
    pub fast_open: bool,
    #[serde(rename = "tcpNoDelay", default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,
    #[serde(rename = "tcpKeepAlive", default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
}

fn default_ip_mode() -> String {
    "auto".to_string()
}

fn default_tcp_nodelay() -> bool {
    true
}

fn default_tcp_keepalive_secs() -> u64 {
    60
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            mode: default_ip_mode(),
            bind_ipv4: None,
            bind_ipv6: None,
            bind_device: None,
            fast_open: false,
            tcp_nodelay: default_tcp_nodelay(),
            tcp_keepalive_secs: default_tcp_keepalive_secs(),
        }
    }
}

#[derive(Clone)]
pub enum OutboundHandler {
    Direct(Arc<Direct>),
    Socks5 { inner: Arc<Socks5>, allow_udp: bool },
    Http(Arc<Http>),
    Reject(Arc<Reject>),
}

impl std::fmt::Debug for OutboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundHandler::Direct(_) => write!(f, "Direct"),
            OutboundHandler::Socks5 { allow_udp, .. } => write!(f, "Socks5(udp={})", allow_udp),
            OutboundHandler::Http(_) => write!(f, "Http"),
            OutboundHandler::Reject(_) => write!(f, "Reject"),
        }
    }
}

impl OutboundHandler {
    pub fn from_entry(entry: &OutboundEntry) -> Result<Self> {
        match entry.outbound_type.as_str() {
            "direct" => {
                let config = entry.direct.as_ref();
                let mode = config.map(|d| d.mode.as_str()).unwrap_or("auto");

                let direct_mode = match mode {
                    "auto" => DirectMode::Auto,
                    "4" | "only4" => DirectMode::Only4,
                    "6" | "only6" => DirectMode::Only6,
                    "prefer4" | "46" => DirectMode::Prefer46,
                    "prefer6" | "64" => DirectMode::Prefer64,
                    _ => {
                        return Err(anyhow!(
                            "Invalid direct mode '{}' for outbound '{}', \
                             valid values: auto, 4, only4, 6, only6, prefer4, 46, prefer6, 64",
                            mode,
                            entry.name
                        ));
                    }
                };

                let bind_ip4 = config
                    .and_then(|d| d.bind_ipv4.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv4Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv4 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_ip6 = config
                    .and_then(|d| d.bind_ipv6.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv6Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv6 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_device = config.and_then(|d| d.bind_device.clone());
                let fast_open = config.is_some_and(|d| d.fast_open);
                let tcp_nodelay =
                    config.map(|d| d.tcp_nodelay).unwrap_or_else(default_tcp_nodelay);
                let tcp_keepalive_secs = config
                    .map(|d| d.tcp_keepalive_secs)
                    .unwrap_or_else(default_tcp_keepalive_secs);
                let tcp_keepalive = if tcp_keepalive_secs > 0 {
                    Some(std::time::Duration::from_secs(tcp_keepalive_secs))
                } else {
                    None
                };

                if let Some(ip) = bind_ip4 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!("FATAL: outbound '{}' bindIPv4 {} failed: {}", entry.name, ip, e)
                    })?;
                }
                if let Some(ip) = bind_ip6 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!("FATAL: outbound '{}' bindIPv6 {} failed: {}", entry.name, ip, e)
                    })?;
                }

                #[cfg(target_os = "linux")]
                if let Some(ref device) = bind_device {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    socket.bind_device(Some(device.as_bytes())).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindDevice '{}' failed: {}",
                            entry.name,
                            device,
                            e
                        )
                    })?;
                }
                #[cfg(not(target_os = "linux"))]
                if let Some(ref device) = bind_device {
                    return Err(anyhow!(
                        "FATAL: outbound '{}' bindDevice '{}' is only supported on Linux",
                        entry.name,
                        device
                    ));
                }

                let opts = DirectOptions {
                    mode: direct_mode,
                    bind_ip4,
                    bind_ip6,
                    bind_device,
                    fast_open,
                    timeout: None,
                    tcp_nodelay,
                    tcp_keepalive,
                };
                let direct = Direct::with_options(opts)
                    .map_err(|e| anyhow!("Invalid direct outbound '{}': {}", entry.name, e))?;

                let mut parts = vec![format!("mode={}", mode)];
                if let Some(ip) = bind_ip4 {
                    parts.push(format!("bindIPv4={}", ip));
                }
                if let Some(ip) = bind_ip6 {
                    parts.push(format!("bindIPv6={}", ip));
                }
                if let Some(ref dev) = config.and_then(|d| d.bind_device.as_ref()) {
                    parts.push(format!("bindDevice={}", dev));
                }
                if fast_open {
                    parts.push("fastOpen=true".to_string());
                }
                if !tcp_nodelay {
                    parts.push("tcpNoDelay=false".to_string());
                }
                if let Some(ka) = tcp_keepalive {
                    if ka.as_secs() != 60 {
                        parts.push(format!("tcpKeepAlive={}s", ka.as_secs()));
                    }
                } else {
                    parts.push("tcpKeepAlive=off".to_string());
                }
                log::info!(
                    outbound = %entry.name,
                    "Direct outbound configured: {}",
                    parts.join(", ")
                );

                Ok(OutboundHandler::Direct(Arc::new(direct)))
            }
            "socks5" => {
                let config = entry.socks5.as_ref().ok_or_else(|| {
                    anyhow!("socks5 config required for outbound '{}'", entry.name)
                })?;

                let socks5 = if let (Some(username), Some(password)) =
                    (&config.username, &config.password)
                {
                    Socks5::with_auth(&config.addr, username, password)
                        .map_err(|e| anyhow!("Invalid socks5 outbound '{}': {}", entry.name, e))?
                } else {
                    Socks5::new(&config.addr)
                };

                Ok(OutboundHandler::Socks5 {
                    inner: Arc::new(socks5),
                    allow_udp: config.allow_udp,
                })
            }
            "http" => {
                let config = entry
                    .http
                    .as_ref()
                    .ok_or_else(|| anyhow!("http config required for outbound '{}'", entry.name))?;

                let mut http = if config.https {
                    Http::try_new(&config.addr, true)
                        .map_err(|e| anyhow!("Invalid http outbound '{}': {}", entry.name, e))?
                } else {
                    Http::new(&config.addr)
                };

                if let (Some(username), Some(password)) = (&config.username, &config.password) {
                    http = http.with_auth(username, password);
                }

                Ok(OutboundHandler::Http(Arc::new(http)))
            }
            "reject" => Ok(OutboundHandler::Reject(Arc::new(Reject::new()))),
            unknown => Err(anyhow!(
                "Unknown outbound type '{}' for outbound '{}'",
                unknown,
                entry.name
            )),
        }
    }

    #[allow(dead_code)]
    pub fn is_reject(&self) -> bool {
        matches!(self, OutboundHandler::Reject(_))
    }

    #[allow(dead_code)]
    pub fn allows_udp(&self) -> bool {
        match self {
            OutboundHandler::Direct(_) => true,
            OutboundHandler::Socks5 { allow_udp, .. } => *allow_udp,
            OutboundHandler::Http(_) => false,
            OutboundHandler::Reject(_) => false,
        }
    }
}

#[async_trait]
impl AsyncOutbound for OutboundHandler {
    async fn dial_tcp(&self, addr: &mut Addr) -> acl_engine_rs::Result<Box<dyn AsyncTcpConn>> {
        match self {
            OutboundHandler::Direct(d) => d.dial_tcp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_tcp(addr).await,
            OutboundHandler::Http(h) => h.dial_tcp(addr).await,
            OutboundHandler::Reject(r) => r.dial_tcp(addr).await,
        }
    }

    async fn dial_udp(&self, addr: &mut Addr) -> acl_engine_rs::Result<Box<dyn AsyncUdpConn>> {
        match self {
            OutboundHandler::Direct(d) => d.dial_udp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_udp(addr).await,
            OutboundHandler::Http(h) => h.dial_udp(addr).await,
            OutboundHandler::Reject(r) => r.dial_udp(addr).await,
        }
    }
}

pub struct AclEngine {
    compiled: acl_engine_rs::CompiledRuleSet<Arc<OutboundHandler>>,
    #[allow(dead_code)]
    outbounds: HashMap<String, Arc<OutboundHandler>>,
}

impl AclEngine {
    pub async fn new(
        config: AclConfig,
        data_dir: Option<&Path>,
        refresh_geodata: bool,
    ) -> Result<Self> {
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();

        for entry in &config.outbounds {
            let handler = OutboundHandler::from_entry(entry)?;
            log::info!(outbound = %entry.name, outbound_type = %entry.outbound_type, "Loaded outbound");
            outbounds.insert(entry.name.clone(), Arc::new(handler));
        }

        outbounds
            .entry("reject".to_string())
            .or_insert_with(|| Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))));
        outbounds
            .entry("direct".to_string())
            .or_insert_with(|| Arc::new(OutboundHandler::Direct(Arc::new(Direct::new()))));

        let rules = if config.acl.inline.is_empty() {
            vec!["direct(all)".to_string()]
        } else {
            config.acl.inline.clone()
        };

        let rules_text = rules.join("\n");
        let text_rules = acl_engine_rs::parse_rules(&rules_text)
            .map_err(|e| anyhow!("Failed to parse ACL rules: {}", e))?;

        let mut geo_loader = if let Some(dir) = data_dir {
            AutoGeoLoader::new()
                .with_data_dir(dir)
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        } else {
            AutoGeoLoader::new()
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        };

        if refresh_geodata {
            use std::time::Duration;
            geo_loader = geo_loader.with_update_interval(Duration::ZERO);
            log::info!("Geo data refresh requested, will download latest files");
        }

        let compiled = acl_engine_rs::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(4096).unwrap(),
            &geo_loader,
        )
        .map_err(|e| anyhow!("Failed to compile ACL rules: {}", e))?;

        log::info!(
            outbounds = outbounds.len(),
            rules = compiled.rule_count(),
            "ACL engine initialized"
        );

        Ok(Self { compiled, outbounds })
    }

    #[allow(dead_code)]
    pub fn new_default() -> Result<Self> {
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();
        outbounds.insert(
            "direct".to_string(),
            Arc::new(OutboundHandler::Direct(Arc::new(Direct::new()))),
        );
        outbounds.insert(
            "reject".to_string(),
            Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))),
        );

        let text_rules = acl_engine_rs::parse_rules("direct(all)")
            .map_err(|e| anyhow!("Failed to parse default rules: {}", e))?;

        let compiled = acl_engine_rs::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(1024).unwrap(),
            &NilGeoLoader,
        )
        .map_err(|e| anyhow!("Failed to compile default rules: {}", e))?;

        Ok(Self { compiled, outbounds })
    }

    pub fn match_host(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
    ) -> Option<Arc<OutboundHandler>> {
        let host_info = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            HostInfo::from_ip(ip)
        } else {
            HostInfo::from_name(host)
        };

        match self.compiled.match_host(&host_info, protocol, port) {
            Some(result) => Some(result.outbound.clone()),
            None => self.outbounds.get("direct").cloned(),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.compiled.rule_count()
    }
}

pub async fn load_acl_config(path: &Path) -> Result<AclConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| anyhow!("Failed to read ACL config file '{}': {}", path.display(), e))?;

    let config: AclConfig = serde_yaml::from_str(&content).map_err(|e| {
        anyhow!("Failed to parse ACL config file '{}': {}", path.display(), e)
    })?;

    Ok(config)
}

pub struct AclRouter {
    engine: AclEngine,
    block_private_ip: bool,
    dns_cache: DnsCache,
}

impl AclRouter {
    pub fn with_cache(engine: AclEngine, block_private_ip: bool, dns_cache: DnsCache) -> Self {
        Self { engine, block_private_ip, dns_cache }
    }
}

#[async_trait]
impl crate::core::hooks::OutboundRouter for AclRouter {
    async fn route(&self, addr: &crate::core::Address) -> crate::core::hooks::OutboundType {
        let mut resolved_addr: Option<std::net::SocketAddr> = None;

        if self.block_private_ip {
            let (is_private, resolved) =
                crate::core::dns::check_private_and_resolve(&self.dns_cache, addr).await;
            if is_private {
                log::debug!(target = %addr, "Blocked private address");
                return crate::core::hooks::OutboundType::Reject;
            }
            resolved_addr = resolved;
        }

        let host = addr.host();
        let port = addr.port();

        self.route_host_with_resolved(&host, port, resolved_addr)
    }
}

impl AclRouter {
    fn route_host_with_resolved(
        &self,
        host: &str,
        port: u16,
        resolved: Option<std::net::SocketAddr>,
    ) -> crate::core::hooks::OutboundType {
        match self.engine.match_host(host, port, Protocol::TCP) {
            Some(handler) => match &*handler {
                OutboundHandler::Direct(_) => crate::core::hooks::OutboundType::Direct {
                    resolved,
                    handler: Some(handler),
                },
                OutboundHandler::Socks5 { .. } | OutboundHandler::Http(_) => {
                    crate::core::hooks::OutboundType::Proxy(handler)
                }
                OutboundHandler::Reject(_) => crate::core::hooks::OutboundType::Reject,
            },
            None => crate::core::hooks::OutboundType::Direct { resolved, handler: None },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acl_config() {
        let yaml = r#"
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      allow_udp: true
  - name: http-proxy
    type: http
    http:
      addr: 127.0.0.1:8080
      https: false
acl:
  inline:
    - reject(all, udp/443)
    - warp(suffix:google.com)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.outbounds[0].name, "warp");
        assert_eq!(config.acl.inline.len(), 3);
    }

    #[test]
    fn test_outbound_handler_from_entry_direct() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig { mode: "auto".to_string(), ..Default::default() }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct(_)));
    }

    #[test]
    fn test_outbound_handler_from_entry_reject() {
        let entry = OutboundEntry {
            name: "block".to_string(),
            outbound_type: "reject".to_string(),
            socks5: None,
            http: None,
            direct: None,
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(handler.is_reject());
    }

    #[tokio::test]
    async fn test_acl_engine_default() {
        let engine = AclEngine::new_default().unwrap();
        let handler = engine.match_host("example.com", 80, Protocol::TCP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());
    }

    #[tokio::test]
    async fn test_acl_router_blocks_private() {
        use crate::core::hooks::OutboundRouter;
        use crate::core::Address;

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_cache(engine, true, dns_cache_rs::DnsCache::new());

        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, crate::core::hooks::OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_acl_router_allows_public() {
        use crate::core::hooks::OutboundRouter;
        use crate::core::Address;

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_cache(engine, true, dns_cache_rs::DnsCache::new());

        let addr = Address::IPv4([8, 8, 8, 8], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, crate::core::hooks::OutboundType::Direct { .. }));
    }
}
