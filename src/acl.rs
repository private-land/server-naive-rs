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
        Reject, ResolveInfo, Socks5,
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

    /// Connect timeout in seconds for this outbound. 0 = use the built-in
    /// default (10s).
    #[serde(rename = "connectTimeout", default)]
    pub connect_timeout_secs: u64,
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
            connect_timeout_secs: 0,
        }
    }
}

#[derive(Clone)]
pub enum OutboundHandler {
    /// Direct connection. `custom_dial` is true when the outbound sets any
    /// dialing option a bare `connect`/`TcpStream::connect` cannot apply —
    /// bindIPv4/bindIPv6/bindDevice, a non-`auto` IP mode, TCP Fast Open, a
    /// non-default TCP_NODELAY, a non-default keepalive, or a non-default
    /// connect timeout — so the router routes such handlers through their own
    /// dialer (`inner`).
    Direct {
        inner: Arc<Direct>,
        custom_dial: bool,
    },
    Socks5 {
        inner: Arc<Socks5>,
        allow_udp: bool,
    },
    Http(Arc<Http>),
    Reject(Arc<Reject>),
}

impl std::fmt::Debug for OutboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundHandler::Direct { .. } => write!(f, "Direct"),
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
                let tcp_nodelay = config
                    .map(|d| d.tcp_nodelay)
                    .unwrap_or_else(default_tcp_nodelay);
                let tcp_keepalive_secs = config
                    .map(|d| d.tcp_keepalive_secs)
                    .unwrap_or_else(default_tcp_keepalive_secs);
                let tcp_keepalive = if tcp_keepalive_secs > 0 {
                    Some(std::time::Duration::from_secs(tcp_keepalive_secs))
                } else {
                    None
                };
                let connect_timeout_secs = config.map(|d| d.connect_timeout_secs).unwrap_or(0);
                let connect_timeout = if connect_timeout_secs > 0 {
                    Some(std::time::Duration::from_secs(connect_timeout_secs))
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
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv4 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
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
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv6 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
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

                // Options a bare connect cannot apply; when any is set the router
                // must dial through this handler instead. The bare path always
                // forces TCP_NODELAY on, applies its own fixed keepalive, never
                // enables TFO, and uses the global connect timeout, so any
                // non-default here diverges from it.
                let custom_dial = bind_ip4.is_some()
                    || bind_ip6.is_some()
                    || bind_device.is_some()
                    || direct_mode != DirectMode::Auto
                    || fast_open
                    || !tcp_nodelay
                    || tcp_keepalive_secs != default_tcp_keepalive_secs()
                    || connect_timeout.is_some();

                let opts = DirectOptions {
                    mode: direct_mode,
                    bind_ip4,
                    bind_ip6,
                    bind_device,
                    fast_open,
                    timeout: connect_timeout,
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
                if let Some(ct) = connect_timeout {
                    parts.push(format!("connectTimeout={}s", ct.as_secs()));
                }
                log::info!(
                    outbound = %entry.name,
                    "Direct outbound configured: {}",
                    parts.join(", ")
                );

                Ok(OutboundHandler::Direct {
                    inner: Arc::new(direct),
                    custom_dial,
                })
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

    /// For a `direct` outbound carrying custom dialing options, return the
    /// dialer to route through so those options are applied; otherwise `None`.
    /// Plain direct outbounds return `None` and keep using the bare connect path.
    fn custom_dialer(self: &Arc<Self>) -> Option<Arc<OutboundHandler>> {
        match self.as_ref() {
            OutboundHandler::Direct {
                custom_dial: true, ..
            } => Some(self.clone()),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn allows_udp(&self) -> bool {
        match self {
            OutboundHandler::Direct { .. } => true,
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
            OutboundHandler::Direct { inner, .. } => inner.dial_tcp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_tcp(addr).await,
            OutboundHandler::Http(h) => h.dial_tcp(addr).await,
            OutboundHandler::Reject(r) => r.dial_tcp(addr).await,
        }
    }

    async fn dial_udp(&self, addr: &mut Addr) -> acl_engine_rs::Result<Box<dyn AsyncUdpConn>> {
        match self {
            OutboundHandler::Direct { inner, .. } => inner.dial_udp(addr).await,
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
        outbounds.entry("direct".to_string()).or_insert_with(|| {
            Arc::new(OutboundHandler::Direct {
                inner: Arc::new(Direct::new()),
                custom_dial: false,
            })
        });

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

        Ok(Self {
            compiled,
            outbounds,
        })
    }

    #[allow(dead_code)]
    pub fn new_default() -> Result<Self> {
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();
        outbounds.insert(
            "direct".to_string(),
            Arc::new(OutboundHandler::Direct {
                inner: Arc::new(Direct::new()),
                custom_dial: false,
            }),
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

        Ok(Self {
            compiled,
            outbounds,
        })
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
        anyhow!(
            "Failed to parse ACL config file '{}': {}",
            path.display(),
            e
        )
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
        Self {
            engine,
            block_private_ip,
            dns_cache,
        }
    }
}

#[async_trait]
impl crate::core::hooks::OutboundRouter for AclRouter {
    async fn route(&self, addr: &crate::core::Address) -> crate::core::hooks::OutboundType {
        let mut resolved: Option<Arc<[std::net::IpAddr]>> = None;

        if self.block_private_ip {
            let (is_private, ips) =
                crate::core::dns::check_private_and_resolve(&self.dns_cache, addr).await;
            if is_private {
                log::debug!(target = %addr, "Blocked private address");
                return crate::core::hooks::OutboundType::Reject;
            }
            resolved = ips;
        }

        self.route_addr_with_resolved(addr, resolved)
    }
}

impl AclRouter {
    fn route_addr_with_resolved(
        &self,
        addr: &crate::core::Address,
        resolved: Option<Arc<[std::net::IpAddr]>>,
    ) -> crate::core::hooks::OutboundType {
        let host = addr.host();
        let port = addr.port();
        match self.engine.match_host(&host, port, Protocol::TCP) {
            Some(handler) => match &*handler {
                // A `direct` handler with custom dialing options is dialed
                // through the handler so its bind/mode/TCP options apply; a plain
                // direct handler keeps the bare connect path (`dialer: None`).
                // The already-SSRF-checked `resolved` rides along either way.
                OutboundHandler::Direct { .. } => {
                    self.direct_decision(addr, resolved, handler.custom_dialer())
                }
                OutboundHandler::Socks5 { .. } | OutboundHandler::Http(_) => {
                    crate::core::hooks::OutboundType::Proxy(handler)
                }
                OutboundHandler::Reject(_) => crate::core::hooks::OutboundType::Reject,
            },
            None => self.direct_decision(addr, resolved, None),
        }
    }

    /// Build a `Direct` decision, failing closed on the SSRF hole: under
    /// `block_private_ip`, a direct **domain** the server could not resolve (so
    /// could not private-IP check) must be rejected rather than handed to a
    /// connect/dialer path that would re-resolve it through an unchecked
    /// resolver (acl-engine's system `lookup_host`) and possibly land on a
    /// private IP. IP literals were already checked; proxy targets never reach
    /// here (the proxy resolves the name itself).
    fn direct_decision(
        &self,
        addr: &crate::core::Address,
        resolved: Option<Arc<[std::net::IpAddr]>>,
        dialer: Option<Arc<OutboundHandler>>,
    ) -> crate::core::hooks::OutboundType {
        if self.block_private_ip
            && resolved.is_none()
            && matches!(addr, crate::core::Address::Domain(..))
        {
            log::debug!(target = %addr, "Blocked unresolved direct domain (fail-closed)");
            return crate::core::hooks::OutboundType::Reject;
        }
        crate::core::hooks::OutboundType::Direct { resolved, dialer }
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
            direct: Some(DirectConfig {
                mode: "auto".to_string(),
                ..Default::default()
            }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct { .. }));
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
        assert!(matches!(
            result,
            crate::core::hooks::OutboundType::Direct { .. }
        ));
    }

    // ---------------------------------------------------------------
    // Custom-dial direct: mode/bind/fastOpen options must be applied by
    // dialing through the handler, so the router must surface a `dialer`.
    // Plain direct must keep the bare connect path (`dialer: None`).
    // -----------------------------------------------------------------

    use crate::core::hooks::{OutboundRouter, OutboundType};
    use crate::core::Address;

    fn mock_cache_with(
        host: &str,
        result: Result<Vec<std::net::IpAddr>, dns_cache_rs::DnsError>,
    ) -> DnsCache {
        let mock = std::sync::Arc::new(dns_cache_rs::MockResolver::new());
        mock.set(host, result);
        DnsCache::builder()
            .resolver_arc(mock as std::sync::Arc<dyn dns_cache_rs::Resolver>)
            .query_timeout(Some(std::time::Duration::from_millis(100)))
            .build()
            .expect("DnsCache build")
    }

    /// Build an `AclEngine` whose only rule (`bound(all)`) routes every host to
    /// a single custom `direct` outbound built from `direct`.
    async fn engine_with_bound_direct(direct: DirectConfig) -> AclEngine {
        let config = AclConfig {
            outbounds: vec![OutboundEntry {
                name: "bound".to_string(),
                outbound_type: "direct".to_string(),
                socks5: None,
                http: None,
                direct: Some(direct),
            }],
            acl: AclRules {
                inline: vec!["bound(all)".to_string()],
            },
        };
        AclEngine::new(config, None, false)
            .await
            .expect("engine builds")
    }

    /// A `direct` outbound with `bindIPv4` must be dialed through the handler so
    /// the bind is applied — surfaced as `Direct { dialer: Some(_) }`.
    #[tokio::test]
    async fn custom_bind_direct_carries_dialer() {
        let engine = engine_with_bound_direct(DirectConfig {
            bind_ipv4: Some("127.0.0.1".to_string()),
            ..Default::default()
        })
        .await;
        let router = AclRouter::with_cache(engine, true, DnsCache::new());

        let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;

        match result {
            OutboundType::Direct {
                dialer: Some(_), ..
            } => {}
            other => panic!("custom-bind direct must carry a dialer, got {other:?}"),
        }
    }

    /// A custom-dial direct outbound targeting a domain must hand the handler the
    /// router's already-SSRF-checked IPs (`resolved`) so it binds without
    /// re-resolving — otherwise a rebinding domain could reach an unchecked,
    /// private IP (SSRF). Both the dialer AND the checked resolution must ride
    /// along.
    #[tokio::test]
    async fn custom_dial_direct_domain_carries_checked_ips() {
        use std::net::{IpAddr, Ipv4Addr};
        let public_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let cache = mock_cache_with("target.test", Ok(vec![public_ip]));
        let engine = engine_with_bound_direct(DirectConfig {
            bind_ipv4: Some("127.0.0.1".to_string()),
            ..Default::default()
        })
        .await;
        let router = AclRouter::with_cache(engine, true, cache);

        let result = router
            .route(&Address::Domain("target.test".to_string(), 443))
            .await;

        match result {
            OutboundType::Direct {
                resolved: Some(ips),
                dialer: Some(_),
            } => assert_eq!(*ips, [public_ip], "handler must receive the checked IPs"),
            other => panic!("expected Direct with checked IPs and a dialer, got {other:?}"),
        }
    }

    /// A dual-stack domain must surface BOTH families in `resolved` so the
    /// custom-dial handler can fall back from the preferred family to the other
    /// (mode 64/46). Before the fix the router collapsed resolution to a single
    /// address, defeating the fallback.
    #[tokio::test]
    async fn custom_dial_direct_dual_stack_carries_both_families() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let cache = mock_cache_with("dual.test", Ok(vec![v6, v4]));
        let engine = engine_with_bound_direct(DirectConfig {
            mode: "64".to_string(),
            ..Default::default()
        })
        .await;
        let router = AclRouter::with_cache(engine, true, cache);

        let result = router
            .route(&Address::Domain("dual.test".to_string(), 443))
            .await;

        match result {
            OutboundType::Direct {
                resolved: Some(ips),
                dialer: Some(_),
            } => {
                assert!(ips.contains(&v4), "v4 must survive to the dialer");
                assert!(ips.contains(&v6), "v6 must survive to the dialer");
            }
            other => panic!("expected dual-stack Direct with a dialer, got {other:?}"),
        }
    }

    /// The SSRF guard must still reject a custom-dial direct outbound whose
    /// domain resolves to a private IP — the private-IP block runs before the
    /// dialer is attached.
    #[tokio::test]
    async fn custom_dial_direct_rejects_private_resolution() {
        use std::net::{IpAddr, Ipv4Addr};
        let cache = mock_cache_with(
            "evil.test",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]),
        );
        let engine = engine_with_bound_direct(DirectConfig {
            bind_ipv4: Some("127.0.0.1".to_string()),
            ..Default::default()
        })
        .await;
        let router = AclRouter::with_cache(engine, true, cache);

        let result = router
            .route(&Address::Domain("evil.test".to_string(), 443))
            .await;

        assert!(matches!(result, OutboundType::Reject), "got {result:?}");
    }

    /// `fastOpen`/`tcpNoDelay`/`mode` are also options `connect` cannot honor, so
    /// a direct outbound setting any of them (even with no bind) must route
    /// through the handler.
    #[tokio::test]
    async fn direct_with_non_default_tcp_options_carries_dialer() {
        for direct in [
            DirectConfig {
                fast_open: true,
                ..Default::default()
            },
            DirectConfig {
                tcp_nodelay: false,
                ..Default::default()
            },
            DirectConfig {
                mode: "4".to_string(),
                ..Default::default()
            },
        ] {
            let label = format!("{direct:?}");
            let engine = engine_with_bound_direct(direct).await;
            let router = AclRouter::with_cache(engine, true, DnsCache::new());
            let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;
            assert!(
                matches!(
                    result,
                    OutboundType::Direct {
                        dialer: Some(_),
                        ..
                    }
                ),
                "config {label} must carry a dialer, got {result:?}"
            );
        }
    }

    /// A non-default connect timeout is a dialing option the bare connect path
    /// cannot apply, so it must route through the outbound's own dialer.
    #[tokio::test]
    async fn direct_with_custom_connect_timeout_carries_dialer() {
        let direct = DirectConfig {
            connect_timeout_secs: 5,
            ..Default::default()
        };
        let engine = engine_with_bound_direct(direct).await;
        let router = AclRouter::with_cache(engine, true, DnsCache::new());
        let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;
        assert!(
            matches!(
                result,
                OutboundType::Direct {
                    dialer: Some(_),
                    ..
                }
            ),
            "custom connectTimeout must carry a dialer, got {result:?}"
        );
    }

    /// Guard: a plain `direct` outbound (all defaults) must keep the bare connect
    /// path — `Direct { dialer: None }`. `match_host` falls back to the `direct`
    /// handler for unmatched traffic, so routing every Direct handler through the
    /// dialer would change the default path for every connection.
    #[tokio::test]
    async fn plain_direct_carries_no_dialer() {
        let engine = AclEngine::new_default().expect("default engine builds");
        let router = AclRouter::with_cache(engine, true, DnsCache::new());

        let result = router.route(&Address::IPv4([1, 2, 3, 4], 443)).await;

        assert!(
            matches!(result, OutboundType::Direct { dialer: None, .. }),
            "plain direct must stay on the bare connect path, got {result:?}"
        );
    }

    /// Fail-closed SSRF guard: a `direct` domain the server cannot resolve (so it
    /// cannot run the private-IP check) must be rejected under `block_private_ip`
    /// — otherwise the connect path would re-resolve it through an unchecked
    /// resolver (acl-engine's system `lookup_host`), which could land on a
    /// private IP and bypass the guard.
    #[tokio::test]
    async fn direct_domain_dns_failure_rejected_under_block() {
        let cache = mock_cache_with(
            "flaky.test",
            Err(dns_cache_rs::DnsError::NotFound("flaky.test".into())),
        );
        let engine = AclEngine::new_default().expect("default engine builds");
        let router = AclRouter::with_cache(engine, true, cache);

        let result = router
            .route(&Address::Domain("flaky.test".to_string(), 443))
            .await;

        assert!(
            matches!(result, OutboundType::Reject),
            "unresolvable direct domain must fail closed, got {result:?}"
        );
    }

    /// With private-IP blocking disabled the fail-closed guard must NOT fire:
    /// an unresolvable direct domain still routes Direct (the connect path
    /// re-resolves at dial time, as before).
    #[tokio::test]
    async fn direct_domain_dns_failure_allowed_when_block_disabled() {
        let cache = mock_cache_with(
            "flaky.test",
            Err(dns_cache_rs::DnsError::NotFound("flaky.test".into())),
        );
        let engine = AclEngine::new_default().expect("default engine builds");
        let router = AclRouter::with_cache(engine, false, cache);

        let result = router
            .route(&Address::Domain("flaky.test".to_string(), 443))
            .await;

        assert!(
            matches!(result, OutboundType::Direct { .. }),
            "block disabled: unresolvable direct domain must stay Direct, got {result:?}"
        );
    }

    /// Regression guard: the fail-closed direct guard must NOT reject a domain
    /// destined for a PROXY outbound just because the server cannot resolve it —
    /// the proxy resolves the name itself. ACL matching happens before the guard.
    #[tokio::test]
    async fn proxy_domain_dns_failure_still_proxied() {
        let cache = mock_cache_with(
            "proxied.test",
            Err(dns_cache_rs::DnsError::NotFound("proxied.test".into())),
        );
        let config = AclConfig {
            outbounds: vec![OutboundEntry {
                name: "warp".to_string(),
                outbound_type: "socks5".to_string(),
                socks5: Some(Socks5Config {
                    addr: "127.0.0.1:40000".to_string(),
                    username: None,
                    password: None,
                    allow_udp: true,
                }),
                http: None,
                direct: None,
            }],
            acl: AclRules {
                inline: vec!["warp(all)".to_string()],
            },
        };
        let engine = AclEngine::new(config, None, false).await.expect("engine");
        let router = AclRouter::with_cache(engine, true, cache);

        let result = router
            .route(&Address::Domain("proxied.test".to_string(), 443))
            .await;

        assert!(
            matches!(result, OutboundType::Proxy(_)),
            "proxy-destined domain must not be rejected by the direct guard, got {result:?}"
        );
    }
}
