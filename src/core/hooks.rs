//! Hook traits for extensibility

use super::address::Address;
use async_trait::async_trait;
use dns_cache_rs::DnsCache;
use std::net::IpAddr;
use std::sync::Arc;

pub type UserId = i64;

/// Authenticator trait — synchronous for lock-free lookup on the hot path.
///
/// For Naive, the credential is the password from HTTP Basic Auth (UUID string).
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, credential: &str) -> Option<UserId>;
}

pub trait StatsCollector: Send + Sync {
    fn record_request(&self, user_id: UserId);
    fn record_upload(&self, user_id: UserId, bytes: u64);
    fn record_download(&self, user_id: UserId, bytes: u64);
}

#[async_trait]
pub trait OutboundRouter: Send + Sync {
    async fn route(&self, addr: &Address) -> OutboundType;
}

#[derive(Clone)]
pub enum OutboundType {
    /// Direct connection, optionally carrying the router's already-SSRF-checked
    /// resolved IPs (both families when available) so the connect path does not
    /// re-resolve to an unchecked address.
    ///
    /// `dialer` is set for a `direct` outbound with custom dialing options
    /// (bind/mode/fastOpen/nodelay/keepalive/connectTimeout) that the bare
    /// connect path cannot apply: the connect path dials through it, feeding it
    /// `resolved` via `ResolveInfo` so the handler binds and applies mode/family
    /// fallback without re-resolving. `None` means a plain direct connection.
    Direct {
        resolved: Option<Arc<[IpAddr]>>,
        dialer: Option<Arc<crate::acl::OutboundHandler>>,
    },
    Reject,
    Proxy(Arc<crate::acl::OutboundHandler>),
}

impl std::fmt::Debug for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundType::Direct { dialer: None, .. } => write!(f, "Direct"),
            OutboundType::Direct {
                dialer: Some(h), ..
            } => write!(f, "Direct({:?})", h),
            OutboundType::Reject => write!(f, "Reject"),
            OutboundType::Proxy(h) => write!(f, "Proxy({:?})", h),
        }
    }
}

/// Direct router — routes all traffic directly with optional private IP blocking
pub struct DirectRouter {
    block_private_ip: bool,
    dns_cache: DnsCache,
}

impl DirectRouter {
    pub fn with_cache(block_private_ip: bool, dns_cache: DnsCache) -> Self {
        Self {
            block_private_ip,
            dns_cache,
        }
    }
}

#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, addr: &Address) -> OutboundType {
        if self.block_private_ip {
            let (is_private, resolved) =
                crate::core::dns::check_private_and_resolve(&self.dns_cache, addr).await;
            if is_private {
                return OutboundType::Reject;
            }
            // Fail closed: a domain we could not resolve (so could not private-IP
            // check) must not fall through to a connect path that re-resolves it
            // through an unchecked resolver. IP literals were already checked.
            if resolved.is_none() && matches!(addr, Address::Domain(..)) {
                return OutboundType::Reject;
            }
            return OutboundType::Direct {
                resolved,
                dialer: None,
            };
        }
        OutboundType::Direct {
            resolved: None,
            dialer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn mock_cache_with(
        host: &str,
        result: Result<Vec<IpAddr>, dns_cache_rs::DnsError>,
    ) -> DnsCache {
        let mock = Arc::new(dns_cache_rs::MockResolver::new());
        mock.set(host, result);
        DnsCache::builder()
            .resolver_arc(mock as Arc<dyn dns_cache_rs::Resolver>)
            .build()
            .expect("DnsCache build")
    }

    #[tokio::test]
    async fn test_direct_router_blocks_loopback() {
        let router = DirectRouter::with_cache(true, DnsCache::new());
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        assert!(matches!(router.route(&addr).await, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_allows_public_ip() {
        let router = DirectRouter::with_cache(true, DnsCache::new());
        let addr = Address::IPv4([8, 8, 8, 8], 80);
        assert!(matches!(
            router.route(&addr).await,
            OutboundType::Direct {
                resolved: None,
                dialer: None
            }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_allows_private_when_disabled() {
        let router = DirectRouter::with_cache(false, DnsCache::new());
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        assert!(matches!(
            router.route(&addr).await,
            OutboundType::Direct {
                resolved: None,
                dialer: None
            }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_domain_resolving_to_private() {
        let cache = mock_cache_with(
            "internal.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]),
        );
        let router = DirectRouter::with_cache(true, cache);
        let addr = Address::Domain("internal.example".to_string(), 80);
        assert!(matches!(router.route(&addr).await, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_public_domain() {
        let cache = mock_cache_with(
            "example.com",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        );
        let router = DirectRouter::with_cache(true, cache);
        let addr = Address::Domain("example.com".to_string(), 80);
        assert!(matches!(
            router.route(&addr).await,
            OutboundType::Direct {
                resolved: Some(_),
                ..
            }
        ));
    }

    /// Fail-closed SSRF guard: an unresolvable domain must be rejected under
    /// `block_private_ip` rather than fall through to Direct (which re-resolves
    /// at dial time through an unchecked resolver).
    #[tokio::test]
    async fn test_direct_router_rejects_unresolvable_domain_under_block() {
        let cache = mock_cache_with(
            "flaky.example",
            Err(dns_cache_rs::DnsError::NotFound("flaky.example".into())),
        );
        let router = DirectRouter::with_cache(true, cache);
        let addr = Address::Domain("flaky.example".to_string(), 80);
        assert!(matches!(router.route(&addr).await, OutboundType::Reject));
    }
}
