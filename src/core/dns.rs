//! DNS resolution for naive-rs.

use std::io;
use std::net::SocketAddr;

use dns_cache_rs::{DnsCache, DnsError};

use super::address::Address;

fn dns_error_to_io(err: DnsError) -> io::Error {
    match err {
        DnsError::NotFound(host) => io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses found for {host}"),
        ),
        DnsError::Timeout(d) => io::Error::new(
            io::ErrorKind::TimedOut,
            format!("DNS query timeout after {d:?}"),
        ),
        DnsError::InvalidHost(h) => {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid host: {h}"))
        }
        DnsError::Other(e) => io::Error::other(e.to_string()),
    }
}

pub async fn resolve_socket_addr(cache: &DnsCache, addr: &Address) -> io::Result<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match addr {
        Address::IPv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port)),
        Address::IPv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port)),
        Address::Domain(host, port) => {
            let mut it = cache
                .resolve_with_port_iter(host, *port)
                .await
                .map_err(dns_error_to_io)?;
            it.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no addresses found for {host}"),
                )
            })
        }
    }
}

pub(crate) async fn check_private_and_resolve(
    cache: &DnsCache,
    addr: &Address,
) -> (bool, Option<SocketAddr>) {
    use super::ip_filter::{is_private_ipv4, is_private_ipv6};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    match addr {
        Address::IPv4(ip, _) => {
            let ipv4 = Ipv4Addr::from(*ip);
            (is_private_ipv4(&ipv4), None)
        }
        Address::IPv6(ip, _) => {
            let ipv6 = Ipv6Addr::from(*ip);
            (is_private_ipv6(&ipv6), None)
        }
        Address::Domain(host, port) => {
            let it = match cache.resolve_with_port_iter(host, *port).await {
                Ok(it) => it,
                Err(_) => return (false, None),
            };
            let mut first_public: Option<SocketAddr> = None;
            for sa in it {
                match sa.ip() {
                    IpAddr::V4(ipv4) if is_private_ipv4(&ipv4) => {
                        return (true, None);
                    }
                    IpAddr::V6(ipv6) if is_private_ipv6(&ipv6) => {
                        return (true, None);
                    }
                    _ => {
                        if first_public.is_none() {
                            first_public = Some(sa);
                        }
                    }
                }
            }
            (false, first_public)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn mock_cache() -> (DnsCache, Arc<dns_cache_rs::MockResolver>) {
        let mock = Arc::new(dns_cache_rs::MockResolver::new());
        let cache = DnsCache::builder()
            .resolver_arc(mock.clone() as Arc<dyn dns_cache_rs::Resolver>)
            .build()
            .expect("DnsCache build");
        (cache, mock)
    }

    #[tokio::test]
    async fn resolve_ipv4_literal_bypasses_cache() {
        let (cache, mock) = mock_cache();
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let got = resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(got, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(mock.total_calls(), 0);
    }

    #[tokio::test]
    async fn resolve_domain_returns_first_address() {
        let (cache, mock) = mock_cache();
        mock.set(
            "example.com",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        );
        let addr = Address::Domain("example.com".into(), 8080);
        let got = resolve_socket_addr(&cache, &addr).await.unwrap();
        assert_eq!(got, "93.184.216.34:8080".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn check_private_ipv4_loopback() {
        let (cache, _) = mock_cache();
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn check_private_domain_resolving_to_private() {
        let (cache, mock) = mock_cache();
        mock.set(
            "internal.example",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]),
        );
        let addr = Address::Domain("internal.example".into(), 443);
        let (is_private, _) = check_private_and_resolve(&cache, &addr).await;
        assert!(is_private);
    }

    #[tokio::test]
    async fn check_private_domain_resolving_to_public() {
        let (cache, mock) = mock_cache();
        mock.set(
            "example.com",
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        );
        let addr = Address::Domain("example.com".into(), 443);
        let (is_private, resolved) = check_private_and_resolve(&cache, &addr).await;
        assert!(!is_private);
        assert!(resolved.is_some());
    }
}
