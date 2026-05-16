//! Network address type used throughout the Naive proxy.

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Network address (IPv4, IPv6, or domain)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    IPv4([u8; 4], u16),
    IPv6([u8; 16], u16),
    Domain(String, u16),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::IPv4(ip, port) => write!(f, "{}:{}", Ipv4Addr::from(*ip), port),
            Address::IPv6(ip, port) => write!(f, "[{}]:{}", Ipv6Addr::from(*ip), port),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

impl Address {
    /// Parse an authority string (host:port) into an Address.
    pub fn from_authority(authority: &str) -> Option<Self> {
        // Handle IPv6: "[::1]:443"
        if authority.starts_with('[') {
            let close = authority.find(']')?;
            let host = &authority[1..close];
            let rest = &authority[close + 1..];
            let port_str = rest.strip_prefix(':')?.trim();
            let port: u16 = port_str.parse().ok()?;
            let ipv6: Ipv6Addr = host.parse().ok()?;
            let octets = ipv6.octets();
            return Some(Address::IPv6(octets, port));
        }

        let colon = authority.rfind(':')?;
        let host = &authority[..colon];
        let port_str = &authority[colon + 1..];
        let port: u16 = port_str.parse().ok()?;

        // Try IPv4
        if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
            return Some(Address::IPv4(ipv4.octets(), port));
        }

        // Domain
        Some(Address::Domain(host.to_string(), port))
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) => *port,
            Address::IPv6(_, port) => *port,
            Address::Domain(_, port) => *port,
        }
    }

    pub fn host(&self) -> Cow<'_, str> {
        match self {
            Address::IPv4(ip, _) => Cow::Owned(Ipv4Addr::from(*ip).to_string()),
            Address::IPv6(ip, _) => Cow::Owned(Ipv6Addr::from(*ip).to_string()),
            Address::Domain(domain, _) => Cow::Borrowed(domain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_authority_domain() {
        let addr = Address::from_authority("example.com:443").unwrap();
        assert!(matches!(addr, Address::Domain(ref d, 443) if d == "example.com"));
    }

    #[test]
    fn test_from_authority_ipv4() {
        let addr = Address::from_authority("1.2.3.4:80").unwrap();
        assert!(matches!(addr, Address::IPv4([1, 2, 3, 4], 80)));
    }

    #[test]
    fn test_from_authority_ipv6() {
        let addr = Address::from_authority("[::1]:443").unwrap();
        assert!(matches!(addr, Address::IPv6(_, 443)));
    }

    #[test]
    fn test_display_domain() {
        let addr = Address::Domain("example.com".into(), 443);
        assert_eq!(addr.to_string(), "example.com:443");
    }

    #[test]
    fn test_display_ipv4() {
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        assert_eq!(addr.to_string(), "8.8.8.8:53");
    }

    #[test]
    fn test_from_authority_invalid_port() {
        assert!(Address::from_authority("example.com:99999").is_none());
        assert!(Address::from_authority("example.com").is_none());
    }

    #[test]
    fn test_host_domain_borrows() {
        let addr = Address::Domain("example.com".into(), 80);
        assert!(matches!(addr.host(), Cow::Borrowed(_)));
    }

    #[test]
    fn test_host_ipv4_owns() {
        let addr = Address::IPv4([1, 2, 3, 4], 80);
        assert!(matches!(addr.host(), Cow::Owned(_)));
    }
}
