//! IP address filtering utilities for SSRF protection.

use std::net::{Ipv4Addr, Ipv6Addr};

pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || ip.is_broadcast()
        || ip.is_multicast()
}

pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback() || is_ipv6_ula(ip) || is_ipv6_link_local(ip)
}

fn is_ipv6_ula(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4() {
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(is_private_ipv6(&Ipv6Addr::LOCALHOST));
        assert!(is_private_ipv6(&"fc00::1".parse().unwrap()));
        assert!(is_private_ipv6(&"fe80::1".parse().unwrap()));
        assert!(!is_private_ipv6(&"2001:4860:4860::8888".parse().unwrap()));
    }
}
