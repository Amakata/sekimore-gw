//! `ipaddress.ip_address` and `ipaddress.ip_network(…, strict=False)` as the `allow_ips` /
//! `block_ips` validator uses them: only whether a string is accepted.

use std::net::Ipv6Addr;

/// `IPv4Address(s)`: four dot-separated decimal octets, ASCII digits only, at most three digits,
/// no leading zero, each at most 255.
fn v4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = 0u32;
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        out = out << 8 | n;
    }
    Some(out)
}

/// `IPv6Address(s)`, including the scope id (`fe80::1%eth0`) Python has taken since 3.9.
fn v6(s: &str) -> bool {
    let addr = match s.split_once('%') {
        Some((a, scope)) if !scope.is_empty() && !scope.contains('%') => a,
        Some(_) => return false,
        None => s,
    };
    addr.parse::<Ipv6Addr>().is_ok()
}

/// `ipaddress.ip_address(s)` does not raise.
pub fn is_address(s: &str) -> bool {
    v4(s).is_some() || v6(s)
}

/// `ipaddress.ip_network(s, strict=False)` does not raise. The prefix is a decimal length, or for
/// IPv4 also a netmask (`255.255.0.0`) or a hostmask (`0.0.255.255`).
pub fn is_network(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() > 2 {
        return false;
    }
    let (addr, prefix) = (parts[0], parts.get(1).copied());
    if v4(addr).is_some() {
        return match prefix {
            None => true,
            Some(p) => prefix_len(p, 32) || v4(p).is_some_and(is_mask),
        };
    }
    if v6(addr) {
        return match prefix {
            None => true,
            Some(p) => prefix_len(p, 128),
        };
    }
    false
}

/// A decimal prefix length: ASCII digits (leading zeros allowed), at most `max`.
fn prefix_len(p: &str, max: u32) -> bool {
    !p.is_empty()
        && p.bytes().all(|b| b.is_ascii_digit())
        && p.parse::<u32>().is_ok_and(|n| n <= max)
}

/// A netmask (ones then zeros) or a hostmask (zeros then ones).
fn is_mask(m: u32) -> bool {
    let contiguous = |x: u32| x.leading_ones() + x.trailing_zeros() == 32 || x == 0;
    contiguous(m) || contiguous(!m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert!(is_address("192.168.1.1"));
        assert!(is_address("::1"));
        assert!(is_address("fe80::1%eth0"));
        assert!(is_address("::ffff:1.2.3.4"));
        assert!(!is_address("01.2.3.4"));
        assert!(!is_address("1.2.3"));
        assert!(!is_address("256.1.1.1"));
        assert!(!is_address(" 1.2.3.4"));
        assert!(!is_address("fe80::1%"));
        assert!(!is_address("not.an.ip.address"));
    }

    #[test]
    fn networks() {
        assert!(is_network("192.168.1.0/24"));
        assert!(is_network("192.168.1.5/24"));
        assert!(is_network("10.0.0.0/255.0.0.0"));
        assert!(is_network("10.0.0.0/0.255.255.255"));
        assert!(is_network("10.0.0.0/08"));
        assert!(is_network("fc00::/7"));
        assert!(!is_network("192.168.1.0/999"));
        assert!(!is_network("192.168.1.0/"));
        assert!(!is_network("10.0.0.0/255.0.255.0"));
        assert!(!is_network("fc00::/129"));
        assert!(!is_network("1.2.3.4/8/8"));
    }
}
