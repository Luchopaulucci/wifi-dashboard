use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn parse_ip_opt(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_matches(|c| c == '[' || c == ']');
    let s = s.split('%').next().unwrap_or(s);
    s.parse().ok()
}

pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback() || v.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
    }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    // 100.64.0.0/10
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn is_ietf_protocol(ip: Ipv4Addr) -> bool {
    // 192.0.0.0/24 documentation-ish / IETF protocol assignments — skip specials
    let o = ip.octets();
    o[0] == 192 && o[1] == 0 && o[2] == 0
}

fn is_benchmark(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

fn is_doc(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

/// IP pública ruteable. Sirve para no mandar RFC1918 a RDAP y para marcar el ISP.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_multicast()
                && !v.is_unspecified()
                && !v.is_broadcast()
                && !is_cgnat(v)
                && !is_ietf_protocol(v)
                && !is_benchmark(v)
                && !is_doc(v)
        }
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            !v.is_loopback()
                && !v.is_multicast()
                && !v.is_unspecified()
                && !is_unique_local(v)
                && !v.is_unicast_link_local()
        }
    }
}

pub fn is_private_or_local(ip: IpAddr) -> bool {
    !is_public_ip(ip)
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    (o[0] & 0xfe) == 0xfc
}

pub fn is_wildcard_addr(s: &str) -> bool {
    matches!(s, "*" | "0.0.0.0" | "::" | "[::]" | "::0")
}

pub fn is_loopback_addr(s: &str) -> bool {
    if is_wildcard_addr(s) {
        return false;
    }
    parse_ip_opt(s).is_some_and(is_loopback_ip) || s == "localhost"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_vs_private() {
        assert!(!is_public_ip("192.168.0.1".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("100.64.1.1".parse().unwrap()));
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(is_public_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_public_ip("fd00::1".parse().unwrap()));
    }
}
