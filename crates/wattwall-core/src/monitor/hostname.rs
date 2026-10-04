//! Host names as text: the name DNS keeps an address under, and which names
//! that come back are fit to show.

use std::net::IpAddr;

/// The name a DNS server keeps an address's own name under: an IPv4 address
/// backwards under `in-addr.arpa`, an IPv6 address backwards one hex digit at
/// a time under `ip6.arpa`.
pub fn reverse_name(address: IpAddr) -> String {
    match address.to_canonical() {
        IpAddr::V4(ip) => {
            let [first, second, third, fourth] = ip.octets();
            format!("{fourth}.{third}.{second}.{first}.in-addr.arpa")
        }
        IpAddr::V6(ip) => {
            let mut name = String::with_capacity(72);
            for byte in ip.octets().iter().rev() {
                for nibble in [byte & 0xF, byte >> 4] {
                    name.extend(char::from_digit(u32::from(nibble), 16));
                    name.push('.');
                }
            }
            name.push_str("ip6.arpa");
            name
        }
    }
}

/// A host name fit to show, or None. DNS answers are untrusted text, so only
/// what a host name is made of is accepted: letters, digits, `-`, `_` and
/// `.`, at most 253 characters, and not just an address written out. Anything
/// else, such as control or direction-changing characters that could make a
/// name read as another, shows the address instead.
pub fn clean_name(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.');
    let plain = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if name.is_empty() || name.len() > 253 || !plain || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn reverse_names_are_the_addresses_backwards_under_the_arpa_zones() {
        let cases = [
            ("93.184.216.34", "34.216.184.93.in-addr.arpa"),
            ("8.8.8.8", "8.8.8.8.in-addr.arpa"),
            ("::ffff:8.8.8.8", "8.8.8.8.in-addr.arpa"),
            (
                "2606:4700:4700::1111",
                "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa",
            ),
            (
                "2001:db8::567:89ab",
                "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            ),
        ];
        for (address, want) in cases {
            assert_eq!(reverse_name(ip(address)), want, "{address}");
        }
    }

    #[test]
    fn only_plain_host_names_are_shown() {
        assert_eq!(clean_name("dns.google"), Some("dns.google".into()));
        assert_eq!(clean_name("  dns.google. "), Some("dns.google".into()));
        assert_eq!(
            clean_name("ec2-3-4-5-6.compute-1.amazonaws.com"),
            Some("ec2-3-4-5-6.compute-1.amazonaws.com".into())
        );
        assert_eq!(
            clean_name("_dmarc.example.org"),
            Some("_dmarc.example.org".into())
        );
        assert_eq!(
            clean_name("xn--bcher-kva.example"),
            Some("xn--bcher-kva.example".into())
        );
        for bad in [
            "",
            ".",
            "bad name",
            "bad\nname",
            "evil\u{202e}moc.example",
            "zero\u{200b}width.example",
            "<script>alert(1)</script>",
            "1.2.3.4",
            "::1",
            &"a".repeat(254),
        ] {
            assert_eq!(clean_name(bad), None, "{bad:?}");
        }
        assert!(clean_name(&"a".repeat(253)).is_some());
    }
}
