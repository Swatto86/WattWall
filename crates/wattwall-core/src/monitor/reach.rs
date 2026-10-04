//! How far away the other end of a connection is, and which addresses are
//! worth asking a DNS server about.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::Serialize;

/// Who can be on the other end. For a connection that is the far address; for
/// a port that is waiting, it is who can reach it: a port open on every
/// address counts as `Internet`, because anyone the firewall lets through can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reach {
    /// This PC itself (loopback).
    ThisPc,
    /// A private, link-local or multicast address: the home or office
    /// network, or a VPN such as Tailscale.
    LocalNetwork,
    Internet,
}

impl Reach {
    pub fn of(address: IpAddr) -> Self {
        match address.to_canonical() {
            IpAddr::V4(ip) => of_v4(ip),
            IpAddr::V6(ip) => of_v6(ip),
        }
    }
}

fn of_v4(ip: Ipv4Addr) -> Reach {
    let [first, second, ..] = ip.octets();
    let shared_space = first == 100 && second & 0xC0 == 64;
    if ip.is_loopback() {
        Reach::ThisPc
    } else if ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || shared_space
    {
        Reach::LocalNetwork
    } else {
        Reach::Internet
    }
}

fn of_v6(ip: Ipv6Addr) -> Reach {
    let first = ip.segments()[0];
    let unique_local = first & 0xFE00 == 0xFC00;
    let link_local = first & 0xFFC0 == 0xFE80;
    if ip.is_loopback() {
        Reach::ThisPc
    } else if unique_local || link_local || ip.is_multicast() {
        Reach::LocalNetwork
    } else {
        Reach::Internet
    }
}

/// Whether a host-name lookup could tell the owner anything: not for this PC,
/// not for "every address", and not for multicast or link-local addresses,
/// which name no single machine.
pub fn worth_resolving(address: IpAddr) -> bool {
    let address = address.to_canonical();
    let link_local = match address {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.segments()[0] & 0xFFC0 == 0xFE80,
    };
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || link_local
        || address == IpAddr::V4(Ipv4Addr::BROADCAST))
}

/// An address without its port, the way a person writes it: an IPv4 address
/// that arrived in IPv6 form is shown as IPv4, and a link-local IPv6 address
/// carries its zone (`fe80::1%12`).
pub fn address_text(address: &SocketAddr) -> String {
    let zone = match address {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => Some(v6.scope_id()),
        _ => None,
    };
    let ip = address.ip().to_canonical();
    match (ip, zone) {
        (IpAddr::V6(ip), Some(zone)) => format!("{ip}%{zone}"),
        (ip, _) => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn reach_of_addresses() {
        let cases = [
            ("127.0.0.1", Reach::ThisPc),
            ("127.8.9.10", Reach::ThisPc),
            ("::1", Reach::ThisPc),
            ("::ffff:127.0.0.1", Reach::ThisPc),
            ("192.168.1.1", Reach::LocalNetwork),
            ("10.1.2.3", Reach::LocalNetwork),
            ("172.16.0.1", Reach::LocalNetwork),
            ("172.31.255.255", Reach::LocalNetwork),
            ("172.32.0.1", Reach::Internet),
            ("169.254.10.10", Reach::LocalNetwork),
            ("100.64.0.1", Reach::LocalNetwork),
            ("100.101.102.103", Reach::LocalNetwork),
            ("100.127.255.255", Reach::LocalNetwork),
            ("100.128.0.1", Reach::Internet),
            ("100.63.255.255", Reach::Internet),
            ("224.0.0.251", Reach::LocalNetwork),
            ("255.255.255.255", Reach::LocalNetwork),
            ("fd7a:115c:a1e0::1", Reach::LocalNetwork),
            ("fe80::1", Reach::LocalNetwork),
            ("ff02::fb", Reach::LocalNetwork),
            ("8.8.8.8", Reach::Internet),
            ("93.184.216.34", Reach::Internet),
            ("2606:4700::1111", Reach::Internet),
            ("::ffff:8.8.8.8", Reach::Internet),
            ("::ffff:192.168.0.9", Reach::LocalNetwork),
            ("0.0.0.0", Reach::Internet),
            ("::", Reach::Internet),
        ];
        for (text, want) in cases {
            assert_eq!(Reach::of(ip(text)), want, "{text}");
        }
    }

    #[test]
    fn only_addresses_that_name_one_machine_are_looked_up() {
        for text in [
            "8.8.8.8",
            "192.168.1.10",
            "100.101.102.103",
            "2606:4700::1111",
            "fd7a:115c:a1e0::1",
        ] {
            assert!(worth_resolving(ip(text)), "{text}");
        }
        for text in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "224.0.0.251",
            "ff02::fb",
            "fe80::1",
            "169.254.10.10",
            "255.255.255.255",
            "::ffff:127.0.0.1",
            "::ffff:169.254.10.10",
        ] {
            assert!(!worth_resolving(ip(text)), "{text}");
        }
    }

    #[test]
    fn address_text_drops_the_port_and_the_ipv6_wrapper() {
        assert_eq!(
            address_text(&"192.168.1.5:443".parse().unwrap()),
            "192.168.1.5"
        );
        assert_eq!(
            address_text(&"[2606:4700::1111]:443".parse().unwrap()),
            "2606:4700::1111"
        );
        assert_eq!(
            address_text(&"[::ffff:93.184.216.34]:443".parse().unwrap()),
            "93.184.216.34"
        );
        assert_eq!(
            address_text(&"[fe80::1%12]:443".parse().unwrap()),
            "fe80::1%12"
        );
    }
}
