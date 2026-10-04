//! Which way a connection goes. Windows lists both ends of every TCP
//! connection but not who opened it, so WattWall infers it:
//!
//! - a connection still being set up is incoming if it was started by a
//!   remote SYN (`SYN_RECEIVED`) and outgoing if this PC sent the SYN
//!   (`SYN_SENT`);
//! - an open connection is incoming when its local port is one a program is
//!   listening on, and outgoing otherwise, since a program that connects out
//!   gets a fresh port nobody listens on;
//! - a listening TCP port or a bound UDP port is just "listening": Windows
//!   does not record who a UDP socket talks to.
//!
//! A program that connects out from the same port it listens on (some
//! peer-to-peer tools) has those connections shown as incoming.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::Serialize;

use super::socket::{Protocol, Socket, SocketKind, TcpState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Incoming,
    Outgoing,
    Listening,
}

/// Where a connection is in its life. `Closed` is only ever given by the
/// tracker, to a connection that has disappeared from the tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Listening,
    Connecting,
    Connected,
    Closing,
    Closed,
}

/// One live connection or waiting port. `remote` is set exactly when the
/// direction is not `Listening`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub protocol: Protocol,
    pub direction: Direction,
    pub phase: Phase,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub pid: u32,
}

/// Turn table rows into flows. Rows with no owning program, and TCP rows that
/// are over (`TIME_WAIT`, `CLOSED`, `DELETE_TCB`), are left out.
pub fn classify(sockets: &[Socket]) -> Vec<Flow> {
    let listeners = Listeners::of(sockets);
    sockets
        .iter()
        .filter(|socket| socket.pid != 0)
        .filter_map(|socket| flow(socket, &listeners))
        .collect()
}

fn flow(socket: &Socket, listeners: &Listeners) -> Option<Flow> {
    let (protocol, direction, phase, remote) = match socket.kind {
        SocketKind::Udp => (Protocol::Udp, Direction::Listening, Phase::Listening, None),
        SocketKind::TcpListener => (Protocol::Tcp, Direction::Listening, Phase::Listening, None),
        SocketKind::TcpConnection { remote, state } => {
            let phase = match state {
                TcpState::SynSent | TcpState::SynReceived => Phase::Connecting,
                TcpState::Established => Phase::Connected,
                TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck => Phase::Closing,
                TcpState::Closed | TcpState::Listen | TcpState::TimeWait | TcpState::DeleteTcb => {
                    return None
                }
            };
            let direction = match state {
                TcpState::SynReceived => Direction::Incoming,
                TcpState::SynSent => Direction::Outgoing,
                _ if listeners.accepts(socket.local) => Direction::Incoming,
                _ => Direction::Outgoing,
            };
            (Protocol::Tcp, direction, phase, Some(remote))
        }
    };
    Some(Flow {
        protocol,
        direction,
        phase,
        local: socket.local,
        remote,
        pid: socket.pid,
    })
}

/// The addresses each local TCP port is listening on.
struct Listeners(HashMap<u16, Vec<IpAddr>>);

impl Listeners {
    fn of(sockets: &[Socket]) -> Self {
        let mut ports: HashMap<u16, Vec<IpAddr>> = HashMap::new();
        for socket in sockets {
            if socket.kind == SocketKind::TcpListener {
                ports
                    .entry(socket.local.port())
                    .or_default()
                    .push(socket.local.ip().to_canonical());
            }
        }
        Self(ports)
    }

    /// Whether some listener would have accepted a connection on `local`. A
    /// listener on every address (`0.0.0.0` or `::`) accepts on any of them;
    /// Windows lists a dual-stack listener only as `::`, and it accepts IPv4
    /// connections too.
    fn accepts(&self, local: SocketAddr) -> bool {
        let address = local.ip().to_canonical();
        self.0.get(&local.port()).is_some_and(|listening| {
            listening
                .iter()
                .any(|on| on.is_unspecified() || *on == address)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn listener(local: &str, pid: u32) -> Socket {
        Socket {
            local: addr(local),
            kind: SocketKind::TcpListener,
            pid,
        }
    }

    fn connection(local: &str, remote: &str, state: TcpState, pid: u32) -> Socket {
        Socket {
            local: addr(local),
            kind: SocketKind::TcpConnection {
                remote: addr(remote),
                state,
            },
            pid,
        }
    }

    fn only(sockets: &[Socket]) -> Flow {
        let flows = classify(sockets);
        assert_eq!(flows.len(), 1, "{flows:?}");
        flows[0]
    }

    #[test]
    fn a_connection_from_a_fresh_port_is_outgoing() {
        let flow = only(&[connection(
            "192.168.1.20:50123",
            "93.184.216.34:443",
            TcpState::Established,
            4242,
        )]);
        assert_eq!(flow.direction, Direction::Outgoing);
        assert_eq!(flow.phase, Phase::Connected);
        assert_eq!(flow.remote, Some(addr("93.184.216.34:443")));
        assert_eq!(flow.protocol, Protocol::Tcp);
        assert_eq!(flow.pid, 4242);
    }

    #[test]
    fn a_connection_to_a_listening_port_is_incoming() {
        let flows = classify(&[
            listener("0.0.0.0:3389", 1000),
            connection(
                "192.168.1.20:3389",
                "203.0.113.9:51234",
                TcpState::Established,
                1000,
            ),
        ]);
        let incoming: Vec<_> = flows
            .iter()
            .filter(|f| f.direction == Direction::Incoming)
            .collect();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].remote, Some(addr("203.0.113.9:51234")));
        assert!(flows.iter().any(|f| f.direction == Direction::Listening));
    }

    #[test]
    fn a_listener_on_one_address_only_claims_that_address() {
        let sockets = [
            listener("192.168.1.20:8080", 1000),
            connection(
                "192.168.1.20:8080",
                "192.168.1.30:50000",
                TcpState::Established,
                1000,
            ),
            connection(
                "10.0.0.5:8080",
                "10.0.0.6:50001",
                TcpState::Established,
                2000,
            ),
        ];
        let flows = classify(&sockets);
        let direction_of = |pid| {
            flows
                .iter()
                .find(|f| f.pid == pid && f.remote.is_some())
                .unwrap()
                .direction
        };
        assert_eq!(direction_of(1000), Direction::Incoming);
        assert_eq!(direction_of(2000), Direction::Outgoing);
    }

    #[test]
    fn a_dual_stack_listener_accepts_ipv4_connections() {
        // Windows lists a dual-stack listener only in the IPv6 table, as `::`.
        let flows = classify(&[
            listener("[::]:3000", 1000),
            connection(
                "127.0.0.1:3000",
                "127.0.0.1:50500",
                TcpState::Established,
                1000,
            ),
        ]);
        let conn = flows.iter().find(|f| f.remote.is_some()).unwrap();
        assert_eq!(conn.direction, Direction::Incoming);
    }

    #[test]
    fn both_ends_of_a_loopback_connection_are_told_apart() {
        let flows = classify(&[
            listener("127.0.0.1:5000", 10),
            connection(
                "127.0.0.1:5000",
                "127.0.0.1:51234",
                TcpState::Established,
                10,
            ),
            connection(
                "127.0.0.1:51234",
                "127.0.0.1:5000",
                TcpState::Established,
                20,
            ),
        ]);
        let server = flows
            .iter()
            .find(|f| f.pid == 10 && f.remote.is_some())
            .unwrap();
        let client = flows.iter().find(|f| f.pid == 20).unwrap();
        assert_eq!(server.direction, Direction::Incoming);
        assert_eq!(client.direction, Direction::Outgoing);
    }

    #[test]
    fn a_syn_decides_the_direction_of_a_connection_being_set_up() {
        let flows = classify(&[
            listener("0.0.0.0:6881", 7),
            // This PC sent the SYN from a port it also listens on.
            connection(
                "192.168.1.20:6881",
                "198.51.100.4:6881",
                TcpState::SynSent,
                7,
            ),
            // A remote SYN arrived on a port nobody lists as listening.
            connection(
                "192.168.1.20:9999",
                "198.51.100.5:40000",
                TcpState::SynReceived,
                8,
            ),
        ]);
        let sent = flows
            .iter()
            .find(|f| f.pid == 7 && f.remote.is_some())
            .unwrap();
        let received = flows.iter().find(|f| f.pid == 8).unwrap();
        assert_eq!(
            (sent.direction, sent.phase),
            (Direction::Outgoing, Phase::Connecting)
        );
        assert_eq!(
            (received.direction, received.phase),
            (Direction::Incoming, Phase::Connecting)
        );
    }

    #[test]
    fn a_closing_connection_keeps_its_direction() {
        for state in [
            TcpState::FinWait1,
            TcpState::FinWait2,
            TcpState::CloseWait,
            TcpState::Closing,
            TcpState::LastAck,
        ] {
            let flow = only(&[connection("10.0.0.5:50000", "10.0.0.6:443", state, 3)]);
            assert_eq!(
                (flow.direction, flow.phase),
                (Direction::Outgoing, Phase::Closing),
                "{state:?}"
            );
        }
    }

    #[test]
    fn finished_connections_and_ownerless_rows_are_left_out() {
        for state in [TcpState::TimeWait, TcpState::Closed, TcpState::DeleteTcb] {
            assert!(classify(&[connection("10.0.0.5:50000", "10.0.0.6:443", state, 3)]).is_empty());
        }
        assert!(classify(&[connection(
            "10.0.0.5:50000",
            "10.0.0.6:443",
            TcpState::Established,
            0
        )])
        .is_empty());
        assert!(classify(&[listener("0.0.0.0:80", 0)]).is_empty());
    }

    #[test]
    fn listeners_and_udp_ports_are_listening_with_no_far_end() {
        let udp = Socket {
            local: addr("0.0.0.0:5353"),
            kind: SocketKind::Udp,
            pid: 1200,
        };
        let flows = classify(&[listener("0.0.0.0:445", 4), udp]);
        assert_eq!(flows.len(), 2);
        for flow in &flows {
            assert_eq!(flow.direction, Direction::Listening);
            assert_eq!(flow.phase, Phase::Listening);
            assert_eq!(flow.remote, None);
        }
        assert_eq!(flows[0].protocol, Protocol::Tcp);
        assert_eq!(flows[1].protocol, Protocol::Udp);
    }
}
