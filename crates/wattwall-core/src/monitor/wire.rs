//! Reading the bytes that `GetExtendedTcpTable` and `GetExtendedUdpTable`
//! fill in: a row count, then that many fixed-size rows. Counts, states, scope
//! ids and process ids are 4-byte little-endian numbers (Windows runs
//! little-endian on every CPU it supports). An address is its bytes in order.
//! A port is two big-endian bytes at the start of a 4-byte field.
//!
//! The offsets are plain numbers so this decodes on any OS from bytes alone.
//! `layout` is public so the Windows crate can check the size of every row
//! and the offset of every field in it against the real structs when it
//! compiles.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::socket::{Socket, SocketKind, TcpState};

/// Byte offsets, from the Windows SDK's `MIB_TCPROW_OWNER_PID`,
/// `MIB_TCP6ROW_OWNER_PID`, `MIB_UDPROW_OWNER_PID` and
/// `MIB_UDP6ROW_OWNER_PID`. Rows start after the 4-byte count.
pub mod layout {
    pub const TABLE_HEADER: usize = 4;

    pub const TCP4_ROW: usize = 24;
    pub const TCP4_STATE: usize = 0;
    pub const TCP4_LOCAL_ADDR: usize = 4;
    pub const TCP4_LOCAL_PORT: usize = 8;
    pub const TCP4_REMOTE_ADDR: usize = 12;
    pub const TCP4_REMOTE_PORT: usize = 16;
    pub const TCP4_PID: usize = 20;

    pub const TCP6_ROW: usize = 56;
    pub const TCP6_LOCAL_ADDR: usize = 0;
    pub const TCP6_LOCAL_SCOPE: usize = 16;
    pub const TCP6_LOCAL_PORT: usize = 20;
    pub const TCP6_REMOTE_ADDR: usize = 24;
    pub const TCP6_REMOTE_SCOPE: usize = 40;
    pub const TCP6_REMOTE_PORT: usize = 44;
    pub const TCP6_STATE: usize = 48;
    pub const TCP6_PID: usize = 52;

    pub const UDP4_ROW: usize = 12;
    pub const UDP4_LOCAL_ADDR: usize = 0;
    pub const UDP4_LOCAL_PORT: usize = 4;
    pub const UDP4_PID: usize = 8;

    pub const UDP6_ROW: usize = 28;
    pub const UDP6_LOCAL_ADDR: usize = 0;
    pub const UDP6_LOCAL_SCOPE: usize = 16;
    pub const UDP6_LOCAL_PORT: usize = 20;
    pub const UDP6_PID: usize = 24;
}

use layout::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

impl TableKind {
    pub const fn row_len(self) -> usize {
        match self {
            Self::Tcp4 => TCP4_ROW,
            Self::Tcp6 => TCP6_ROW,
            Self::Udp4 => UDP4_ROW,
            Self::Udp6 => UDP6_ROW,
        }
    }
}

/// Every row of a table buffer that can be understood. A buffer that is short,
/// or claims more rows than it holds, gives the whole rows it does hold; a row
/// with a TCP state Windows has not defined is skipped.
pub fn parse_table(kind: TableKind, bytes: &[u8]) -> Vec<Socket> {
    let Some(header) = bytes.get(..TABLE_HEADER) else {
        return Vec::new();
    };
    let Some(rows) = bytes.get(TABLE_HEADER..) else {
        return Vec::new();
    };
    let declared = header
        .try_into()
        .map(u32::from_le_bytes)
        .ok()
        .and_then(|count| usize::try_from(count).ok())
        .unwrap_or(0);
    rows.chunks_exact(kind.row_len())
        .take(declared)
        .filter_map(|raw| parse_row(kind, Row(raw)))
        .collect()
}

struct Row<'a>(&'a [u8]);

impl Row<'_> {
    fn word(&self, at: usize) -> Option<u32> {
        let bytes: [u8; 4] = self.0.get(at..at + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn port(&self, at: usize) -> Option<u16> {
        let bytes: [u8; 2] = self.0.get(at..at + 2)?.try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }

    fn v4(&self, at: usize, port: usize) -> Option<SocketAddr> {
        let octets: [u8; 4] = self.0.get(at..at + 4)?.try_into().ok()?;
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(octets),
            self.port(port)?,
        )))
    }

    fn v6(&self, at: usize, scope: usize, port: usize) -> Option<SocketAddr> {
        let octets: [u8; 16] = self.0.get(at..at + 16)?.try_into().ok()?;
        Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(octets),
            self.port(port)?,
            0,
            self.word(scope)?,
        )))
    }
}

fn parse_row(kind: TableKind, row: Row) -> Option<Socket> {
    match kind {
        TableKind::Tcp4 => tcp(
            row.v4(TCP4_LOCAL_ADDR, TCP4_LOCAL_PORT)?,
            row.v4(TCP4_REMOTE_ADDR, TCP4_REMOTE_PORT)?,
            row.word(TCP4_STATE)?,
            row.word(TCP4_PID)?,
        ),
        TableKind::Tcp6 => tcp(
            row.v6(TCP6_LOCAL_ADDR, TCP6_LOCAL_SCOPE, TCP6_LOCAL_PORT)?,
            row.v6(TCP6_REMOTE_ADDR, TCP6_REMOTE_SCOPE, TCP6_REMOTE_PORT)?,
            row.word(TCP6_STATE)?,
            row.word(TCP6_PID)?,
        ),
        TableKind::Udp4 => Some(Socket {
            local: row.v4(UDP4_LOCAL_ADDR, UDP4_LOCAL_PORT)?,
            kind: SocketKind::Udp,
            pid: row.word(UDP4_PID)?,
        }),
        TableKind::Udp6 => Some(Socket {
            local: row.v6(UDP6_LOCAL_ADDR, UDP6_LOCAL_SCOPE, UDP6_LOCAL_PORT)?,
            kind: SocketKind::Udp,
            pid: row.word(UDP6_PID)?,
        }),
    }
}

fn tcp(local: SocketAddr, remote: SocketAddr, state: u32, pid: u32) -> Option<Socket> {
    let kind = match TcpState::from_code(state)? {
        TcpState::Listen => SocketKind::TcpListener,
        state => SocketKind::TcpConnection { remote, state },
    };
    Some(Socket { local, kind, pid })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    /// A port the way Windows stores it: big-endian bytes first, then two zeros.
    fn port(value: u16) -> [u8; 4] {
        let [high, low] = value.to_be_bytes();
        [high, low, 0, 0]
    }

    fn table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut out = word(u32::try_from(rows.len()).unwrap()).to_vec();
        rows.iter().for_each(|row| out.extend(row));
        out
    }

    fn tcp4(state: u32, local: ([u8; 4], u16), remote: ([u8; 4], u16), pid: u32) -> Vec<u8> {
        [
            &word(state)[..],
            &local.0,
            &port(local.1),
            &remote.0,
            &port(remote.1),
            &word(pid),
        ]
        .concat()
    }

    fn tcp6(
        state: u32,
        local: ([u8; 16], u32, u16),
        remote: ([u8; 16], u32, u16),
        pid: u32,
    ) -> Vec<u8> {
        [
            &local.0[..],
            &word(local.1),
            &port(local.2),
            &remote.0,
            &word(remote.1),
            &port(remote.2),
            &word(state),
            &word(pid),
        ]
        .concat()
    }

    fn addr(text: &str, port: u16) -> SocketAddr {
        SocketAddr::new(text.parse().unwrap(), port)
    }

    #[test]
    fn row_lengths_are_what_the_offsets_add_up_to() {
        // The process id is the last field of every row.
        assert_eq!(TCP4_PID + 4, TCP4_ROW);
        assert_eq!(TCP6_PID + 4, TCP6_ROW);
        assert_eq!(UDP4_PID + 4, UDP4_ROW);
        assert_eq!(UDP6_PID + 4, UDP6_ROW);
        assert_eq!(TableKind::Tcp6.row_len(), 56);
    }

    #[test]
    fn an_ipv4_connection_and_a_listener_decode() {
        let bytes = table(&[
            tcp4(
                5,
                ([192, 168, 1, 20], 50123),
                ([93, 184, 216, 34], 443),
                4242,
            ),
            tcp4(2, ([0, 0, 0, 0], 80), ([0, 0, 0, 0], 0), 4),
        ]);
        let sockets = parse_table(TableKind::Tcp4, &bytes);
        assert_eq!(
            sockets,
            vec![
                Socket {
                    local: addr("192.168.1.20", 50123),
                    kind: SocketKind::TcpConnection {
                        remote: addr("93.184.216.34", 443),
                        state: TcpState::Established,
                    },
                    pid: 4242,
                },
                Socket {
                    local: addr("0.0.0.0", 80),
                    kind: SocketKind::TcpListener,
                    pid: 4,
                },
            ]
        );
    }

    #[test]
    fn an_ipv6_connection_keeps_its_scope_id() {
        let local: Ipv6Addr = "fe80::1".parse().unwrap();
        let remote: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        let bytes = table(&[tcp6(
            5,
            (local.octets(), 12, 51000),
            (remote.octets(), 0, 443),
            77,
        )]);
        let sockets = parse_table(TableKind::Tcp6, &bytes);
        assert_eq!(sockets.len(), 1);
        let SocketAddr::V6(local_addr) = sockets[0].local else {
            panic!("expected an IPv6 address");
        };
        assert_eq!(*local_addr.ip(), local);
        assert_eq!(local_addr.port(), 51000);
        assert_eq!(local_addr.scope_id(), 12);
        assert_eq!(
            sockets[0].kind,
            SocketKind::TcpConnection {
                remote: addr("2606:4700::1111", 443),
                state: TcpState::Established,
            }
        );
        assert_eq!(sockets[0].pid, 77);
    }

    #[test]
    fn udp_rows_have_no_far_end() {
        let v4 = table(&[[&[0, 0, 0, 0][..], &port(5353), &word(1200)].concat()]);
        assert_eq!(
            parse_table(TableKind::Udp4, &v4),
            vec![Socket {
                local: addr("0.0.0.0", 5353),
                kind: SocketKind::Udp,
                pid: 1200
            }]
        );
        let any: Ipv6Addr = "::".parse().unwrap();
        let v6 = table(&[[&any.octets()[..], &word(0), &port(546), &word(900)].concat()]);
        let sockets = parse_table(TableKind::Udp6, &v6);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local.port(), 546);
        assert_eq!(sockets[0].kind, SocketKind::Udp);
        assert_eq!(sockets[0].pid, 900);
    }

    #[test]
    fn a_port_is_read_big_endian_from_the_first_two_bytes() {
        // 443 is 0x01BB: the bytes in the field are 01 BB 00 00.
        let bytes = table(&[tcp4(5, ([10, 0, 0, 2], 443), ([10, 0, 0, 3], 0x1F90), 1)]);
        let sockets = parse_table(TableKind::Tcp4, &bytes);
        assert_eq!(sockets[0].local.port(), 443);
        let SocketKind::TcpConnection { remote, .. } = sockets[0].kind else {
            panic!("expected a connection");
        };
        assert_eq!(remote.port(), 8080);
    }

    #[test]
    fn a_short_buffer_gives_only_the_whole_rows_it_holds() {
        let row = tcp4(5, ([10, 0, 0, 2], 1000), ([10, 0, 0, 3], 2000), 5);
        let mut bytes = word(3).to_vec();
        bytes.extend(&row);
        bytes.extend(&row[..10]);
        assert_eq!(parse_table(TableKind::Tcp4, &bytes).len(), 1);
    }

    #[test]
    fn a_count_below_the_rows_present_is_respected() {
        let row = tcp4(5, ([10, 0, 0, 2], 1000), ([10, 0, 0, 3], 2000), 5);
        let mut bytes = word(1).to_vec();
        bytes.extend(&row);
        bytes.extend(&row);
        assert_eq!(parse_table(TableKind::Tcp4, &bytes).len(), 1);
    }

    #[test]
    fn nothing_or_nonsense_gives_no_rows() {
        assert!(parse_table(TableKind::Tcp4, &[]).is_empty());
        assert!(parse_table(TableKind::Tcp4, &[1, 0]).is_empty());
        assert!(parse_table(TableKind::Tcp6, &word(u32::MAX)).is_empty());
        assert!(parse_table(TableKind::Udp4, &table(&[])).is_empty());
    }

    #[test]
    fn a_row_with_an_undefined_state_is_skipped_not_guessed() {
        let bytes = table(&[
            tcp4(99, ([10, 0, 0, 2], 1000), ([10, 0, 0, 3], 2000), 5),
            tcp4(5, ([10, 0, 0, 2], 1001), ([10, 0, 0, 3], 2001), 6),
        ]);
        let sockets = parse_table(TableKind::Tcp4, &bytes);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].pid, 6);
    }
}
