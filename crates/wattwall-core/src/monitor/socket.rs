//! One row of the system's TCP or UDP table, as WattWall reads it.

use std::net::SocketAddr;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A TCP connection's state, numbered the way Windows numbers it
/// (`MIB_TCP_STATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
}

impl TcpState {
    pub const fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            _ => return None,
        })
    }
}

/// What a row is. A connection always has a far end and a state; a listener
/// and a UDP port have neither, because Windows does not record who a UDP
/// socket talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketKind {
    TcpListener,
    TcpConnection { remote: SocketAddr, state: TcpState },
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socket {
    pub local: SocketAddr,
    pub kind: SocketKind,
    /// The owning process. 0 when Windows names none (a closing connection
    /// whose program has gone).
    pub pid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_windows_state_number_is_known_and_nothing_else() {
        let known: Vec<TcpState> = (1..=12).filter_map(TcpState::from_code).collect();
        assert_eq!(known.len(), 12);
        assert_eq!(TcpState::from_code(2), Some(TcpState::Listen));
        assert_eq!(TcpState::from_code(5), Some(TcpState::Established));
        assert_eq!(TcpState::from_code(0), None);
        assert_eq!(TcpState::from_code(13), None);
    }
}
