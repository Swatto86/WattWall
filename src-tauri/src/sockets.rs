//! The system's TCP and UDP tables as the network monitor reads them: every
//! socket with its owning process, and the program each process runs. The
//! bytes are decoded by `wattwall_core::monitor`, which knows nothing of
//! Windows; the offsets it uses are checked against Windows' own structs
//! below, so a wrong one stops the build instead of mislabelling a connection.
//! The same goes for the TCP state numbers.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::mem::{offset_of, size_of};
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;
use wattwall_core::monitor::{layout, parse_table, Socket, SocketKind, TableKind, TcpState};
use windows::Win32::NetworkManagement::IpHelper::{
    MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD,
    MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::net::Connections;
use crate::programs::path_for_pid;
use crate::tables::table;

const FAKE_SOCKETS: &str = "fake-sockets.json";

const _: () = {
    // The rows start after the row count.
    assert!(offset_of!(MIB_TCPTABLE_OWNER_PID, table) == layout::TABLE_HEADER);
    assert!(offset_of!(MIB_TCP6TABLE_OWNER_PID, table) == layout::TABLE_HEADER);
    assert!(offset_of!(MIB_UDPTABLE_OWNER_PID, table) == layout::TABLE_HEADER);
    assert!(offset_of!(MIB_UDP6TABLE_OWNER_PID, table) == layout::TABLE_HEADER);

    // The state numbers Windows uses are the ones `TcpState` decodes.
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_CLOSED.0.cast_unsigned()),
        Some(TcpState::Closed)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_LISTEN.0.cast_unsigned()),
        Some(TcpState::Listen)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_SYN_SENT.0.cast_unsigned()),
        Some(TcpState::SynSent)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_SYN_RCVD.0.cast_unsigned()),
        Some(TcpState::SynReceived)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_ESTAB.0.cast_unsigned()),
        Some(TcpState::Established)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_FIN_WAIT1.0.cast_unsigned()),
        Some(TcpState::FinWait1)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_FIN_WAIT2.0.cast_unsigned()),
        Some(TcpState::FinWait2)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_CLOSE_WAIT.0.cast_unsigned()),
        Some(TcpState::CloseWait)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_CLOSING.0.cast_unsigned()),
        Some(TcpState::Closing)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_LAST_ACK.0.cast_unsigned()),
        Some(TcpState::LastAck)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_TIME_WAIT.0.cast_unsigned()),
        Some(TcpState::TimeWait)
    ));
    assert!(matches!(
        TcpState::from_code(MIB_TCP_STATE_DELETE_TCB.0.cast_unsigned()),
        Some(TcpState::DeleteTcb)
    ));

    assert!(size_of::<MIB_TCPROW_OWNER_PID>() == layout::TCP4_ROW);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwState) == layout::TCP4_STATE);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwLocalAddr) == layout::TCP4_LOCAL_ADDR);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwLocalPort) == layout::TCP4_LOCAL_PORT);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwRemoteAddr) == layout::TCP4_REMOTE_ADDR);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwRemotePort) == layout::TCP4_REMOTE_PORT);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwOwningPid) == layout::TCP4_PID);

    assert!(size_of::<MIB_TCP6ROW_OWNER_PID>() == layout::TCP6_ROW);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, ucLocalAddr) == layout::TCP6_LOCAL_ADDR);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwLocalScopeId) == layout::TCP6_LOCAL_SCOPE);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwLocalPort) == layout::TCP6_LOCAL_PORT);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, ucRemoteAddr) == layout::TCP6_REMOTE_ADDR);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwRemoteScopeId) == layout::TCP6_REMOTE_SCOPE);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwRemotePort) == layout::TCP6_REMOTE_PORT);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwState) == layout::TCP6_STATE);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwOwningPid) == layout::TCP6_PID);

    assert!(size_of::<MIB_UDPROW_OWNER_PID>() == layout::UDP4_ROW);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwLocalAddr) == layout::UDP4_LOCAL_ADDR);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwLocalPort) == layout::UDP4_LOCAL_PORT);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwOwningPid) == layout::UDP4_PID);

    assert!(size_of::<MIB_UDP6ROW_OWNER_PID>() == layout::UDP6_ROW);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, ucLocalAddr) == layout::UDP6_LOCAL_ADDR);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwLocalScopeId) == layout::UDP6_LOCAL_SCOPE);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwLocalPort) == layout::UDP6_LOCAL_PORT);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwOwningPid) == layout::UDP6_PID);
};

/// A look at the tables.
pub struct Sockets {
    pub rows: Vec<Socket>,
    /// The program each owning process runs. A process Windows will not
    /// describe has no entry.
    pub programs: HashMap<u32, String>,
}

impl Connections {
    pub fn sockets(&self) -> Result<Sockets, String> {
        match self {
            Self::Live => live(),
            Self::Fake(dir) => fake(&dir.join(FAKE_SOCKETS)),
        }
    }
}

fn live() -> Result<Sockets, String> {
    let mut rows = Vec::new();
    for (kind, family, tcp) in [
        (TableKind::Tcp4, AF_INET, true),
        (TableKind::Tcp6, AF_INET6, true),
        (TableKind::Udp4, AF_INET, false),
        (TableKind::Udp6, AF_INET6, false),
    ] {
        rows.extend(parse_table(kind, &table(u32::from(family.0), tcp)?));
    }
    let owners: BTreeSet<u32> = rows
        .iter()
        .map(|socket| socket.pid)
        .filter(|pid| *pid != 0)
        .collect();
    let programs = owners
        .into_iter()
        .filter_map(|pid| path_for_pid(pid).map(|path| (pid, path)))
        .collect();
    Ok(Sockets { rows, programs })
}

/// A socket in the test mode's `fake-sockets.json`, which also says which
/// program owns it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FakeSocket {
    path: String,
    pid: u32,
    protocol: FakeProtocol,
    #[serde(default)]
    state: Option<FakeState>,
    local: SocketAddr,
    #[serde(default)]
    remote: Option<SocketAddr>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum FakeProtocol {
    Tcp,
    Udp,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum FakeState {
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
}

impl From<FakeState> for TcpState {
    fn from(state: FakeState) -> Self {
        match state {
            FakeState::Listen => Self::Listen,
            FakeState::SynSent => Self::SynSent,
            FakeState::SynReceived => Self::SynReceived,
            FakeState::Established => Self::Established,
            FakeState::FinWait1 => Self::FinWait1,
            FakeState::FinWait2 => Self::FinWait2,
            FakeState::CloseWait => Self::CloseWait,
            FakeState::Closing => Self::Closing,
            FakeState::LastAck => Self::LastAck,
            FakeState::TimeWait => Self::TimeWait,
        }
    }
}

fn fake(file: &Path) -> Result<Sockets, String> {
    if !file.exists() {
        return Ok(Sockets {
            rows: Vec::new(),
            programs: HashMap::new(),
        });
    }
    let text = fs::read_to_string(file).map_err(|err| err.to_string())?;
    let entries: Vec<FakeSocket> = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    let mut rows = Vec::new();
    let mut programs = HashMap::new();
    for entry in entries {
        let kind = match (entry.protocol, entry.state, entry.remote) {
            (FakeProtocol::Udp, None, None) => SocketKind::Udp,
            (FakeProtocol::Tcp, Some(FakeState::Listen), None) => SocketKind::TcpListener,
            (FakeProtocol::Tcp, Some(state), Some(remote)) if !matches!(state, FakeState::Listen) => {
                SocketKind::TcpConnection {
                    remote,
                    state: state.into(),
                }
            }
            _ => {
                return Err(format!(
                    "{}: a socket needs a state and a remote address if and only if it is a TCP connection",
                    entry.local
                ))
            }
        };
        programs.insert(entry.pid, entry.path);
        rows.push(Socket {
            local: entry.local,
            kind,
            pid: entry.pid,
        });
    }
    Ok(Sockets { rows, programs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use wattwall_core::monitor::{classify, Direction, Phase};

    /// A listener and a connection to it, both in this process, so the real
    /// tables have a known answer: the listener waits, the accepted end is
    /// incoming, and the connecting end is outgoing.
    #[test]
    fn the_real_tables_show_this_process_listening_accepting_and_connecting() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = server.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let client_port = client.local_addr().unwrap().port();
        let (_accepted, _) = server.accept().unwrap();

        let look = Connections::Live.sockets().unwrap();
        let me = std::process::id();
        let flows: Vec<_> = classify(&look.rows)
            .into_iter()
            .filter(|flow| flow.pid == me)
            .collect();
        let find = |local: u16, remote: Option<u16>| {
            flows
                .iter()
                .find(|flow| flow.local.port() == local && flow.remote.map(|r| r.port()) == remote)
                .copied()
        };

        let listening = find(server_port, None).expect("the listener is in the table");
        assert_eq!(listening.direction, Direction::Listening);
        let accepted =
            find(server_port, Some(client_port)).expect("the accepted end is in the table");
        assert_eq!(
            (accepted.direction, accepted.phase),
            (Direction::Incoming, Phase::Connected)
        );
        let connecting =
            find(client_port, Some(server_port)).expect("the connecting end is in the table");
        assert_eq!(
            (connecting.direction, connecting.phase),
            (Direction::Outgoing, Phase::Connected)
        );

        let exe = std::env::current_exe().unwrap();
        let program = look
            .programs
            .get(&me)
            .expect("this process has a program path");
        let name = |path: &str| {
            path.rsplit('\\')
                .next()
                .unwrap_or(path)
                .to_ascii_lowercase()
        };
        assert_eq!(name(program), name(&exe.to_string_lossy()));
    }

    #[test]
    fn a_fake_file_gives_the_sockets_it_describes() {
        let dir = std::env::temp_dir().join(format!("wattwall-sockets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join(FAKE_SOCKETS);
        fs::write(
            &file,
            r#"[
              {"path": "C:\\a\\curl.exe", "pid": 7, "protocol": "tcp", "state": "established",
               "local": "192.168.1.20:50123", "remote": "203.0.113.7:443"},
              {"path": "C:\\a\\srv.exe", "pid": 8, "protocol": "tcp", "state": "listen", "local": "0.0.0.0:3389"},
              {"path": "C:\\a\\srv.exe", "pid": 8, "protocol": "udp", "local": "0.0.0.0:5353"}
            ]"#,
        )
        .unwrap();
        let look = fake(&file).unwrap();
        assert_eq!(look.rows.len(), 3);
        assert_eq!(
            look.programs.get(&7).map(String::as_str),
            Some(r"C:\a\curl.exe")
        );
        assert_eq!(look.rows[1].kind, SocketKind::TcpListener);
        assert_eq!(look.rows[2].kind, SocketKind::Udp);

        // Each of these is a socket that cannot exist, so a fixture with one is broken.
        for broken in [
            r#"{"protocol": "tcp", "local": "10.0.0.1:1"}"#,
            r#"{"protocol": "tcp", "local": "10.0.0.1:1", "remote": "10.0.0.2:2"}"#,
            r#"{"protocol": "tcp", "state": "established", "local": "10.0.0.1:1"}"#,
            r#"{"protocol": "tcp", "state": "listen", "local": "10.0.0.1:1", "remote": "10.0.0.2:2"}"#,
            r#"{"protocol": "udp", "state": "established", "local": "10.0.0.1:1"}"#,
            r#"{"protocol": "udp", "local": "10.0.0.1:1", "remote": "10.0.0.2:2"}"#,
        ] {
            let entry = broken.replacen('{', r#"{"path": "C:\\a.exe", "pid": 1, "#, 1);
            fs::write(&file, format!("[{entry}]")).unwrap();
            assert!(fake(&file).is_err(), "{broken}");
        }
        assert!(fake(&dir.join("absent.json")).unwrap().rows.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
