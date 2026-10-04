//! The lines the window is given, and how a connection becomes one.

use std::net::IpAddr;

use serde::Serialize;

use super::flows::{Direction, Phase};
use super::reach::{address_text, worth_resolving, Reach};
use super::socket::Protocol;
use super::tracker::Connection;
use crate::pathutil::exe_name;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionDto {
    /// The same from one look to the next, so the window updates a line in
    /// place instead of redrawing it.
    pub key: String,
    /// The program's full path, `System` for process 4, empty when unknown.
    pub path: String,
    pub name: String,
    pub pid: u32,
    pub protocol: Protocol,
    pub direction: Direction,
    pub phase: Phase,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    /// The host name DNS gave for the far address, once it has.
    pub remote_name: Option<String>,
    pub reach: Reach,
    pub first_seen: i64,
    pub closed_at: Option<i64>,
}

/// The `monitor_snapshot` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorDto {
    pub connections: Vec<ConnectionDto>,
    /// More than `MAX_ROWS` were found; the least interesting were left out.
    pub truncated: bool,
    /// Host-name lookups are on.
    pub names: bool,
    /// Lookups still waiting or running.
    pub pending_names: usize,
    pub now: i64,
}

pub(super) fn program_name(path: &str, pid: u32) -> String {
    if path.is_empty() {
        return format!("Unknown (pid {pid})");
    }
    exe_name(path).unwrap_or(path).to_string()
}

/// Who a connection is, the same from one look to the next: its protocol,
/// both ends and process. No two connections have the same one.
pub(super) fn key(connection: &Connection) -> String {
    let flow = &connection.flow;
    let protocol = match flow.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    format!(
        "{protocol}|{}|{}|{}",
        flow.local,
        flow.remote
            .map(|remote| remote.to_string())
            .unwrap_or_default(),
        flow.pid
    )
}

pub(super) fn line(
    connection: &Connection,
    key: String,
    name_of: &impl Fn(IpAddr) -> Option<String>,
) -> ConnectionDto {
    let flow = &connection.flow;
    let remote_name = flow
        .remote
        .map(|remote| remote.ip())
        .filter(|ip| worth_resolving(*ip))
        .and_then(name_of);
    ConnectionDto {
        key,
        path: connection.program.clone(),
        name: program_name(&connection.program, flow.pid),
        pid: flow.pid,
        protocol: flow.protocol,
        direction: flow.direction,
        phase: flow.phase,
        local_address: address_text(&flow.local),
        local_port: flow.local.port(),
        remote_address: flow.remote.as_ref().map(address_text),
        remote_port: flow.remote.map(|remote| remote.port()),
        remote_name,
        reach: Reach::of(flow.remote.unwrap_or(flow.local).ip()),
        first_seen: connection.first_seen,
        closed_at: connection.closed_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::fixtures::connection;
    use crate::monitor::view::connections_view;
    use serde_json::json;

    fn none(_: IpAddr) -> Option<String> {
        None
    }

    #[test]
    fn a_line_is_exactly_what_the_window_reads() {
        let mut open = connection(
            r"C:\Tools\curl.exe",
            7,
            Direction::Outgoing,
            "192.168.1.20:50123",
            Some("93.184.216.34:443"),
            100,
        );
        open.closed_at = Some(160);
        let (lines, truncated) = connections_view(vec![open], |_| Some("example.net".to_string()));
        assert!(!truncated);
        assert_eq!(
            serde_json::to_value(&lines[0]).unwrap(),
            json!({
                "key": "tcp|192.168.1.20:50123|93.184.216.34:443|7",
                "path": r"C:\Tools\curl.exe",
                "name": "curl.exe",
                "pid": 7,
                "protocol": "tcp",
                "direction": "outgoing",
                "phase": "connected",
                "localAddress": "192.168.1.20",
                "localPort": 50123,
                "remoteAddress": "93.184.216.34",
                "remotePort": 443,
                "remoteName": "example.net",
                "reach": "internet",
                "firstSeen": 100,
                "closedAt": 160,
            })
        );
    }

    #[test]
    fn a_waiting_port_has_no_far_end_and_takes_its_reach_from_where_it_listens() {
        let any = connection("System", 4, Direction::Listening, "0.0.0.0:445", None, 5);
        let local = connection("System", 4, Direction::Listening, "127.0.0.1:5000", None, 5);
        let (lines, _) = connections_view(vec![any, local], |_| Some("never.example".to_string()));
        let find = |port| lines.iter().find(|l| l.local_port == port).unwrap();
        assert_eq!(find(445).reach, Reach::Internet);
        assert_eq!(find(5000).reach, Reach::ThisPc);
        for line in &lines {
            assert_eq!(line.remote_address, None);
            assert_eq!(line.remote_port, None);
            assert_eq!(line.remote_name, None);
            assert_eq!(line.name, "System");
        }
    }

    #[test]
    fn names_are_asked_only_for_far_addresses_a_lookup_could_name() {
        let asked = std::cell::RefCell::new(Vec::new());
        let name_of = |ip: IpAddr| {
            asked.borrow_mut().push(ip);
            Some("name.example".to_string())
        };
        let lines = connections_view(
            vec![
                connection(
                    "a.exe",
                    1,
                    Direction::Outgoing,
                    "10.0.0.5:50000",
                    Some("8.8.8.8:53"),
                    1,
                ),
                connection(
                    "a.exe",
                    1,
                    Direction::Outgoing,
                    "127.0.0.1:50001",
                    Some("127.0.0.1:5000"),
                    2,
                ),
                connection(
                    "a.exe",
                    1,
                    Direction::Outgoing,
                    "[fe80::1%3]:50002",
                    Some("[fe80::2%3]:80"),
                    3,
                ),
            ],
            name_of,
        )
        .0;
        assert_eq!(
            asked.into_inner(),
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(lines.iter().filter(|l| l.remote_name.is_some()).count(), 1);
    }

    #[test]
    fn an_ipv4_address_in_ipv6_form_is_shown_as_ipv4() {
        let line = connections_view(
            vec![connection(
                "a.exe",
                1,
                Direction::Outgoing,
                "[::ffff:10.0.0.5]:50000",
                Some("[::ffff:93.184.216.34]:443"),
                1,
            )],
            none,
        )
        .0
        .remove(0);
        assert_eq!(line.remote_address.as_deref(), Some("93.184.216.34"));
        assert_eq!(line.local_address, "10.0.0.5");
        assert_eq!(line.reach, Reach::Internet);
    }

    #[test]
    fn a_program_windows_would_not_name_is_listed_by_process_id() {
        let line = connections_view(
            vec![connection(
                "",
                812,
                Direction::Outgoing,
                "10.0.0.5:50000",
                Some("8.8.8.8:443"),
                1,
            )],
            none,
        )
        .0
        .remove(0);
        assert_eq!(line.name, "Unknown (pid 812)");
        assert_eq!(line.path, "");
    }

    #[test]
    fn the_key_tells_flows_apart_by_ends_and_process() {
        let a = connection(
            "a.exe",
            1,
            Direction::Outgoing,
            "10.0.0.5:50000",
            Some("8.8.8.8:443"),
            1,
        );
        let mut b = a.clone();
        b.flow.pid = 2;
        let (lines, _) = connections_view(vec![a, b], none);
        assert_ne!(lines[0].key, lines[1].key);
    }
}
