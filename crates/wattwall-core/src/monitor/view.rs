//! The order the window shows connections in, and what is kept when there
//! are too many.

use std::cmp::Ordering;
use std::net::IpAddr;

use super::dto::{key, line, program_name, ConnectionDto};
use super::flows::Direction;
use super::tracker::Connection;

/// Most connections sent to the window at once.
pub const MAX_ROWS: usize = 2000;

/// Lines for the window. `name_of` gives the host name already found for an
/// address; it is asked only for addresses a lookup could name. If there are
/// more than `MAX_ROWS`, open connections are kept before waiting ports, and
/// those before closed ones, oldest first, so what is cut never depends on
/// the order the connections arrived in. The second value says whether any
/// were left out.
pub fn connections_view(
    connections: Vec<Connection>,
    name_of: impl Fn(IpAddr) -> Option<String>,
) -> (Vec<ConnectionDto>, bool) {
    let mut keyed: Vec<(String, Connection)> = connections
        .into_iter()
        .map(|connection| (key(&connection), connection))
        .collect();
    keyed.sort_by(|(key_a, a), (key_b, b)| {
        importance(a)
            .cmp(&importance(b))
            .then_with(|| a.first_seen.cmp(&b.first_seen))
            .then_with(|| key_a.cmp(key_b))
    });
    let truncated = keyed.len() > MAX_ROWS;
    keyed.truncate(MAX_ROWS);
    keyed.sort_by(|(key_a, a), (key_b, b)| display_order(a, b).then_with(|| key_a.cmp(key_b)));
    let lines = keyed
        .into_iter()
        .map(|(key, connection)| line(&connection, key, &name_of))
        .collect();
    (lines, truncated)
}

fn importance(connection: &Connection) -> u8 {
    match (connection.closed_at, connection.flow.direction) {
        (Some(_), _) => 2,
        (None, Direction::Listening) => 1,
        (None, _) => 0,
    }
}

/// By program, then process, then incoming before outgoing before waiting
/// ports, then oldest first. Nothing in it changes while a connection lives
/// or closes, and names are not in it, so a line stays where it is when its
/// state changes or its name arrives.
fn display_order(a: &Connection, b: &Connection) -> Ordering {
    let rank = |connection: &Connection| match connection.flow.direction {
        Direction::Incoming => 0,
        Direction::Outgoing => 1,
        Direction::Listening => 2,
    };
    let program = |connection: &Connection| program_name(&connection.program, connection.flow.pid);
    program(a)
        .to_ascii_lowercase()
        .cmp(&program(b).to_ascii_lowercase())
        .then_with(|| {
            a.program
                .to_ascii_lowercase()
                .cmp(&b.program.to_ascii_lowercase())
        })
        .then_with(|| a.flow.pid.cmp(&b.flow.pid))
        .then_with(|| rank(a).cmp(&rank(b)))
        .then_with(|| a.first_seen.cmp(&b.first_seen))
        .then_with(|| a.flow.local.to_string().cmp(&b.flow.local.to_string()))
        .then_with(|| remote_text(a).cmp(&remote_text(b)))
}

fn remote_text(connection: &Connection) -> String {
    connection
        .flow
        .remote
        .map(|remote| remote.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::fixtures::connection;
    use crate::monitor::flows::Phase;
    use crate::monitor::socket::Protocol;

    fn none(_: IpAddr) -> Option<String> {
        None
    }

    #[test]
    fn lines_run_by_program_then_direction_then_age_and_do_not_move_when_a_name_arrives() {
        let make = || {
            vec![
                connection(
                    r"C:\b\zeta.exe",
                    9,
                    Direction::Outgoing,
                    "10.0.0.5:50003",
                    Some("8.8.4.4:443"),
                    30,
                ),
                connection(
                    r"C:\a\Alpha.exe",
                    2,
                    Direction::Listening,
                    "0.0.0.0:80",
                    None,
                    1,
                ),
                connection(
                    r"C:\a\Alpha.exe",
                    2,
                    Direction::Outgoing,
                    "10.0.0.5:50002",
                    Some("1.1.1.1:443"),
                    20,
                ),
                connection(
                    r"C:\a\Alpha.exe",
                    2,
                    Direction::Incoming,
                    "10.0.0.5:80",
                    Some("9.9.9.9:41000"),
                    40,
                ),
                connection(
                    r"C:\a\Alpha.exe",
                    2,
                    Direction::Outgoing,
                    "10.0.0.5:50001",
                    Some("1.0.0.1:443"),
                    10,
                ),
            ]
        };
        let order =
            |lines: &[ConnectionDto]| lines.iter().map(|l| l.local_port).collect::<Vec<_>>();
        let before = connections_view(make(), none).0;
        assert_eq!(order(&before), vec![80, 50001, 50002, 80, 50003]);
        assert_eq!(before[0].direction, Direction::Incoming);
        assert_eq!(before[3].direction, Direction::Listening);
        let named = connections_view(make(), |ip| Some(format!("z{ip}.example"))).0;
        assert_eq!(order(&named), order(&before));
    }

    #[test]
    fn a_tcp_and_a_udp_port_on_one_address_keep_a_fixed_order() {
        let tcp = connection("p2p.exe", 5, Direction::Listening, "0.0.0.0:6881", None, 1);
        let mut udp = tcp.clone();
        udp.flow.protocol = Protocol::Udp;
        let one = connections_view(vec![tcp.clone(), udp.clone()], none).0;
        let other = connections_view(vec![udp, tcp], none).0;
        assert_eq!(one, other);
        assert_eq!(one[0].protocol, Protocol::Tcp);
    }

    #[test]
    fn which_lines_survive_truncation_does_not_depend_on_the_order_they_arrive_in() {
        let make = || -> Vec<Connection> {
            (0..MAX_ROWS + 400)
                .map(|n| {
                    connection(
                        "a.exe",
                        1,
                        Direction::Outgoing,
                        &format!("10.0.{}.{}:{}", n / 250, n % 250, 40000 + n % 20000),
                        Some("8.8.8.8:443"),
                        i64::try_from(n % 7).unwrap(),
                    )
                })
                .collect()
        };
        let forward = connections_view(make(), none);
        let mut backwards = make();
        backwards.reverse();
        let reversed = connections_view(backwards, none);
        assert!(forward.1 && reversed.1);
        assert_eq!(forward.0.len(), MAX_ROWS);
        assert_eq!(forward.0, reversed.0);
    }

    #[test]
    fn past_the_limit_open_connections_win_over_waiting_ports_over_closed_ones() {
        let mut all = Vec::new();
        for n in 0..MAX_ROWS {
            let mut closed = connection(
                "a.exe",
                1,
                Direction::Outgoing,
                &format!("10.0.0.5:{}", 10000 + n % 50000),
                Some("8.8.8.8:443"),
                1,
            );
            closed.closed_at = Some(2);
            closed.flow.phase = Phase::Closed;
            all.push(closed);
        }
        all.push(connection(
            "b.exe",
            2,
            Direction::Listening,
            "0.0.0.0:80",
            None,
            1,
        ));
        all.push(connection(
            "b.exe",
            2,
            Direction::Outgoing,
            "10.0.0.5:60000",
            Some("1.1.1.1:443"),
            1,
        ));
        let (lines, truncated) = connections_view(all, none);
        assert!(truncated);
        assert_eq!(lines.len(), MAX_ROWS);
        assert!(lines
            .iter()
            .any(|l| l.local_port == 60000 && l.closed_at.is_none()));
        assert!(lines
            .iter()
            .any(|l| l.local_port == 80 && l.direction == Direction::Listening));
    }
}
