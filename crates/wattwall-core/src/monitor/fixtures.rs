//! Connections made up for tests.

use crate::monitor::flows::{Direction, Flow, Phase};
use crate::monitor::socket::Protocol;
use crate::monitor::tracker::Connection;

pub fn connection(
    program: &str,
    pid: u32,
    direction: Direction,
    local: &str,
    remote: Option<&str>,
    first_seen: i64,
) -> Connection {
    Connection {
        flow: Flow {
            protocol: Protocol::Tcp,
            direction,
            phase: if direction == Direction::Listening {
                Phase::Listening
            } else {
                Phase::Connected
            },
            local: local.parse().unwrap(),
            remote: remote.map(|text| text.parse().unwrap()),
            pid,
        },
        program: program.to_string(),
        first_seen,
        closed_at: None,
    }
}
