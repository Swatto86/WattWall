//! A short memory of connections, so one that closed between two looks is
//! still listed, marked closed, for a minute. Kept in memory only: nothing
//! about who a PC talked to is written to disk.

use std::collections::HashMap;
use std::net::SocketAddr;

use super::flows::{Flow, Phase};
use super::socket::Protocol;

/// How long a closed connection stays listed.
pub const CLOSED_KEEP_SECS: i64 = 60;
/// Most closed connections remembered, newest kept.
const CLOSED_CAP: usize = 200;
/// A look this much later than the one before is a fresh start, not the next
/// step of a watch (looks come every two seconds while the view is open).
const STALE_AFTER_SECS: i64 = 10;

/// A flow, the program that owns it and when it was first and last seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub flow: Flow,
    /// The program's full path, `System` for process 4, or empty when Windows
    /// would not say.
    pub program: String,
    pub first_seen: i64,
    pub closed_at: Option<i64>,
}

/// Who a flow is: its protocol, both ends and its process. The process is part
/// of it so a reused process id is a new flow. The phase is not, so a
/// connection that moves from connecting to connected is the same flow.
type Key = (Protocol, SocketAddr, Option<SocketAddr>, u32);

fn key(flow: &Flow) -> Key {
    (flow.protocol, flow.local, flow.remote, flow.pid)
}

#[derive(Default)]
pub struct Tracker {
    live: HashMap<Key, Connection>,
    closed: Vec<Connection>,
    last_look: Option<i64>,
}

impl Tracker {
    /// Forget everything: the owner stopped watching.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Fold in a fresh look at the tables. Returns every live connection and
    /// every one that closed within the last `CLOSED_KEEP_SECS`, in no
    /// particular order. `programs` maps a process id to its program path.
    /// After a long gap between looks nothing that ended meanwhile is reported
    /// as closed: it would only say when the owner came back.
    ///
    /// A flow keeps the direction first inferred for it. The first look at a
    /// connection being set up knows the most (who sent the first packet); an
    /// open connection is judged by its ports, which can mislead for a program
    /// that connects out from the port it listens on.
    pub fn update(
        &mut self,
        flows: &[Flow],
        programs: &HashMap<u32, String>,
        now: i64,
    ) -> Vec<Connection> {
        if self
            .last_look
            .is_some_and(|last| now - last > STALE_AFTER_SECS)
        {
            self.reset();
        }
        self.last_look = Some(now);
        let mut live = HashMap::with_capacity(flows.len());
        for flow in flows {
            let earlier = self.live.get(&key(flow));
            live.insert(
                key(flow),
                Connection {
                    flow: Flow {
                        direction: earlier.map_or(flow.direction, |earlier| earlier.flow.direction),
                        ..*flow
                    },
                    program: programs.get(&flow.pid).cloned().unwrap_or_default(),
                    first_seen: earlier.map_or(now, |earlier| earlier.first_seen),
                    closed_at: None,
                },
            );
        }
        for (gone, earlier) in std::mem::take(&mut self.live) {
            if !live.contains_key(&gone) {
                self.closed.push(Connection {
                    flow: Flow {
                        phase: Phase::Closed,
                        ..earlier.flow
                    },
                    closed_at: Some(now),
                    ..earlier
                });
            }
        }
        self.live = live;

        // A flow that is back is live again; an old one is forgotten.
        let live = &self.live;
        self.closed.retain(|connection| {
            let age = now - connection.closed_at.unwrap_or(now);
            age <= CLOSED_KEEP_SECS && !live.contains_key(&key(&connection.flow))
        });
        if self.closed.len() > CLOSED_CAP {
            self.closed.sort_by_key(|connection| connection.closed_at);
            let excess = self.closed.len() - CLOSED_CAP;
            self.closed.drain(..excess);
        }

        self.live
            .values()
            .chain(self.closed.iter())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::flows::Direction;

    fn flow(local: &str, remote: &str, pid: u32) -> Flow {
        Flow {
            protocol: Protocol::Tcp,
            direction: Direction::Outgoing,
            phase: Phase::Connected,
            local: local.parse().unwrap(),
            remote: Some(remote.parse().unwrap()),
            pid,
        }
    }

    fn programs() -> HashMap<u32, String> {
        HashMap::from([(7, r"C:\Tools\curl.exe".to_string())])
    }

    fn closed(connections: &[Connection]) -> Vec<&Connection> {
        connections
            .iter()
            .filter(|c| c.closed_at.is_some())
            .collect()
    }

    #[test]
    fn a_new_flow_is_live_and_first_seen_now() {
        let mut tracker = Tracker::default();
        let out = tracker.update(
            &[flow("10.0.0.5:50000", "1.2.3.4:443", 7)],
            &programs(),
            100,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].first_seen, 100);
        assert_eq!(out[0].closed_at, None);
        assert_eq!(out[0].program, r"C:\Tools\curl.exe");
    }

    #[test]
    fn a_flow_keeps_its_first_seen_time_while_its_phase_changes() {
        let mut tracker = Tracker::default();
        let mut connecting = flow("10.0.0.5:50000", "1.2.3.4:443", 7);
        connecting.phase = Phase::Connecting;
        tracker.update(&[connecting], &programs(), 100);
        let out = tracker.update(
            &[flow("10.0.0.5:50000", "1.2.3.4:443", 7)],
            &programs(),
            103,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].first_seen, 100);
        assert_eq!(out[0].flow.phase, Phase::Connected);
    }

    #[test]
    fn a_flow_that_vanishes_is_listed_closed_for_a_minute() {
        let mut tracker = Tracker::default();
        let one = flow("10.0.0.5:50000", "1.2.3.4:443", 7);
        tracker.update(&[one], &programs(), 100);
        let out = tracker.update(&[], &programs(), 103);
        let gone = closed(&out);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].flow.phase, Phase::Closed);
        assert_eq!(gone[0].closed_at, Some(103));
        assert_eq!(gone[0].first_seen, 100);
        assert_eq!(gone[0].program, r"C:\Tools\curl.exe");
        // Looks come every two seconds while the view is open.
        let mut now = 103;
        while now < 103 + CLOSED_KEEP_SECS {
            now += 2;
            let still = tracker.update(&[], &programs(), now);
            assert_eq!(
                still.len(),
                usize::from(now <= 103 + CLOSED_KEEP_SECS),
                "at {now}"
            );
        }
        assert!(tracker.update(&[], &programs(), now + 2).is_empty());
    }

    #[test]
    fn a_flow_that_comes_back_is_live_and_not_also_closed() {
        let mut tracker = Tracker::default();
        let one = flow("10.0.0.5:50000", "1.2.3.4:443", 7);
        tracker.update(&[one], &programs(), 100);
        tracker.update(&[], &programs(), 103);
        let out = tracker.update(&[one], &programs(), 106);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].closed_at, None);
        assert_eq!(out[0].first_seen, 106);
    }

    #[test]
    fn a_reused_process_id_is_a_different_flow() {
        let mut tracker = Tracker::default();
        tracker.update(
            &[flow("10.0.0.5:50000", "1.2.3.4:443", 7)],
            &programs(),
            100,
        );
        let out = tracker.update(
            &[flow("10.0.0.5:50000", "1.2.3.4:443", 8)],
            &programs(),
            103,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(closed(&out).len(), 1);
        assert_eq!(closed(&out)[0].flow.pid, 7);
    }

    #[test]
    fn a_pid_with_no_known_program_has_an_empty_program() {
        let mut tracker = Tracker::default();
        let out = tracker.update(
            &[flow("10.0.0.5:50000", "1.2.3.4:443", 99)],
            &programs(),
            100,
        );
        assert_eq!(out[0].program, "");
    }

    #[test]
    fn a_long_pause_is_a_fresh_start_not_a_burst_of_closures() {
        let mut tracker = Tracker::default();
        let many: Vec<Flow> = (0..5)
            .map(|n| flow(&format!("10.0.0.5:{}", 50000 + n), "1.2.3.4:443", 7))
            .collect();
        tracker.update(&many, &programs(), 100);
        // The owner left the view for an hour: what ended meanwhile is not news.
        let back = tracker.update(&[], &programs(), 100 + 3600);
        assert!(back.is_empty(), "{back:?}");
        // And what is still there is new again.
        let again = tracker.update(&many, &programs(), 100 + 3602);
        assert_eq!(again.len(), 5);
        assert!(again
            .iter()
            .all(|c| c.first_seen == 100 + 3602 && c.closed_at.is_none()));
    }

    #[test]
    fn looks_a_few_seconds_apart_are_still_one_continuous_watch() {
        let mut tracker = Tracker::default();
        let one = flow("10.0.0.5:50000", "1.2.3.4:443", 7);
        tracker.update(&[one], &programs(), 100);
        let out = tracker.update(&[], &programs(), 100 + STALE_AFTER_SECS);
        assert_eq!(closed(&out).len(), 1);
    }

    #[test]
    fn resetting_forgets_everything() {
        let mut tracker = Tracker::default();
        tracker.update(
            &[flow("10.0.0.5:50000", "1.2.3.4:443", 7)],
            &programs(),
            100,
        );
        tracker.update(&[], &programs(), 101);
        tracker.reset();
        assert!(tracker.update(&[], &programs(), 102).is_empty());
    }

    #[test]
    fn a_flow_keeps_the_direction_first_inferred_for_it() {
        // Connecting out from a port the program also listens on: the SYN says
        // outgoing, and once open the port rule would say incoming.
        let mut tracker = Tracker::default();
        let mut setting_up = flow("10.0.0.5:6881", "1.2.3.4:6881", 7);
        setting_up.phase = Phase::Connecting;
        tracker.update(&[setting_up], &programs(), 100);
        let mut open = setting_up;
        open.phase = Phase::Connected;
        open.direction = Direction::Incoming;
        let out = tracker.update(&[open], &programs(), 102);
        assert_eq!(out[0].flow.direction, Direction::Outgoing);
        assert_eq!(out[0].flow.phase, Phase::Connected);

        // An accepted connection stays incoming when its listener closes.
        let mut accepted = flow("10.0.0.5:2121", "9.9.9.9:50000", 8);
        accepted.direction = Direction::Incoming;
        tracker.update(&[accepted], &programs(), 104);
        accepted.direction = Direction::Outgoing;
        let out = tracker.update(&[accepted], &programs(), 106);
        let kept = out.iter().find(|c| c.flow.pid == 8).unwrap();
        assert_eq!(kept.flow.direction, Direction::Incoming);
    }

    #[test]
    fn only_the_newest_closed_flows_are_kept() {
        // Five flows replaced every second for 50 seconds: 245 closures inside
        // the minute, more than the cap.
        let mut tracker = Tracker::default();
        let mut out = Vec::new();
        for tick in 0..50u16 {
            let now = 100 + i64::from(tick);
            let flows: Vec<Flow> = (0..5)
                .map(|n| {
                    flow(
                        &format!("10.0.0.5:{}", 40000 + tick * 5 + n),
                        "1.2.3.4:443",
                        7,
                    )
                })
                .collect();
            out = tracker.update(&flows, &programs(), now);
        }
        let gone = closed(&out);
        assert_eq!(gone.len(), CLOSED_CAP);
        // The 45 oldest closures (seconds 101 to 109) were dropped.
        let oldest = gone.iter().filter_map(|c| c.closed_at).min();
        assert_eq!(oldest, Some(110));
        assert_eq!(out.len(), CLOSED_CAP + 5);
    }
}
