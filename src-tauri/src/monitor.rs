//! The network monitor's side of the window: the commands it calls, and what
//! is kept between two looks (which connections have closed, which host names
//! are known). `sockets.rs` reads the tables, `dns.rs` asks DNS, and what a
//! connection is, which way it goes and how it is listed is decided in
//! `wattwall_core::monitor`.

use std::path::Path;
use std::sync::Mutex;

use tauri::State;
use wattwall_core::monitor::{classify, connections_view, worth_resolving, MonitorDto, Tracker};

use crate::dns::Names;
use crate::engine::unix_now;
use crate::net::Connections;
use crate::resolver::Resolver;
use crate::{snapshot, StateDto, Watt};

pub struct Monitor {
    tracker: Mutex<Tracker>,
    pub names: Names,
}

impl Monitor {
    pub fn open(test_copy: bool, dir: &Path) -> Self {
        let resolver = if test_copy {
            Resolver::Fake(dir.to_path_buf())
        } else {
            Resolver::Live
        };
        Self {
            tracker: Mutex::new(Tracker::default()),
            names: Names::new(resolver),
        }
    }

    /// The owner stopped looking at the view. What waited for a host-name
    /// lookup is forgotten, and so is the list of closed connections: nothing
    /// is asked until the view is open again, and what ended in the meantime
    /// is not news when it is.
    pub fn close(&self) {
        self.names.cancel_waiting();
        if let Ok(mut tracker) = self.tracker.lock() {
            tracker.reset();
        }
    }

    /// Look at the tables now. Names come from what lookups have found so far;
    /// addresses not yet answered are queued and will have names on a later look.
    fn look(&self, connections: &Connections, names_on: bool) -> Result<MonitorDto, String> {
        let looked = connections.sockets()?;
        let flows = classify(&looked.rows);
        let now = unix_now();
        if names_on {
            self.names.ask(
                flows
                    .iter()
                    .filter_map(|flow| flow.remote)
                    .map(|remote| remote.ip())
                    .filter(|ip| worth_resolving(*ip)),
                now,
            );
        } else {
            self.names.cancel_waiting();
        }
        let seen = self
            .tracker
            .lock()
            .map_err(|_| "WattWall's connection list lock failed.".to_string())?
            .update(&flows, &looked.programs, now);
        let (connections, truncated) =
            connections_view(seen, |ip| if names_on { self.names.name(ip) } else { None });
        Ok(MonitorDto {
            connections,
            truncated,
            names: names_on,
            pending_names: if names_on { self.names.pending() } else { 0 },
            now,
        })
    }
}

/// Every connection and waiting port now, and those that closed in the last
/// minute; null while the window is hidden in the tray or minimized, when
/// nobody is looking and nothing is read or asked of DNS. Reading the tables
/// and mapping each process to its program takes a few milliseconds, so it
/// runs off the window's thread.
#[tauri::command(async)]
pub fn monitor_snapshot(
    window: tauri::WebviewWindow,
    state: State<Watt>,
) -> Result<Option<MonitorDto>, String> {
    // A minimized window still counts as visible, so both are asked.
    let watching = window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false);
    if !watching {
        state.monitor.close();
        return Ok(None);
    }
    state
        .monitor
        .look(&state.engine.connections, state.engine.resolve_names())
        .map(Some)
}

/// The window left the Connections view: nothing is read or asked of DNS
/// until it is opened again.
#[tauri::command]
pub fn monitor_close(state: State<Watt>) {
    state.monitor.close();
}

/// Turn host-name lookups on or off. Off asks DNS nothing more at once, even
/// of what was already waiting, and the window shows addresses only.
#[tauri::command]
pub fn set_resolve_names(state: State<Watt>, enabled: bool) -> Result<StateDto, String> {
    state.engine.set_resolve_names(enabled)?;
    if !enabled {
        state.monitor.names.cancel_waiting();
    }
    snapshot(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, Instant};
    use wattwall_core::monitor::{ConnectionDto, Direction, Phase};

    const SOCKETS: &str = r#"[
      {"path": "C:\\Tools\\curl.exe", "pid": 7, "protocol": "tcp", "state": "established",
       "local": "192.168.1.20:50123", "remote": "203.0.113.7:443"},
      {"path": "C:\\Tools\\srv.exe", "pid": 8, "protocol": "tcp", "state": "listen", "local": "0.0.0.0:3389"},
      {"path": "C:\\Tools\\srv.exe", "pid": 8, "protocol": "tcp", "state": "established",
       "local": "192.168.1.20:3389", "remote": "198.51.100.9:50000"},
      {"path": "C:\\Tools\\srv.exe", "pid": 8, "protocol": "udp", "local": "0.0.0.0:5353"},
      {"path": "C:\\Tools\\curl.exe", "pid": 7, "protocol": "tcp", "state": "established",
       "local": "127.0.0.1:50200", "remote": "127.0.0.1:8080"}
    ]"#;

    fn find<'a>(lines: &'a [ConnectionDto], program: &str, port: u16) -> &'a ConnectionDto {
        lines
            .iter()
            .find(|line| line.name == program && line.local_port == port)
            .unwrap_or_else(|| panic!("no {program} line on port {port}"))
    }

    fn look_until(
        monitor: &Monitor,
        connections: &Connections,
        what: &str,
        done: impl Fn(&MonitorDto) -> bool,
    ) -> MonitorDto {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let seen = monitor.look(connections, true).unwrap();
            if done(&seen) {
                return seen;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The whole path the Connections view takes, minus the window: sockets
    /// from a file, directions, names from background lookups, a connection
    /// that closes, and names turned off.
    #[test]
    fn a_look_lists_directions_names_and_closures_and_obeys_the_names_switch() {
        let dir = std::env::temp_dir().join(format!("wattwall-monitor-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("fake-sockets.json"), SOCKETS).unwrap();
        fs::write(
            dir.join("fake-dns.json"),
            r#"{"203.0.113.7": "example.test", "127.0.0.1": "must-not-be-asked.test"}"#,
        )
        .unwrap();
        let connections = Connections::Fake(dir.clone());
        let monitor = Monitor::open(true, &dir);
        monitor.names.start_workers().unwrap();

        let seen = look_until(&monitor, &connections, "a host name", |seen| {
            seen.connections
                .iter()
                .any(|line| line.remote_name.is_some())
        });
        let lines = &seen.connections;
        assert!(seen.names && !seen.truncated);
        let curl = find(lines, "curl.exe", 50123);
        assert_eq!(curl.direction, Direction::Outgoing);
        assert_eq!(curl.remote_name.as_deref(), Some("example.test"));
        assert_eq!(curl.remote_address.as_deref(), Some("203.0.113.7"));
        assert_eq!(curl.remote_port, Some(443));
        assert_eq!(curl.path, r"C:\Tools\curl.exe");
        assert!(lines
            .iter()
            .any(|line| line.local_port == 3389 && line.direction == Direction::Listening));
        let accepted = lines
            .iter()
            .find(|line| line.local_port == 3389 && line.remote_port == Some(50000))
            .unwrap();
        assert_eq!(accepted.direction, Direction::Incoming);
        assert_eq!(accepted.remote_name, None, "no name is on record for it");
        assert_eq!(find(lines, "srv.exe", 5353).remote_address, None);
        let loopback = find(lines, "curl.exe", 50200);
        assert_eq!(
            loopback.remote_name, None,
            "this PC's own address is not looked up"
        );

        // A connection that goes away stays listed, closed.
        let without_curl = SOCKETS.replace("192.168.1.20:50123", "192.168.1.20:50999");
        fs::write(dir.join("fake-sockets.json"), without_curl).unwrap();
        let after = monitor.look(&connections, true).unwrap();
        let closed = find(&after.connections, "curl.exe", 50123);
        assert_eq!(closed.phase, Phase::Closed);
        assert!(closed.closed_at.is_some());
        assert_eq!(
            find(&after.connections, "curl.exe", 50999).phase,
            Phase::Connected
        );

        // Leaving the view forgets the closed list and what waited to be asked.
        monitor.close();
        assert_eq!(monitor.names.pending(), 0);
        let fresh = monitor.look(&connections, true).unwrap();
        assert!(
            fresh
                .connections
                .iter()
                .all(|line| line.closed_at.is_none()),
            "closed connections are not carried across a close"
        );

        // Names off: no names shown, and nothing more is asked of DNS.
        let asked = || {
            fs::read_to_string(dir.join("fake-dns-calls.log"))
                .unwrap()
                .lines()
                .count()
        };
        let before = asked();
        let off = monitor.look(&connections, false).unwrap();
        assert!(!off.names);
        assert_eq!(off.pending_names, 0);
        assert!(off
            .connections
            .iter()
            .all(|line| line.remote_name.is_none()));
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(asked(), before);
        // 203.0.113.7 and 198.51.100.9 only: once each, and never the loopback address.
        let log = fs::read_to_string(dir.join("fake-dns-calls.log")).unwrap();
        assert!(!log.contains("127.0.0.1"));
        assert_eq!(log.matches("203.0.113.7").count(), 1);

        monitor.names.stop();
        fs::remove_dir_all(&dir).unwrap();
    }
}
