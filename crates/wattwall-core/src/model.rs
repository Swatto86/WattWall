//! The window's list, built from firewall rules (what is blocked) and the
//! small memory of programs that have used the network.

use std::collections::BTreeMap;

use crate::danger::{guard, Guard};
use crate::pathutil::exe_name;

/// How many programs WattWall remembers after they disconnect.
/// Oldest ones that are not blocked are dropped past this.
pub const REMEMBERED_CAP: usize = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRecord {
    pub path: String,
    /// `true` when that direction's rule exists and is enabled.
    pub outbound_enabled: Option<bool>,
    pub inbound_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remembered {
    pub path: String,
    pub last_seen: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub path: String,
    pub name: String,
    pub blocked: bool,
    /// Both rules exist and are enabled, so the block is in force.
    pub enforced: bool,
    pub connected: bool,
    pub last_seen: Option<i64>,
    pub needs_confirmation: bool,
    pub cannot_block: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub blocked: Vec<Row>,
    pub seen: Vec<Row>,
    /// Every WattWall rule is switched off.
    pub suspended: bool,
    pub has_rules: bool,
}

pub fn new_rules_enabled(rules: &[RuleRecord]) -> bool {
    !suspended(rules)
}

pub fn suspended(rules: &[RuleRecord]) -> bool {
    let mut any = false;
    for rule in rules {
        if rule.outbound_enabled.is_some() || rule.inbound_enabled.is_some() {
            any = true;
        }
        if rule.outbound_enabled == Some(true) || rule.inbound_enabled == Some(true) {
            return false;
        }
    }
    any
}

/// Record programs seen on the network. Blocked programs are kept even past
/// the cap; the oldest unblocked ones are forgotten first.
pub fn remember(
    remembered: &mut Vec<Remembered>,
    connected: &[String],
    now: i64,
    blocked: &[String],
) {
    for path in connected {
        if path.trim().is_empty() {
            continue;
        }
        if let Some(existing) = remembered
            .iter_mut()
            .find(|item| same_path(&item.path, path))
        {
            existing.path = path.clone();
            existing.last_seen = now;
        } else {
            remembered.push(Remembered {
                path: path.clone(),
                last_seen: now,
            });
        }
    }
    if remembered.len() <= REMEMBERED_CAP {
        return;
    }
    remembered.sort_by_key(|item| item.last_seen);
    while remembered.len() > REMEMBERED_CAP {
        let victim = remembered
            .iter()
            .position(|item| !blocked.iter().any(|path| same_path(path, &item.path)));
        match victim {
            Some(index) => {
                remembered.remove(index);
            }
            None => break,
        }
    }
}

pub fn build_view(rules: &[RuleRecord], connected: &[String], remembered: &[Remembered]) -> View {
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();

    for rule in rules {
        if rule.path.trim().is_empty() {
            continue;
        }
        let row = rows
            .entry(key(&rule.path))
            .or_insert_with(|| empty_row(&rule.path));
        row.path = rule.path.clone();
        row.blocked = rule.outbound_enabled.is_some() || rule.inbound_enabled.is_some();
        row.enforced = rule.outbound_enabled == Some(true) && rule.inbound_enabled == Some(true);
    }

    for path in connected {
        if path.trim().is_empty() {
            continue;
        }
        let row = rows.entry(key(path)).or_insert_with(|| empty_row(path));
        row.path = path.clone();
        row.connected = true;
    }

    for item in remembered {
        if item.path.trim().is_empty() {
            continue;
        }
        let row = rows
            .entry(key(&item.path))
            .or_insert_with(|| empty_row(&item.path));
        if row.path.is_empty() {
            row.path = item.path.clone();
        }
        row.last_seen = Some(
            row.last_seen
                .map(|seen| seen.max(item.last_seen))
                .unwrap_or(item.last_seen),
        );
    }

    let mut blocked = Vec::new();
    let mut seen = Vec::new();
    for mut row in rows.into_values() {
        apply_guard(&mut row);
        if row.blocked {
            blocked.push(row);
        } else if row.connected || row.last_seen.is_some() {
            seen.push(row);
        }
    }
    blocked.sort_by_key(|row| row.name.to_ascii_lowercase());
    seen.sort_by(|a, b| {
        b.connected
            .cmp(&a.connected)
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
    });

    View {
        suspended: suspended(rules),
        has_rules: rules
            .iter()
            .any(|rule| rule.outbound_enabled.is_some() || rule.inbound_enabled.is_some()),
        blocked,
        seen,
    }
}

fn empty_row(path: &str) -> Row {
    let name = if path.eq_ignore_ascii_case("System") {
        "System".to_string()
    } else {
        exe_name(path).unwrap_or(path).to_string()
    };
    Row {
        path: path.to_string(),
        name,
        blocked: false,
        enforced: false,
        connected: false,
        last_seen: None,
        needs_confirmation: false,
        cannot_block: false,
    }
}

fn apply_guard(row: &mut Row) {
    let name = exe_name(&row.path).unwrap_or(&row.name);
    let is_system = row.path.eq_ignore_ascii_case("System") || name.eq_ignore_ascii_case("System");
    match guard(name, false, is_system) {
        Guard::Ok => {}
        Guard::Confirm(_) => row.needs_confirmation = true,
        Guard::Impossible(_) => row.cannot_block = true,
    }
}

fn key(path: &str) -> String {
    path.trim().to_ascii_lowercase()
}

fn same_path(left: &str, right: &str) -> bool {
    key(left) == key(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: &str, enabled: bool) -> RuleRecord {
        RuleRecord {
            path: path.to_string(),
            outbound_enabled: Some(enabled),
            inbound_enabled: Some(enabled),
        }
    }

    #[test]
    fn blocked_and_seen_are_separate_and_connected_sorts_first() {
        let rules = vec![rule(r"C:\Windows\System32\curl.exe", true)];
        let connected = vec![
            r"C:\Windows\System32\curl.exe".to_string(),
            r"C:\Windows\System32\ssh.exe".to_string(),
        ];
        let remembered = vec![Remembered {
            path: r"C:\Tools\old.exe".to_string(),
            last_seen: 10,
        }];
        let view = build_view(&rules, &connected, &remembered);
        assert_eq!(view.blocked.len(), 1);
        assert_eq!(view.blocked[0].name, "curl.exe");
        assert!(view.blocked[0].connected);
        assert!(view.blocked[0].enforced);
        assert!(!view.suspended);
        assert_eq!(view.seen.len(), 2);
        assert_eq!(view.seen[0].name, "ssh.exe");
        assert!(view.seen[0].connected);
        assert_eq!(view.seen[1].name, "old.exe");
        assert_eq!(view.seen[1].last_seen, Some(10));
    }

    #[test]
    fn all_off_is_every_rule_disabled() {
        let rules = vec![rule(r"C:\a\curl.exe", false), rule(r"C:\a\wget.exe", false)];
        assert!(suspended(&rules));
        assert!(!new_rules_enabled(&rules));
        let view = build_view(&rules, &[], &[]);
        assert!(view.suspended);
        assert!(!view.blocked[0].enforced);
        assert!(view.blocked[0].blocked);
    }

    #[test]
    fn one_enabled_rule_means_blocks_are_on() {
        let rules = vec![rule(r"C:\a\curl.exe", false), rule(r"C:\a\wget.exe", true)];
        assert!(!suspended(&rules));
        assert!(new_rules_enabled(&rules));
    }

    #[test]
    fn no_rules_means_a_new_block_is_enforced() {
        assert!(new_rules_enabled(&[]));
        assert!(!suspended(&[]));
    }

    #[test]
    fn remembered_list_drops_the_oldest_unblocked_program() {
        let mut remembered = Vec::new();
        let connected: Vec<String> = (0..REMEMBERED_CAP as i64)
            .map(|i| format!(r"C:\apps\{i}.exe"))
            .collect();
        remember(&mut remembered, &connected, 1, &[]);
        assert_eq!(remembered.len(), REMEMBERED_CAP);
        let blocked = vec![r"C:\apps\0.exe".to_string()];
        remember(
            &mut remembered,
            &[r"C:\apps\new.exe".to_string()],
            2,
            &blocked,
        );
        assert_eq!(remembered.len(), REMEMBERED_CAP);
        assert!(remembered.iter().any(|item| item.path.ends_with("new.exe")));
        assert!(remembered
            .iter()
            .any(|item| same_path(&item.path, r"C:\apps\0.exe")));
        assert!(!remembered
            .iter()
            .any(|item| same_path(&item.path, r"C:\apps\1.exe")));
    }

    #[test]
    fn system_cannot_be_blocked_and_svchost_needs_confirmation() {
        let view = build_view(
            &[],
            &[
                "System".to_string(),
                r"C:\Windows\System32\svchost.exe".to_string(),
            ],
            &[],
        );
        let system = view.seen.iter().find(|row| row.name == "System").unwrap();
        assert!(system.cannot_block);
        let host = view
            .seen
            .iter()
            .find(|row| row.name == "svchost.exe")
            .unwrap();
        assert!(host.needs_confirmation);
        assert!(!host.cannot_block);
    }
}
