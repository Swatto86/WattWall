//! The bookkeeping behind host-name lookups: which addresses to ask about,
//! what came back and when to ask again. It does no lookup itself. The
//! Windows crate asks DNS from worker threads and reports each answer here.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// A name that was found is trusted this long (seconds).
const FOUND_TTL: i64 = 3600;
/// An address that has no name is not asked about again for this long.
const MISSING_TTL: i64 = 600;
/// A lookup that failed for a reason that may pass, such as no DNS server
/// answering, is tried again sooner.
const TEMPORARY_TTL: i64 = 120;
/// Addresses waiting for a lookup, at most.
const QUEUE_CAP: usize = 256;
/// Answers remembered, at most. The oldest go first.
const ENTRY_CAP: usize = 4096;

/// Why a lookup gave no name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// DNS answered that the address has no name.
    NotFound,
    /// DNS did not answer, or the lookup failed some other way.
    Temporary,
}

struct Entry {
    name: Option<String>,
    retry_at: i64,
    /// When this was recorded, for dropping the oldest.
    at: i64,
}

#[derive(Default)]
pub struct NameCache {
    entries: HashMap<IpAddr, Entry>,
    queue: VecDeque<IpAddr>,
    waiting: HashSet<IpAddr>,
    in_flight: HashSet<IpAddr>,
}

impl NameCache {
    /// The name last found for an address. A name past its time stays until a
    /// fresh lookup replaces it, so a row does not flicker back to a number.
    pub fn name(&self, address: IpAddr) -> Option<&str> {
        self.entries.get(&address.to_canonical())?.name.as_deref()
    }

    /// Say which addresses are wanted now: those with no current answer that
    /// are not being looked up already. What waited for an earlier call and
    /// is not asked for again is forgotten, so a connection that has gone is
    /// never looked up and one that is on screen never waits behind it. Once
    /// `QUEUE_CAP` are waiting the rest are left for a later call, so a busy
    /// PC cannot flood the DNS server.
    pub fn want(&mut self, addresses: impl IntoIterator<Item = IpAddr>, now: i64) {
        self.cancel_waiting();
        for address in addresses {
            if self.queue.len() >= QUEUE_CAP {
                break;
            }
            let address = address.to_canonical();
            if self.waiting.contains(&address) || self.in_flight.contains(&address) {
                continue;
            }
            if self
                .entries
                .get(&address)
                .is_some_and(|entry| now < entry.retry_at)
            {
                continue;
            }
            self.waiting.insert(address);
            self.queue.push_back(address);
        }
    }

    /// The next address to look up, now counted as being looked up.
    pub fn start_lookup(&mut self) -> Option<IpAddr> {
        let address = self.queue.pop_front()?;
        self.waiting.remove(&address);
        self.in_flight.insert(address);
        Some(address)
    }

    /// Record what a lookup found. A temporary failure keeps any earlier name.
    pub fn finish(&mut self, address: IpAddr, outcome: Result<String, Failure>, now: i64) {
        let address = address.to_canonical();
        self.in_flight.remove(&address);
        let entry = match outcome {
            Ok(name) => Entry {
                name: Some(name),
                retry_at: now + FOUND_TTL,
                at: now,
            },
            Err(Failure::NotFound) => Entry {
                name: None,
                retry_at: now + MISSING_TTL,
                at: now,
            },
            Err(Failure::Temporary) => Entry {
                name: self.entries.get(&address).and_then(|old| old.name.clone()),
                retry_at: now + TEMPORARY_TTL,
                at: now,
            },
        };
        self.entries.insert(address, entry);
        self.forget_the_oldest();
    }

    /// Lookups queued or running.
    pub fn pending(&self) -> usize {
        self.queue.len() + self.in_flight.len()
    }

    /// Drop the lookups still waiting, for when names are turned off. Those
    /// already running finish and are kept.
    pub fn cancel_waiting(&mut self) {
        self.queue.clear();
        self.waiting.clear();
    }

    fn forget_the_oldest(&mut self) {
        if self.entries.len() <= ENTRY_CAP {
            return;
        }
        let mut by_age: Vec<(i64, IpAddr)> = self
            .entries
            .iter()
            .map(|(address, entry)| (entry.at, *address))
            .collect();
        by_age.sort_unstable();
        // Drop a tenth more than the excess so this is not redone every time.
        let drop = self.entries.len() - ENTRY_CAP + ENTRY_CAP / 10;
        for (_, address) in by_age.into_iter().take(drop) {
            self.entries.remove(&address);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_address_is_queued_once_and_counted_while_it_waits_and_runs() {
        let mut cache = NameCache::default();
        cache.want([ip("8.8.8.8"), ip("8.8.8.8"), ip("1.1.1.1")], 100);
        assert_eq!(cache.pending(), 2);
        assert_eq!(cache.start_lookup(), Some(ip("8.8.8.8")));
        // Running now: asking again, as every look does, does not queue it a second time.
        cache.want([ip("8.8.8.8"), ip("1.1.1.1")], 101);
        assert_eq!(cache.pending(), 2);
        assert_eq!(cache.start_lookup(), Some(ip("1.1.1.1")));
        assert_eq!(cache.start_lookup(), None);
        cache.finish(ip("8.8.8.8"), Ok("dns.google".into()), 102);
        cache.finish(ip("1.1.1.1"), Ok("one.one.one.one".into()), 102);
        assert_eq!(cache.pending(), 0);
    }

    #[test]
    fn a_found_name_is_used_until_it_is_due_and_then_asked_for_again() {
        let mut cache = NameCache::default();
        cache.want([ip("8.8.8.8")], 100);
        cache.start_lookup();
        cache.finish(ip("8.8.8.8"), Ok("dns.google".into()), 100);
        assert_eq!(cache.name(ip("8.8.8.8")), Some("dns.google"));
        cache.want([ip("8.8.8.8")], 100 + FOUND_TTL - 1);
        assert_eq!(cache.pending(), 0);
        cache.want([ip("8.8.8.8")], 100 + FOUND_TTL);
        assert_eq!(cache.pending(), 1);
        // The old name stays on show while the new lookup runs.
        assert_eq!(cache.name(ip("8.8.8.8")), Some("dns.google"));
    }

    #[test]
    fn no_name_is_remembered_for_ten_minutes() {
        let mut cache = NameCache::default();
        cache.want([ip("203.0.113.9")], 100);
        cache.start_lookup();
        cache.finish(ip("203.0.113.9"), Err(Failure::NotFound), 100);
        assert_eq!(cache.name(ip("203.0.113.9")), None);
        cache.want([ip("203.0.113.9")], 100 + MISSING_TTL - 1);
        assert_eq!(cache.pending(), 0);
        cache.want([ip("203.0.113.9")], 100 + MISSING_TTL);
        assert_eq!(cache.pending(), 1);
    }

    #[test]
    fn a_failure_that_may_pass_is_retried_sooner_and_keeps_the_old_name() {
        let mut cache = NameCache::default();
        cache.want([ip("8.8.8.8")], 100);
        cache.start_lookup();
        cache.finish(ip("8.8.8.8"), Ok("dns.google".into()), 100);
        cache.want([ip("8.8.8.8")], 100 + FOUND_TTL);
        cache.start_lookup();
        cache.finish(ip("8.8.8.8"), Err(Failure::Temporary), 100 + FOUND_TTL);
        assert_eq!(cache.name(ip("8.8.8.8")), Some("dns.google"));
        cache.want([ip("8.8.8.8")], 100 + FOUND_TTL + TEMPORARY_TTL);
        assert_eq!(cache.pending(), 1);
    }

    #[test]
    fn a_name_not_found_replaces_an_old_name() {
        let mut cache = NameCache::default();
        cache.want([ip("198.51.100.7")], 0);
        cache.start_lookup();
        cache.finish(ip("198.51.100.7"), Ok("old.example".into()), 0);
        cache.want([ip("198.51.100.7")], FOUND_TTL);
        cache.start_lookup();
        cache.finish(ip("198.51.100.7"), Err(Failure::NotFound), FOUND_TTL);
        assert_eq!(cache.name(ip("198.51.100.7")), None);
    }

    #[test]
    fn an_ipv4_address_in_ipv6_form_is_the_same_address() {
        let mut cache = NameCache::default();
        cache.want([ip("::ffff:8.8.8.8"), ip("8.8.8.8")], 0);
        assert_eq!(cache.pending(), 1);
        let asked = cache.start_lookup().unwrap();
        assert_eq!(asked, ip("8.8.8.8"));
        cache.finish(ip("::ffff:8.8.8.8"), Ok("dns.google".into()), 0);
        assert_eq!(cache.name(ip("8.8.8.8")), Some("dns.google"));
        assert_eq!(cache.name(ip("::ffff:8.8.8.8")), Some("dns.google"));
    }

    #[test]
    fn the_queue_is_bounded_and_the_rest_wait_for_a_later_call() {
        let mut cache = NameCache::default();
        let many: Vec<IpAddr> = (0..QUEUE_CAP + 40)
            .map(|n| ip(&format!("10.1.{}.{}", n / 250, n % 250 + 1)))
            .collect();
        cache.want(many.iter().copied(), 0);
        assert_eq!(cache.pending(), QUEUE_CAP);
        // Work off some, and the next call takes up where the first stopped:
        // every address not yet answered is now waiting.
        for _ in 0..50 {
            let asked = cache.start_lookup().unwrap();
            cache.finish(asked, Err(Failure::NotFound), 1);
        }
        cache.want(many.iter().copied(), 2);
        assert_eq!(cache.pending(), many.len() - 50);
    }

    #[test]
    fn asking_again_replaces_what_is_waiting_so_nothing_stale_is_looked_up() {
        let mut cache = NameCache::default();
        cache.want([ip("1.1.1.1"), ip("2.2.2.2"), ip("3.3.3.3")], 0);
        cache.want([ip("3.3.3.3"), ip("4.4.4.4")], 1);
        assert_eq!(cache.pending(), 2);
        assert_eq!(cache.start_lookup(), Some(ip("3.3.3.3")));
        assert_eq!(cache.start_lookup(), Some(ip("4.4.4.4")));
        assert_eq!(cache.start_lookup(), None);
    }

    #[test]
    fn an_address_that_is_no_longer_wanted_does_not_hold_up_one_that_is() {
        let mut cache = NameCache::default();
        let stale: Vec<IpAddr> = (1..=200).map(|n| ip(&format!("10.9.0.{n}"))).collect();
        cache.want(stale, 0);
        cache.want([ip("8.8.8.8")], 1);
        assert_eq!(cache.pending(), 1);
        assert_eq!(cache.start_lookup(), Some(ip("8.8.8.8")));
    }

    #[test]
    fn an_address_being_looked_up_stays_looked_up_when_the_queue_is_replaced() {
        let mut cache = NameCache::default();
        cache.want([ip("8.8.8.8"), ip("1.1.1.1")], 0);
        assert_eq!(cache.start_lookup(), Some(ip("8.8.8.8")));
        cache.want([ip("8.8.8.8"), ip("9.9.9.9")], 1);
        // 8.8.8.8 is running, so only 9.9.9.9 waits.
        assert_eq!(cache.pending(), 2);
        assert_eq!(cache.start_lookup(), Some(ip("9.9.9.9")));
        assert_eq!(cache.start_lookup(), None);
    }

    #[test]
    fn turning_names_off_drops_the_waiting_lookups_only() {
        let mut cache = NameCache::default();
        cache.want([ip("8.8.8.8"), ip("1.1.1.1")], 0);
        cache.start_lookup();
        cache.cancel_waiting();
        assert_eq!(cache.pending(), 1);
        cache.finish(ip("8.8.8.8"), Ok("dns.google".into()), 1);
        assert_eq!(cache.name(ip("8.8.8.8")), Some("dns.google"));
        // The dropped one can be asked for again later.
        cache.want([ip("1.1.1.1")], 2);
        assert_eq!(cache.pending(), 1);
    }

    #[test]
    fn the_oldest_answers_are_forgotten_past_the_cap() {
        let mut cache = NameCache::default();
        for n in 0..=ENTRY_CAP {
            let address = ip(&format!(
                "10.{}.{}.{}",
                n / 65025,
                n / 255 % 255,
                n % 255 + 1
            ));
            cache.finish(
                address,
                Ok(format!("host{n}.example")),
                i64::try_from(n).unwrap(),
            );
        }
        assert!(cache.entries.len() <= ENTRY_CAP);
        assert!(cache.entries.len() >= ENTRY_CAP - ENTRY_CAP / 10);
        assert_eq!(cache.name(ip("10.0.0.1")), None, "the oldest went");
        let newest = ENTRY_CAP;
        let address = ip(&format!(
            "10.{}.{}.{}",
            newest / 65025,
            newest / 255 % 255,
            newest % 255 + 1
        ));
        assert!(cache.name(address).is_some(), "the newest stayed");
    }
}
