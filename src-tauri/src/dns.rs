//! Host names for the Connections view: the cache of what has been found, and
//! the four worker threads that find more by asking a `Resolver` (see
//! `resolver.rs`). Lookups run off the window's thread so a slow DNS server
//! never holds it up, and every answer, even "no name", is kept for a while so
//! an address is asked about once.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use wattwall_core::monitor::NameCache;

use crate::engine::unix_now;
use crate::resolver::Resolver;

const WORKERS: usize = 4;
struct Shared {
    resolver: Resolver,
    cache: Mutex<NameCache>,
    /// Workers wait here for an address to look up, or for `stop`.
    wake: Condvar,
    /// Only set while holding `cache`, so a worker that has just looked at it
    /// cannot miss the wake-up.
    stopping: AtomicBool,
}

/// Names found so far, and the workers finding more.
#[derive(Clone)]
pub struct Names {
    shared: Arc<Shared>,
}

impl Names {
    pub fn new(resolver: Resolver) -> Self {
        Self {
            shared: Arc::new(Shared {
                resolver,
                cache: Mutex::new(NameCache::default()),
                wake: Condvar::new(),
                stopping: AtomicBool::new(false),
            }),
        }
    }

    /// Start the lookup threads. They sleep until there is an address to look
    /// up and run until `stop`.
    pub fn start_workers(&self) -> std::io::Result<()> {
        for number in 0..WORKERS {
            let shared = self.shared.clone();
            std::thread::Builder::new()
                .name(format!("wattwall-dns-{number}"))
                .spawn(move || work(&shared))?;
        }
        Ok(())
    }

    /// Tell the workers to finish. A lookup already running ends when Windows
    /// answers.
    pub fn stop(&self) {
        if let Ok(_cache) = self.shared.cache.lock() {
            self.shared.stopping.store(true, Ordering::Relaxed);
        }
        self.shared.wake.notify_all();
    }

    /// Look these addresses up unless they already have an answer.
    pub fn ask(&self, addresses: impl IntoIterator<Item = IpAddr>, now: i64) {
        if let Ok(mut cache) = self.shared.cache.lock() {
            cache.want(addresses, now);
            if cache.pending() > 0 {
                self.shared.wake.notify_all();
            }
        }
    }

    pub fn name(&self, address: IpAddr) -> Option<String> {
        let cache = self.shared.cache.lock().ok()?;
        cache.name(address).map(str::to_owned)
    }

    pub fn pending(&self) -> usize {
        self.shared.cache.lock().map_or(0, |cache| cache.pending())
    }

    /// Names were turned off: stop asking about what has not been asked yet.
    pub fn cancel_waiting(&self) {
        if let Ok(mut cache) = self.shared.cache.lock() {
            cache.cancel_waiting();
        }
    }
}

fn work(shared: &Shared) {
    // A poisoned lock means a thread panicked while holding the cache. Stop
    // rather than work with a cache that may be half-updated.
    while let Some(address) = shared.take() {
        let outcome = shared.resolver.resolve(address);
        let Ok(mut cache) = shared.cache.lock() else {
            return;
        };
        cache.finish(address, outcome, unix_now());
    }
}

impl Shared {
    /// The next address to look up, waiting for one to turn up. None when
    /// told to stop or when the cache is unusable.
    fn take(&self) -> Option<IpAddr> {
        let mut cache = self.cache.lock().ok()?;
        loop {
            if self.stopping.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(address) = cache.start_lookup() {
                return Some(address);
            }
            cache = self.wake.wait(cache).ok()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{FAKE_CALLS, FAKE_NAMES};
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// Work off the queue the way a worker does, on this thread.
    fn drain(names: &Names) {
        while let Some(address) = names.shared.take_now() {
            let outcome = names.shared.resolver.resolve(address);
            names
                .shared
                .cache
                .lock()
                .unwrap()
                .finish(address, outcome, unix_now());
        }
    }

    impl Shared {
        fn take_now(&self) -> Option<IpAddr> {
            self.cache.lock().ok()?.start_lookup()
        }
    }

    fn fake_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wattwall-dns-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_test_mode_answers_from_its_table_and_notes_each_question() {
        let dir = fake_dir("table");
        fs::write(
            dir.join(FAKE_NAMES),
            r#"{"203.0.113.7": "example.test", "198.51.100.1": "bad name with spaces"}"#,
        )
        .unwrap();
        let names = Names::new(Resolver::Fake(dir.clone()));
        names.ask([ip("203.0.113.7"), ip("198.51.100.1"), ip("192.0.2.9")], 0);
        assert_eq!(names.pending(), 3);
        drain(&names);
        assert_eq!(names.pending(), 0);
        assert_eq!(
            names.name(ip("203.0.113.7")).as_deref(),
            Some("example.test")
        );
        assert_eq!(
            names.name(ip("198.51.100.1")),
            None,
            "an unfit name is not shown"
        );
        assert_eq!(names.name(ip("192.0.2.9")), None);
        let asked = fs::read_to_string(dir.join(FAKE_CALLS)).unwrap();
        assert_eq!(asked.lines().count(), 3);

        // Asked about again: answered from memory, not looked up again.
        names.ask([ip("203.0.113.7")], unix_now());
        assert_eq!(names.pending(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn turning_names_off_stops_the_questions_that_have_not_been_asked() {
        let dir = fake_dir("off");
        let names = Names::new(Resolver::Fake(dir.clone()));
        names.ask([ip("203.0.113.7")], 0);
        names.cancel_waiting();
        drain(&names);
        assert!(
            !dir.join(FAKE_CALLS).exists(),
            "nothing may be asked once names are off"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn workers_answer_in_the_background_and_all_stop_when_told() {
        let dir = fake_dir("workers");
        fs::write(dir.join(FAKE_NAMES), r#"{"203.0.113.7": "example.test"}"#).unwrap();
        let names = Names::new(Resolver::Fake(dir.clone()));
        names.start_workers().unwrap();
        assert_eq!(Arc::strong_count(&names.shared), 1 + WORKERS);

        names.ask([ip("203.0.113.7")], unix_now());
        wait_until("a worker to answer", || {
            names.name(ip("203.0.113.7")).is_some()
        });
        assert_eq!(
            names.name(ip("203.0.113.7")).as_deref(),
            Some("example.test")
        );
        assert_eq!(names.pending(), 0);

        // Every worker holds the shared state, so once none is left, all have stopped.
        names.stop();
        wait_until("the workers to stop", || {
            Arc::strong_count(&names.shared) == 1
        });
        fs::remove_dir_all(&dir).unwrap();
    }
}
