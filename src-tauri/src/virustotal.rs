//! The VirusTotal check. Off until the owner turns it on with an API key.
//! A worker thread hashes the listed programs (SHA-256, re-read only when a
//! file's size or date changes), asks VirusTotal about each hash within the
//! owner's limits, and keeps the answers in `virustotal.json` with the
//! on/off choice and the limits. Only hashes leave the PC. The key lives in
//! the vault and never reaches the window.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use wattwall_core::virustotal::{api_key, is_due, Checked, Limits, Lookup, Pacer};
use zeroize::Zeroizing;

use crate::vault::{Secrets, Vault};
use crate::vtnet::{self, Hashed, LookupError};
use crate::{publish, Watt};

const STATE_FILE: &str = "virustotal.json";
/// How long a hash is trusted before the file's size and date are compared again.
const REVERIFY: i64 = 600;
/// A file that could not be read is tried again after this long.
const RETRY_UNREADABLE: i64 = 600;
/// After a network failure, wait this long before the next lookup.
const RETRY_UNREACHABLE: i64 = 120;
/// Hashes found between lookups are saved at most this often.
const SAVE_EVERY: i64 = 10;

/// What `virustotal.json` holds.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateFile {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    limits: Limits,
    /// Keyed by the lower-cased program path.
    #[serde(default)]
    files: HashMap<String, Hashed>,
    /// Keyed by SHA-256.
    #[serde(default)]
    reports: HashMap<String, Checked>,
    #[serde(default)]
    day: i64,
    #[serde(default)]
    used_today: u32,
}

enum Problem {
    KeyRejected,
    Limited,
    Unreachable(String),
}

struct Inner {
    saved: StateFile,
    has_key: bool,
    key: Option<Zeroizing<String>>,
    pacer: Pacer,
    problem: Option<Problem>,
    /// Program paths to check, most important first.
    wanted: Vec<String>,
    verified: HashMap<String, i64>,
    unreadable: HashMap<String, i64>,
    dirty: bool,
    saved_at: i64,
}

/// One program's result for the window.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VtRowDto {
    /// "pending", "found", "unknown" or "unreadable".
    state: &'static str,
    malicious: u32,
    suspicious: u32,
    engines: u32,
    names: Vec<String>,
    sha256: String,
    checked_at: Option<i64>,
}

/// The Settings section and header summary.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VtSummaryDto {
    enabled: bool,
    has_key: bool,
    per_minute: u32,
    per_day: u32,
    checked: usize,
    total: usize,
    status: String,
    /// "ok", "warn", "bad" or "muted".
    tone: &'static str,
}

enum Job {
    Hash(String),
    Lookup { path: String, sha256: String },
}

pub struct VirusTotal {
    dir: PathBuf,
    test_copy: bool,
    vault: Vault,
    inner: Mutex<Inner>,
}

impl VirusTotal {
    pub fn open(dir: &Path, test_copy: bool) -> Self {
        let saved: StateFile = std::fs::read_to_string(dir.join(STATE_FILE))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let vault = Vault::new(dir, test_copy);
        let pacer = pacer_for(saved.limits, saved.day, saved.used_today, test_copy);
        Self {
            dir: dir.to_path_buf(),
            test_copy,
            inner: Mutex::new(Inner {
                has_key: vault.exists(),
                saved,
                key: None,
                pacer,
                problem: None,
                wanted: Vec::new(),
                verified: HashMap::new(),
                unreadable: HashMap::new(),
                dirty: false,
                saved_at: 0,
            }),
            vault,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Save a new key (optional once one is saved) and the limits, and turn
    /// the check on.
    pub fn configure(&self, key: Option<String>, limits: Limits) -> Result<(), String> {
        let key = match key.filter(|key| !key.trim().is_empty()) {
            Some(text) => Some(Zeroizing::new(api_key(&text).ok_or(
                "That is not a VirusTotal API key: it should be 64 letters and digits.",
            )?)),
            None => None,
        };
        if key.is_none() && !self.lock().has_key {
            return Err("Paste your VirusTotal API key first.".into());
        }
        if let Some(key) = &key {
            self.vault.save(&Secrets {
                virustotal_key: Some(key.to_string()),
            })?;
        }
        let mut inner = self.lock();
        if let Some(key) = key {
            inner.key = Some(key);
            inner.has_key = true;
            inner.problem = None;
        }
        let (day, used) = inner.pacer.usage();
        inner.pacer = pacer_for(limits, day, used, self.test_copy);
        inner.saved.limits = limits;
        inner.saved.enabled = true;
        self.save(&mut inner, now())
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut inner = self.lock();
        if enabled && !inner.has_key {
            return Err("Set up VirusTotal with your API key first.".into());
        }
        inner.saved.enabled = enabled;
        if enabled
            && matches!(
                inner.problem,
                Some(Problem::Limited | Problem::Unreachable(_))
            )
        {
            inner.problem = None;
            inner.pacer.resume();
        }
        self.save(&mut inner, now())
    }

    /// Delete the key and turn the check off. Results stay for next time.
    pub fn remove_key(&self) -> Result<(), String> {
        self.vault.clear()?;
        let mut inner = self.lock();
        inner.key = None;
        inner.has_key = false;
        inner.problem = None;
        inner.saved.enabled = false;
        self.save(&mut inner, now())
    }

    /// Take the programs to check, most important first, and return what the
    /// window shows for each of them and for the whole check.
    pub fn update(&self, wanted: Vec<String>) -> (Vec<Option<VtRowDto>>, VtSummaryDto) {
        let now = now();
        let mut inner = self.lock();
        inner.wanted = wanted;
        let enabled = inner.saved.enabled && inner.has_key;
        let rows: Vec<Option<VtRowDto>> = inner
            .wanted
            .iter()
            .map(|path| enabled.then(|| row(&inner, path, now)))
            .collect();
        let readable: Vec<&Option<VtRowDto>> = rows
            .iter()
            .filter(|row| row.as_ref().is_some_and(|row| row.state != "unreadable"))
            .collect();
        let checked = readable
            .iter()
            .filter(|row| row.as_ref().is_some_and(|row| row.state != "pending"))
            .count();
        let summary = summary(&inner, checked, readable.len(), now);
        (rows, summary)
    }

    /// One unit of work: hash one file or look up one hash. Returns true when
    /// a result changed and the window should be refreshed.
    pub fn step(&self) -> bool {
        let now = now();
        let job = next_job(&mut self.lock(), now);
        match job {
            None => {
                let mut inner = self.lock();
                if inner.dirty && now - inner.saved_at >= SAVE_EVERY {
                    let _ = self.save(&mut inner, now);
                }
                false
            }
            Some(Job::Hash(path)) => {
                let key = path.to_ascii_lowercase();
                let cached = self.lock().saved.files.get(&key).cloned();
                let result = vtnet::hash_file(Path::new(&path), cached.as_ref());
                let mut inner = self.lock();
                match result {
                    Ok(hashed) => {
                        let changed = cached.as_ref() != Some(&hashed);
                        inner.saved.files.insert(key.clone(), hashed);
                        inner.verified.insert(key.clone(), now);
                        inner.unreadable.remove(&key);
                        inner.dirty |= changed;
                        changed
                    }
                    Err(_) => {
                        inner.unreadable.insert(key, now);
                        true
                    }
                }
            }
            Some(Job::Lookup { path, sha256 }) => self.look_up(&path, &sha256, now),
        }
    }

    fn look_up(&self, path: &str, sha256: &str, now: i64) -> bool {
        let key = match self.key() {
            Ok(key) => key,
            Err(err) => {
                self.lock().problem = Some(Problem::Unreachable(err));
                return true;
            }
        };
        self.lock().pacer.sent(now);
        let result = if self.test_copy {
            vtnet::fake_lookup(&self.dir, path, sha256, &key)
        } else {
            vtnet::lookup(sha256, &key)
        };
        let mut inner = self.lock();
        match result {
            Ok(lookup) => {
                inner.saved.reports.insert(
                    sha256.to_string(),
                    Checked {
                        checked_at: now,
                        lookup,
                    },
                );
                inner.pacer.answered();
                inner.problem = None;
            }
            Err(LookupError::KeyRejected) => inner.problem = Some(Problem::KeyRejected),
            Err(LookupError::Limited) => {
                inner.pacer.limited(now);
                inner.problem = Some(Problem::Limited);
            }
            Err(LookupError::Other(message)) => {
                inner.pacer.pause(now, RETRY_UNREACHABLE);
                inner.problem = Some(Problem::Unreachable(message));
            }
        }
        let _ = self.save(&mut inner, now);
        true
    }

    /// The API key, read from the vault on first use.
    fn key(&self) -> Result<Zeroizing<String>, String> {
        if let Some(key) = &self.lock().key {
            return Ok(key.clone());
        }
        let secrets = self.vault.load()?;
        let key = secrets
            .as_ref()
            .and_then(|secrets| secrets.virustotal_key.clone())
            .map(Zeroizing::new)
            .ok_or("The VirusTotal key is missing. Set it up again in Settings.")?;
        self.lock().key = Some(key.clone());
        Ok(key)
    }

    fn save(&self, inner: &mut Inner, now: i64) -> Result<(), String> {
        let (day, used) = inner.pacer.usage();
        inner.saved.day = day;
        inner.saved.used_today = used;
        let text = serde_json::to_string(&inner.saved).map_err(|err| err.to_string())?;
        std::fs::create_dir_all(&self.dir).map_err(|err| err.to_string())?;
        let path = self.dir.join(STATE_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|err| err.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|err| err.to_string())?;
        inner.dirty = false;
        inner.saved_at = now;
        Ok(())
    }
}

fn pacer_for(limits: Limits, day: i64, used: u32, test_copy: bool) -> Pacer {
    if test_copy {
        Pacer::new(0, limits.per_day, day, used)
    } else {
        Pacer::for_limits(limits, day, used)
    }
}

fn next_job(inner: &mut Inner, now: i64) -> Option<Job> {
    if !inner.saved.enabled || !inner.has_key || matches!(inner.problem, Some(Problem::KeyRejected))
    {
        return None;
    }
    let may_look_up = inner.pacer.wait(now) == 0;
    for path in &inner.wanted {
        let key = path.to_ascii_lowercase();
        if inner
            .unreadable
            .get(&key)
            .is_some_and(|at| now - at < RETRY_UNREADABLE)
        {
            continue;
        }
        let fresh = inner
            .verified
            .get(&key)
            .is_some_and(|at| now - at < REVERIFY);
        let Some(hashed) = inner.saved.files.get(&key).filter(|_| fresh) else {
            return Some(Job::Hash(path.clone()));
        };
        if may_look_up && is_due(inner.saved.reports.get(&hashed.sha256), now) {
            return Some(Job::Lookup {
                path: path.clone(),
                sha256: hashed.sha256.clone(),
            });
        }
    }
    None
}

fn row(inner: &Inner, path: &str, now: i64) -> VtRowDto {
    let key = path.to_ascii_lowercase();
    let mut dto = VtRowDto {
        state: "pending",
        malicious: 0,
        suspicious: 0,
        engines: 0,
        names: Vec::new(),
        sha256: String::new(),
        checked_at: None,
    };
    if inner.unreadable.contains_key(&key) {
        dto.state = "unreadable";
        return dto;
    }
    let Some(hashed) = inner.saved.files.get(&key) else {
        return dto;
    };
    dto.sha256 = hashed.sha256.clone();
    if let Some(checked) = inner.saved.reports.get(&hashed.sha256) {
        dto.checked_at = Some(checked.checked_at.min(now));
        match &checked.lookup {
            Lookup::Found(report) => {
                dto.state = "found";
                dto.malicious = report.malicious;
                dto.suspicious = report.suspicious;
                dto.engines = report.engines;
                dto.names = report.names.clone();
            }
            Lookup::Unknown => dto.state = "unknown",
        }
    }
    dto
}

fn summary(inner: &Inner, checked: usize, total: usize, now: i64) -> VtSummaryDto {
    let (status, tone) = if !inner.saved.enabled || !inner.has_key {
        (String::new(), "muted")
    } else {
        match &inner.problem {
            Some(Problem::KeyRejected) => (
                "VirusTotal rejected the API key. Change it with Change settings.".to_string(),
                "bad",
            ),
            Some(Problem::Limited) => (
                format!(
                    "VirusTotal says the key's quota is used up. Trying again {}.",
                    when(inner.pacer.wait(now))
                ),
                "warn",
            ),
            Some(Problem::Unreachable(message)) => (
                format!("Could not reach VirusTotal ({message}). Trying again shortly."),
                "warn",
            ),
            None if checked < total => (
                format!(
                    "Checked {checked} of {total} programs. Next lookup {}.",
                    when(inner.pacer.wait(now))
                ),
                "muted",
            ),
            None => (format!("All {total} programs checked."), "ok"),
        }
    };
    VtSummaryDto {
        enabled: inner.saved.enabled && inner.has_key,
        has_key: inner.has_key,
        per_minute: inner.saved.limits.per_minute,
        per_day: inner.saved.limits.per_day,
        checked,
        total,
        status,
        tone,
    }
}

fn when(seconds: i64) -> String {
    match seconds {
        ..=0 => "now".into(),
        1..=90 => format!("in {seconds} s"),
        91..=5_400 => format!("in {} min", (seconds + 59) / 60),
        _ => format!("in {} h", (seconds + 3_599) / 3_600),
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Runs on its own thread until `stop` is set.
pub fn watch(app: AppHandle, stop: Arc<AtomicBool>, test_copy: bool) {
    let tick = Duration::from_millis(if test_copy { 100 } else { 1_000 });
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(tick);
        let changed = app
            .try_state::<Watt>()
            .is_some_and(|watt| watt.virustotal.step());
        if changed {
            publish(&app);
        }
    }
}
