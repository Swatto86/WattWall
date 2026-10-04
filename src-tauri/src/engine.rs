//! What the window asks for: block, allow, suspend, and the list to draw.
//! Firewall rules stay the source of truth. This only remembers programs
//! that have been seen, and the autostart preference.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use wattwall_core::{
    build_view, check_exe_path, exe_name, guard, new_rules_enabled, plain_path, remember, Guard,
    View,
};

use crate::com::init_com;
use crate::firewall::Firewall;
use crate::net::Connections;
use crate::programs::current_exe;
use crate::{store, task};

pub struct Engine {
    pub firewall: Firewall,
    pub connections: Connections,
    data_dir: PathBuf,
    settings: Mutex<store::Settings>,
    live: bool,
}

impl Engine {
    pub fn open() -> Result<Self, String> {
        let live = !fake_mode();
        if live {
            init_com()?;
        }
        let data_dir = data_dir();
        let settings = store::load(&data_dir);
        if live {
            task::repair(settings.autostart)?;
        }
        let dir = data_dir.clone();
        Ok(Self {
            firewall: if live {
                Firewall::Live
            } else {
                Firewall::Fake(dir.join("fake-rules.json"))
            },
            connections: if live {
                Connections::Live
            } else {
                Connections::Fake(dir.clone())
            },
            data_dir,
            settings: Mutex::new(settings),
            live,
        })
    }

    pub fn refresh(&self) -> Result<View, String> {
        let connected = self.connections.snapshot()?;
        let rules = self.firewall.list()?;
        let mut settings = self
            .settings
            .lock()
            .map_err(|_| "WattWall's settings lock failed.".to_string())?;
        let now = unix_now();
        let mut changed = false;
        let blocked: Vec<String> = rules.iter().map(|rule| rule.path.clone()).collect();
        let due: Vec<String> = connected
            .iter()
            .filter(|path| {
                settings
                    .remembered
                    .iter()
                    .find(|item| item.path.eq_ignore_ascii_case(path))
                    .map(|item| now.saturating_sub(item.last_seen) >= 30)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if !due.is_empty() {
            remember(&mut settings.remembered, &due, now, &blocked);
            changed = true;
        }
        let remembered = settings.remembered.clone();
        if changed {
            store::save(&self.data_dir, &settings)?;
        }
        drop(settings);
        Ok(build_view(&rules, &connected, &remembered))
    }

    pub fn set_blocked(&self, path: &str, blocked: bool, confirmed: bool) -> Result<(), String> {
        if path.eq_ignore_ascii_case("System") {
            return Err(format!("impossible:{}", impossible_text()));
        }
        let resolved = resolve(path, blocked)?;
        let name = exe_name(&resolved).unwrap_or(&resolved);
        let is_self = current_exe()
            .ok()
            .is_some_and(|exe| exe.to_string_lossy().eq_ignore_ascii_case(&resolved));
        match guard(name, is_self, false) {
            Guard::Impossible(text) => return Err(format!("impossible:{text}")),
            Guard::Confirm(text) if !confirmed => return Err(format!("confirm:{text}")),
            Guard::Ok | Guard::Confirm(_) => {}
        }
        if blocked {
            let rules = self.firewall.list()?;
            let enabled = new_rules_enabled(&rules);
            self.firewall.set_blocked(&resolved, enabled)?;
            if enabled {
                self.connections.close_tcp(&resolved)?;
            }
        } else {
            self.firewall.remove(&resolved)?;
            if resolved != path.trim() {
                self.firewall.remove(path.trim())?;
            }
        }
        Ok(())
    }

    pub fn block_all(&self) -> Result<bool, String> {
        self.firewall.block_all()
    }

    /// Turn Block All on or off. Turning it on also closes every TCP
    /// connection that leaves the PC, since Windows keeps connections it has
    /// already allowed.
    pub fn set_block_all(&self, on: bool) -> Result<(), String> {
        self.firewall.set_block_all(on)?;
        if on {
            self.connections.close_all_tcp()?;
        }
        Ok(())
    }

    pub fn set_suspended(&self, suspended: bool) -> Result<(), String> {
        self.firewall.set_all_enabled(!suspended)?;
        if !suspended {
            for rule in self.firewall.list()? {
                if rule.outbound_enabled == Some(true) {
                    self.connections.close_tcp(&rule.path)?;
                }
            }
        }
        Ok(())
    }

    /// Whether the Connections view looks up host names. Off if the settings
    /// lock is broken, so a fault never means more lookups.
    pub fn resolve_names(&self) -> bool {
        self.settings
            .lock()
            .is_ok_and(|settings| settings.resolve_names)
    }

    /// Save the choice before reporting it; a failed save leaves the old one.
    pub fn set_resolve_names(&self, enabled: bool) -> Result<(), String> {
        let mut settings = self
            .settings
            .lock()
            .map_err(|_| "WattWall's settings lock failed.".to_string())?;
        let before = settings.resolve_names;
        settings.resolve_names = enabled;
        store::save(&self.data_dir, &settings).inspect_err(|_| settings.resolve_names = before)
    }

    pub fn set_autostart(&self, enabled: bool) -> Result<(), String> {
        if !self.live {
            return Err("Autostart is not available in the test copy.".to_string());
        }
        task::set(enabled)?;
        let mut settings = self
            .settings
            .lock()
            .map_err(|_| "WattWall's settings lock failed.".to_string())?;
        settings.autostart = enabled;
        store::save(&self.data_dir, &settings)
    }

    /// Only the real firewall needs an elevated process; the debug build's
    /// file-backed stand-in does not.
    pub fn needs_admin(&self) -> bool {
        self.live
    }

    /// The debug build's test mode (WATTWALL_FAKE=1): fake firewall, fake
    /// connections, and no Credential Manager or network for VirusTotal.
    pub fn is_test_copy(&self) -> bool {
        !self.live
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn autostart(&self) -> task::Autostart {
        if self.live {
            task::status()
        } else {
            task::Autostart {
                enabled: false,
                available: false,
                reason: "Autostart is not available in the test copy.".to_string(),
            }
        }
    }

    pub fn warnings(&self) -> Result<Vec<String>, String> {
        self.firewall.warnings()
    }
}

pub fn cleanup(rules: bool, task_too: bool, data: bool) -> Result<(), String> {
    init_com()?;
    if rules {
        Firewall::Live.remove_all()?;
    }
    if task_too {
        task::remove()?;
    }
    if data {
        match fs::remove_dir_all(real_data_dir()) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.to_string()),
        }
        crate::vault::forget_key()?;
    }
    Ok(())
}

pub fn real_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("WattWall")
}

fn data_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        if let Ok(dir) = std::env::var("WATTWALL_DATA_DIR") {
            if !dir.is_empty() {
                return PathBuf::from(dir);
            }
        }
    }
    real_data_dir()
}

fn fake_mode() -> bool {
    cfg!(debug_assertions) && std::env::var("WATTWALL_FAKE").ok().as_deref() == Some("1")
}

fn resolve(path: &str, must_exist: bool) -> Result<String, String> {
    check_exe_path(path).map_err(|err| err.to_string())?;
    match std::fs::canonicalize(path) {
        Ok(canonical) => {
            let plain = plain_path(&canonical);
            if !plain.is_file() {
                return Err("That program file was not found.".to_string());
            }
            Ok(plain.to_string_lossy().to_string())
        }
        Err(_) if must_exist => Err("That program file was not found.".to_string()),
        Err(_) => Ok(path.trim().to_string()),
    }
}

fn impossible_text() -> &'static str {
    match guard("System", false, true) {
        Guard::Impossible(text) => text,
        _ => "System cannot be blocked.",
    }
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_in(dir: PathBuf) -> Engine {
        Engine {
            firewall: Firewall::Fake(dir.join("fake-rules.json")),
            connections: Connections::Fake(dir.clone()),
            data_dir: dir,
            settings: Mutex::new(store::Settings::default()),
            live: false,
        }
    }

    fn scratch(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wattwall-engine-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(&dir);
        dir
    }

    #[test]
    fn the_host_names_choice_is_saved_before_it_is_reported() {
        let dir = scratch("saved");
        let engine = engine_in(dir.clone());
        assert!(engine.resolve_names());
        engine.set_resolve_names(false).unwrap();
        assert!(!engine.resolve_names());
        assert!(!store::load(&dir).resolve_names, "the file says off");
        engine.set_resolve_names(true).unwrap();
        assert!(store::load(&dir).resolve_names);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_choice_that_cannot_be_saved_leaves_the_old_one_in_force() {
        // A file where the folder should be: the save cannot succeed.
        let dir = scratch("unsaved");
        fs::write(&dir, "in the way").unwrap();
        let engine = engine_in(dir.clone());
        assert!(engine.set_resolve_names(false).is_err());
        assert!(engine.resolve_names(), "still on: nothing was saved");
        fs::remove_file(&dir).unwrap();
    }
}
