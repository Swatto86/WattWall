//! The small memory of programs that have used the network, and whether
//! autostart should be on. Firewall rules are not stored here.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use wattwall_core::Remembered;

#[derive(Serialize, Deserialize)]
struct File {
    #[serde(default = "yes")]
    autostart: bool,
    /// Whether the Connections view looks up host names. On unless turned off.
    #[serde(default = "yes")]
    resolve_names: bool,
    #[serde(default)]
    remembered: Vec<Saved>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Saved {
    path: String,
    last_seen: i64,
}

fn yes() -> bool {
    true
}

pub struct Settings {
    pub autostart: bool,
    pub resolve_names: bool,
    pub remembered: Vec<Remembered>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            autostart: true,
            resolve_names: true,
            remembered: Vec::new(),
        }
    }
}

impl Settings {
    /// The file is there but cannot be read or understood. What the owner
    /// chose about host names is unknown, so they stay off rather than
    /// resuming lookups nobody agreed to.
    fn unreadable() -> Self {
        Self {
            resolve_names: false,
            ..Self::default()
        }
    }
}

pub fn load(dir: &std::path::Path) -> Settings {
    let path = file(dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Settings::default(),
        Err(_) => return Settings::unreadable(),
    };
    let Ok(parsed) = serde_json::from_str::<File>(&text) else {
        return Settings::unreadable();
    };
    Settings {
        autostart: parsed.autostart,
        resolve_names: parsed.resolve_names,
        remembered: parsed
            .remembered
            .into_iter()
            .map(|item| Remembered {
                path: item.path,
                last_seen: item.last_seen,
            })
            .collect(),
    }
}

pub fn save(dir: &std::path::Path, settings: &Settings) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    let file_body = File {
        autostart: settings.autostart,
        resolve_names: settings.resolve_names,
        remembered: settings
            .remembered
            .iter()
            .map(|item| Saved {
                path: item.path.clone(),
                last_seen: item.last_seen,
            })
            .collect(),
    };
    let text = serde_json::to_string_pretty(&file_body).map_err(|err| err.to_string())?;
    let path = file(dir);
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).map_err(|err| err.to_string())?;
    fs::rename(&tmp, &path).map_err(|err| err.to_string())?;
    Ok(())
}

fn file(dir: &std::path::Path) -> PathBuf {
    dir.join("settings.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wattwall-store-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_settings_file_from_before_host_names_turns_them_on() {
        let dir = scratch("old");
        fs::write(file(&dir), r#"{"autostart": false, "remembered": []}"#).unwrap();
        let settings = load(&dir);
        assert!(!settings.autostart);
        assert!(settings.resolve_names);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn turning_host_names_off_survives_a_save_and_a_load() {
        let dir = scratch("roundtrip");
        let settings = Settings {
            resolve_names: false,
            remembered: vec![Remembered {
                path: r"C:\curl.exe".to_string(),
                last_seen: 5,
            }],
            ..Settings::default()
        };
        save(&dir, &settings).unwrap();
        let loaded = load(&dir);
        assert!(!loaded.resolve_names);
        assert!(loaded.autostart);
        assert_eq!(loaded.remembered.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_file_gives_the_defaults() {
        let dir = scratch("none");
        let settings = load(&dir);
        assert!(settings.autostart && settings.resolve_names);
        assert!(settings.remembered.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_that_cannot_be_understood_keeps_host_names_off() {
        let dir = scratch("broken");
        fs::write(file(&dir), "not json").unwrap();
        let settings = load(&dir);
        assert!(!settings.resolve_names, "unknown consent is no consent");
        assert!(settings.autostart, "the other defaults are unchanged");
        // A file that is there but cannot be read as text is the same.
        fs::write(file(&dir), [0xFF, 0xFE, 0x00, 0x9F]).unwrap();
        assert!(!load(&dir).resolve_names);
        fs::remove_dir_all(&dir).unwrap();
    }
}
