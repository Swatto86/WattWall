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
    pub remembered: Vec<Remembered>,
}

pub fn load(dir: &std::path::Path) -> Settings {
    let path = file(dir);
    let Ok(text) = fs::read_to_string(&path) else {
        return Settings {
            autostart: true,
            remembered: Vec::new(),
        };
    };
    let Ok(parsed) = serde_json::from_str::<File>(&text) else {
        return Settings {
            autostart: true,
            remembered: Vec::new(),
        };
    };
    Settings {
        autostart: parsed.autostart,
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
