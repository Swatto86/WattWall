//! A program's row as the window gets it: what the list knows about it, plus
//! its icon and publisher, each worked out once and kept.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;
use wattwall_core::{exe_name, guard, Guard, Row};

use crate::programs::{icon_data_url, publisher};
use crate::virustotal::VtRowDto;
use crate::Watt;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RowDto {
    pub path: String,
    pub name: String,
    pub publisher: String,
    pub icon: String,
    pub blocked: bool,
    pub enforced: bool,
    pub connected: bool,
    pub last_seen: Option<i64>,
    pub needs_confirmation: bool,
    pub cannot_block: bool,
    pub warning: String,
    /// None while the VirusTotal check is off.
    pub virustotal: Option<VtRowDto>,
}

pub fn map_row(row: &Row, app: &Watt) -> RowDto {
    let key = row.path.to_ascii_lowercase();
    let icon = if row.path.eq_ignore_ascii_case("System") {
        String::new()
    } else {
        cached(&app.icons, &key, || {
            icon_data_url(&row.path).unwrap_or_default()
        })
    };
    let publisher = if row.path.eq_ignore_ascii_case("System") {
        String::new()
    } else {
        cached(&app.publishers, &key, || {
            publisher(&row.path).unwrap_or_default()
        })
    };
    let name = exe_name(&row.path).unwrap_or(&row.name);
    let warning = match guard(name, false, row.cannot_block) {
        Guard::Ok => String::new(),
        Guard::Confirm(text) | Guard::Impossible(text) => text.to_string(),
    };
    RowDto {
        path: row.path.clone(),
        name: row.name.clone(),
        publisher,
        icon,
        blocked: row.blocked,
        enforced: row.enforced,
        connected: row.connected,
        last_seen: row.last_seen,
        needs_confirmation: row.needs_confirmation,
        cannot_block: row.cannot_block,
        warning,
        virustotal: None,
    }
}

fn cached(
    map: &Mutex<HashMap<String, String>>,
    key: &str,
    make: impl FnOnce() -> String,
) -> String {
    if let Ok(guard) = map.lock() {
        if let Some(found) = guard.get(key) {
            return found.clone();
        }
    }
    let value = make();
    if let Ok(mut guard) = map.lock() {
        guard.insert(key.to_string(), value.clone());
    }
    value
}
