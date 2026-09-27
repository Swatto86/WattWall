//! The debug build's stand-in for Windows Firewall (WATTWALL_FAKE=1): rules in
//! `fake-rules.json` and the Block All switch in `fake-block-all.json`, so the
//! end-to-end suite never changes this PC's firewall.

use std::fs;
use std::path::Path;

use wattwall_core::RuleRecord;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct FakeRule {
    path: String,
    outbound_enabled: Option<bool>,
    inbound_enabled: Option<bool>,
}

pub fn list(file: &Path) -> Result<Vec<RuleRecord>, String> {
    Ok(read(file)?
        .into_iter()
        .map(|rule| RuleRecord {
            path: rule.path,
            outbound_enabled: rule.outbound_enabled,
            inbound_enabled: rule.inbound_enabled,
        })
        .collect())
}

pub fn set(file: &Path, path: &str, enabled: bool) -> Result<(), String> {
    let mut rules = read(file)?;
    if let Some(rule) = rules
        .iter_mut()
        .find(|rule| rule.path.eq_ignore_ascii_case(path))
    {
        rule.path = path.to_string();
        rule.outbound_enabled = Some(enabled);
        rule.inbound_enabled = Some(enabled);
    } else {
        rules.push(FakeRule {
            path: path.to_string(),
            outbound_enabled: Some(enabled),
            inbound_enabled: Some(enabled),
        });
    }
    write(file, &rules)
}

pub fn remove(file: &Path, path: &str) -> Result<(), String> {
    let mut rules = read(file)?;
    rules.retain(|rule| !rule.path.eq_ignore_ascii_case(path));
    write(file, &rules)
}

pub fn set_all(file: &Path, enabled: bool) -> Result<(), String> {
    let mut rules = read(file)?;
    for rule in &mut rules {
        if rule.outbound_enabled.is_some() {
            rule.outbound_enabled = Some(enabled);
        }
        if rule.inbound_enabled.is_some() {
            rule.inbound_enabled = Some(enabled);
        }
    }
    write(file, &rules)
}

pub fn remove_all(file: &Path) -> Result<(), String> {
    write(file, &[])?;
    set_block_all(file, false)
}

pub fn block_all(file: &Path) -> Result<bool, String> {
    let flag = block_all_file(file);
    if !flag.exists() {
        return Ok(false);
    }
    let text = fs::read_to_string(flag).map_err(|err| err.to_string())?;
    serde_json::from_str(&text).map_err(|err| err.to_string())
}

pub fn set_block_all(file: &Path, on: bool) -> Result<(), String> {
    let flag = block_all_file(file);
    if let Some(parent) = flag.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    fs::write(flag, if on { "true" } else { "false" }).map_err(|err| err.to_string())
}

fn block_all_file(file: &Path) -> std::path::PathBuf {
    file.with_file_name("fake-block-all.json")
}

fn read(path: &Path) -> Result<Vec<FakeRule>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    serde_json::from_str(&text).map_err(|err| err.to_string())
}

fn write(path: &Path, rules: &[FakeRule]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let text = serde_json::to_string_pretty(rules).map_err(|err| err.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).map_err(|err| err.to_string())?;
    fs::rename(&tmp, path).map_err(|err| err.to_string())?;
    Ok(())
}
