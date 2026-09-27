//! Windows Firewall via INetFwPolicy2. Rules WattWall did not create are never
//! changed. A file-backed stand-in is used only by the debug end-to-end suite.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use wattwall_core::{is_our_rule, rule_names, RuleRecord, GROUP, MARKER};
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_MODIFY_STATE_GP_OVERRIDE, NET_FW_MODIFY_STATE_INBOUND_BLOCKED,
    NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
    NET_FW_RULE_DIRECTION, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_DISPATCH, VT_UNKNOWN};

use crate::com::win_err;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct FakeRule {
    path: String,
    outbound_enabled: Option<bool>,
    inbound_enabled: Option<bool>,
}

pub enum Firewall {
    Live,
    Fake(PathBuf),
}

impl Firewall {
    pub fn list(&self) -> Result<Vec<RuleRecord>, String> {
        match self {
            Self::Live => live_list(),
            Self::Fake(path) => fake_list(path),
        }
    }

    pub fn set_blocked(&self, path: &str, enabled: bool) -> Result<(), String> {
        match self {
            Self::Live => live_set(path, enabled),
            Self::Fake(file) => fake_set(file, path, enabled),
        }
    }

    pub fn remove(&self, path: &str) -> Result<(), String> {
        match self {
            Self::Live => live_remove_path(path),
            Self::Fake(file) => fake_remove(file, path),
        }
    }

    pub fn set_all_enabled(&self, enabled: bool) -> Result<(), String> {
        match self {
            Self::Live => live_set_all(enabled),
            Self::Fake(file) => {
                let mut rules = read_fake(file)?;
                for rule in &mut rules {
                    if rule.outbound_enabled.is_some() {
                        rule.outbound_enabled = Some(enabled);
                    }
                    if rule.inbound_enabled.is_some() {
                        rule.inbound_enabled = Some(enabled);
                    }
                }
                write_fake(file, &rules)
            }
        }
    }

    pub fn remove_all(&self) -> Result<(), String> {
        match self {
            Self::Live => live_remove_all(),
            Self::Fake(file) => write_fake(file, &[]),
        }
    }

    pub fn warnings(&self) -> Result<Vec<String>, String> {
        match self {
            Self::Live => live_warnings(),
            Self::Fake(_) => Ok(Vec::new()),
        }
    }
}

fn policy() -> Result<INetFwPolicy2, String> {
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(win_err)
}

fn live_list() -> Result<Vec<RuleRecord>, String> {
    let policy = policy()?;
    let rules = unsafe { policy.Rules() }.map_err(win_err)?;
    let owned = unsafe { our_rules(&rules) }?;
    let mut grouped: BTreeMap<String, RuleRecord> = BTreeMap::new();
    for (path, outbound, enabled) in owned {
        let entry = grouped
            .entry(path.to_ascii_lowercase())
            .or_insert_with(|| RuleRecord {
                path: path.clone(),
                outbound_enabled: None,
                inbound_enabled: None,
            });
        entry.path = path;
        if outbound {
            entry.outbound_enabled = Some(enabled);
        } else {
            entry.inbound_enabled = Some(enabled);
        }
    }
    Ok(grouped.into_values().collect())
}

fn live_set(path: &str, enabled: bool) -> Result<(), String> {
    let (out_name, in_name) = rule_names(path);
    let policy = policy()?;
    let rules = unsafe { policy.Rules() }.map_err(win_err)?;
    unsafe {
        upsert(&rules, &out_name, path, NET_FW_RULE_DIR_OUT, enabled)?;
        upsert(&rules, &in_name, path, NET_FW_RULE_DIR_IN, enabled)?;
    }
    Ok(())
}

fn live_remove_path(path: &str) -> Result<(), String> {
    let policy = policy()?;
    let rules = unsafe { policy.Rules() }.map_err(win_err)?;
    let owned = unsafe { our_rules(&rules) }?;
    let want = path.to_ascii_lowercase();
    for (rule_path, outbound, _) in &owned {
        if rule_path.to_ascii_lowercase() == want {
            let (out_name, in_name) = rule_names(rule_path);
            let name = if *outbound { out_name } else { in_name };
            remove_named(&rules, &name)?;
        }
    }
    let (out_name, in_name) = rule_names(path);
    remove_named(&rules, &out_name)?;
    remove_named(&rules, &in_name)?;
    Ok(())
}

fn live_set_all(enabled: bool) -> Result<(), String> {
    let policy = policy()?;
    let rules = unsafe { policy.Rules() }.map_err(win_err)?;
    let flag = bool_variant(enabled);
    for (path, outbound, _) in unsafe { our_rules(&rules) }? {
        let (out_name, in_name) = rule_names(&path);
        let name = if outbound { out_name } else { in_name };
        if let Ok(rule) = unsafe { rules.Item(&BSTR::from(name)) } {
            if unsafe { ours(&rule) }.unwrap_or(false) {
                unsafe { rule.SetEnabled(flag) }.map_err(win_err)?;
            }
        }
    }
    Ok(())
}

fn live_remove_all() -> Result<(), String> {
    let policy = policy()?;
    let rules = unsafe { policy.Rules() }.map_err(win_err)?;
    let names: Vec<String> = unsafe { our_rules(&rules) }?
        .into_iter()
        .map(|(path, outbound, _)| {
            let (out_name, in_name) = rule_names(&path);
            if outbound {
                out_name
            } else {
                in_name
            }
        })
        .collect();
    for name in names {
        remove_named(&rules, &name)?;
    }
    Ok(())
}

fn remove_named(rules: &INetFwRules, name: &str) -> Result<(), String> {
    match unsafe { rules.Item(&BSTR::from(name)) } {
        Ok(rule) => {
            if unsafe { ours(&rule) }.unwrap_or(false) {
                unsafe { rules.Remove(&BSTR::from(name)) }.map_err(win_err)?;
            }
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

unsafe fn upsert(
    rules: &INetFwRules,
    name: &str,
    path: &str,
    direction: NET_FW_RULE_DIRECTION,
    enabled: bool,
) -> Result<(), String> {
    if let Ok(existing) = unsafe { rules.Item(&BSTR::from(name)) } {
        if !unsafe { ours(&existing) }.unwrap_or(false) {
            return Err(format!(
                "A firewall rule named {name} already exists and was not created by WattWall."
            ));
        }
        unsafe { existing.SetEnabled(bool_variant(enabled)) }.map_err(win_err)?;
        unsafe { existing.SetApplicationName(&BSTR::from(path)) }.map_err(win_err)?;
        return Ok(());
    }
    let rule: INetFwRule =
        unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }.map_err(win_err)?;
    unsafe {
        rule.SetName(&BSTR::from(name)).map_err(win_err)?;
        rule.SetDescription(&BSTR::from(MARKER)).map_err(win_err)?;
        rule.SetApplicationName(&BSTR::from(path))
            .map_err(win_err)?;
        rule.SetGrouping(&BSTR::from(GROUP)).map_err(win_err)?;
        rule.SetDirection(direction).map_err(win_err)?;
        rule.SetAction(NET_FW_ACTION_BLOCK).map_err(win_err)?;
        rule.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)
            .map_err(win_err)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(win_err)?;
        rule.SetInterfaceTypes(&BSTR::from("All"))
            .map_err(win_err)?;
        rule.SetEnabled(bool_variant(enabled)).map_err(win_err)?;
        rules.Add(&rule).map_err(win_err)?;
    }
    Ok(())
}

unsafe fn ours(rule: &INetFwRule) -> Result<bool, String> {
    let name = bstr(unsafe { rule.Name() }.map_err(win_err)?)?;
    let description = bstr(unsafe { rule.Description() }.unwrap_or_default())?;
    let grouping = bstr(unsafe { rule.Grouping() }.unwrap_or_default())?;
    Ok(is_our_rule(&grouping, &description, &name))
}

unsafe fn our_rules(rules: &INetFwRules) -> Result<Vec<(String, bool, bool)>, String> {
    let unknown = unsafe { rules._NewEnum() }.map_err(win_err)?;
    let enumerator: IEnumVARIANT = unknown.cast().map_err(win_err)?;
    let mut found = Vec::new();
    loop {
        let mut fetched = 0u32;
        let mut vars = [VARIANT::default()];
        let hr = unsafe { enumerator.Next(&mut vars, &mut fetched) };
        if fetched == 0 || hr.is_err() {
            break;
        }
        let rule = match variant_rule(&vars[0]) {
            Some(rule) => rule,
            None => {
                unsafe { VariantClear(&mut vars[0]) }.ok();
                continue;
            }
        };
        if unsafe { ours(&rule) }.unwrap_or(false) {
            let name = bstr(unsafe { rule.Name() }.unwrap_or_default()).unwrap_or_default();
            let path =
                bstr(unsafe { rule.ApplicationName() }.unwrap_or_default()).unwrap_or_default();
            let enabled = unsafe { rule.Enabled() }
                .map(|value| value == VARIANT_TRUE)
                .unwrap_or(false);
            let outbound = name.starts_with("WattWall Out ");
            if !path.is_empty() {
                found.push((path, outbound, enabled));
            }
        }
        unsafe { VariantClear(&mut vars[0]) }.ok();
    }
    Ok(found)
}

fn variant_rule(variant: &VARIANT) -> Option<INetFwRule> {
    unsafe {
        let inner = &*variant.Anonymous.Anonymous;
        if inner.vt == VT_DISPATCH {
            let dispatch = (*inner.Anonymous.pdispVal).clone()?;
            return dispatch.cast().ok();
        }
        if inner.vt == VT_UNKNOWN {
            let unknown = (*inner.Anonymous.punkVal).clone()?;
            return unknown.cast().ok();
        }
    }
    None
}

fn live_warnings() -> Result<Vec<String>, String> {
    let policy = policy()?;
    let mut warnings = Vec::new();
    let profiles = [
        (NET_FW_PROFILE2_DOMAIN, "Domain"),
        (NET_FW_PROFILE2_PRIVATE, "Private"),
        (NET_FW_PROFILE2_PUBLIC, "Public"),
    ];
    let mut off = Vec::new();
    for (profile, label) in profiles {
        match unsafe { policy.get_FirewallEnabled(profile) } {
            Ok(enabled) if enabled == VARIANT_FALSE => off.push(label),
            Ok(_) => {}
            Err(err) => warnings.push(format!(
                "Could not read the {label} firewall profile: {}",
                win_err(err)
            )),
        }
    }
    if !off.is_empty() {
        warnings.push(format!(
            "Windows Firewall is off for the {} network. Blocks do nothing until it is turned back on.",
            off.join(", ")
        ));
    }
    match unsafe { policy.LocalPolicyModifyState() } {
        Ok(state) if state == NET_FW_MODIFY_STATE_GP_OVERRIDE => {
            warnings.push(
                "Group Policy controls this PC's firewall, so WattWall's rules may be ignored."
                    .to_string(),
            );
        }
        Ok(state) if state == NET_FW_MODIFY_STATE_INBOUND_BLOCKED => {
            warnings.push("Group Policy is blocking inbound traffic on its own. WattWall's outbound blocks still apply.".to_string());
        }
        Ok(_) => {}
        Err(err) => warnings.push(format!(
            "Could not tell whether Group Policy overrides the firewall: {}",
            win_err(err)
        )),
    }
    Ok(warnings)
}

fn bool_variant(enabled: bool) -> VARIANT_BOOL {
    if enabled {
        VARIANT_TRUE
    } else {
        VARIANT_FALSE
    }
}

fn bstr(value: BSTR) -> Result<String, String> {
    Ok(String::from_utf16_lossy(&value))
}

fn fake_list(path: &std::path::Path) -> Result<Vec<RuleRecord>, String> {
    Ok(read_fake(path)?
        .into_iter()
        .map(|rule| RuleRecord {
            path: rule.path,
            outbound_enabled: rule.outbound_enabled,
            inbound_enabled: rule.inbound_enabled,
        })
        .collect())
}

fn fake_set(file: &std::path::Path, path: &str, enabled: bool) -> Result<(), String> {
    let mut rules = read_fake(file)?;
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
    write_fake(file, &rules)
}

fn fake_remove(file: &std::path::Path, path: &str) -> Result<(), String> {
    let mut rules = read_fake(file)?;
    rules.retain(|rule| !rule.path.eq_ignore_ascii_case(path));
    write_fake(file, &rules)
}

fn read_fake(path: &std::path::Path) -> Result<Vec<FakeRule>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    serde_json::from_str(&text).map_err(|err| err.to_string())
}

fn write_fake(path: &std::path::Path, rules: &[FakeRule]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let text = serde_json::to_string_pretty(rules).map_err(|err| err.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).map_err(|err| err.to_string())?;
    fs::rename(&tmp, path).map_err(|err| err.to_string())?;
    Ok(())
}
