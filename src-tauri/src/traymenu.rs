//! The tray's right-click menu: what state the blocks are in, the programs
//! online now (tick one to block it), turning all blocks off or on, opening
//! the window and quitting.
//!
//! The menu is described by a `MenuPlan`. The traffic thread swaps in a new
//! menu only when the plan changes, and changes nothing about the tray while
//! a menu of this process is on screen: an open tray menu used to close by
//! itself within a couple of seconds because the menu and icons were being
//! replaced underneath it.

use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::{AppHandle, Manager, Wry};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowExW, GetWindowThreadProcessId, IsWindowVisible,
};

use crate::{publish, show, snapshot, tray, RowDto, Watt};

/// Menu ids of the program items start with this, then the program's path.
const BLOCK: &str = "block:";

const BLOCK_ALL_WARNING: &str = "Block all internet access?\n\nEvery program on this PC loses its network connection, including remote access such as Tailscale or Remote Desktop, until you turn Block all off in WattWall. Connections already open are closed now.";

/// Everything the menu shows. Two equal plans draw the same menu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuPlan {
    status: String,
    block_all: bool,
    online: Vec<Online>,
    blocks: Blocks,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Online {
    path: String,
    label: String,
    enabled: bool,
    checked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Blocks {
    None,
    On,
    Off,
}

/// The menu for this state. Programs are sorted by name, so it only changes
/// when a program comes online, goes offline, or is blocked or allowed.
pub fn plan(
    blocked: &[RowDto],
    seen: &[RowDto],
    suspended: bool,
    has_rules: bool,
    elevated: bool,
    block_all: bool,
) -> MenuPlan {
    let status = if !elevated {
        "not running as administrator".to_string()
    } else if block_all {
        "all internet access is blocked".to_string()
    } else if suspended {
        "all blocks are off".to_string()
    } else {
        match blocked.iter().filter(|row| row.enforced).count() {
            0 => "nothing blocked yet".to_string(),
            1 => "blocking 1 program".to_string(),
            count => format!("blocking {count} programs"),
        }
    };
    let mut online: Vec<Online> = blocked
        .iter()
        .chain(seen)
        .filter(|row| row.connected)
        .map(|row| Online {
            path: row.path.clone(),
            label: if row.cannot_block {
                format!("{} (cannot block)", row.name)
            } else if row.blocked && row.enforced {
                format!("{} (blocked)", row.name)
            } else if row.blocked {
                format!("{} (block paused)", row.name)
            } else {
                row.name.clone()
            },
            enabled: !row.cannot_block,
            checked: row.blocked,
        })
        .collect();
    online.sort_by(|a, b| {
        a.label
            .to_lowercase()
            .cmp(&b.label.to_lowercase())
            .then_with(|| a.path.cmp(&b.path))
    });
    let blocks = if !has_rules {
        Blocks::None
    } else if suspended {
        Blocks::Off
    } else {
        Blocks::On
    };
    MenuPlan {
        status: format!("WattWall: {status}"),
        block_all,
        online,
        blocks,
    }
}

pub fn build(app: &AppHandle, plan: &MenuPlan) -> tauri::Result<Menu<Wry>> {
    let menu = Menu::new(app)?;
    menu.append(&MenuItem::with_id(
        app,
        "status",
        &plan.status,
        false,
        None::<&str>,
    )?)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    let caption = if plan.online.is_empty() {
        "Nothing is using the network right now"
    } else {
        "Online now: tick one to block it"
    };
    menu.append(&MenuItem::with_id(
        app,
        "online",
        caption,
        false,
        None::<&str>,
    )?)?;
    for item in &plan.online {
        menu.append(&CheckMenuItem::with_id(
            app,
            format!("{BLOCK}{}", item.path),
            &item.label,
            item.enabled,
            item.checked,
            None::<&str>,
        )?)?;
    }
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&CheckMenuItem::with_id(
        app,
        "block-all",
        "Block all internet access",
        true,
        plan.block_all,
        None::<&str>,
    )?)?;
    let (id, text, enabled) = match plan.blocks {
        Blocks::None => ("suspend", "Turn all blocks off", false),
        Blocks::On => ("suspend", "Turn all blocks off", true),
        Blocks::Off => ("resume", "Turn all blocks on", true),
    };
    menu.append(&MenuItem::with_id(app, id, text, enabled, None::<&str>)?)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(
        app,
        "open",
        "Open WattWall",
        true,
        None::<&str>,
    )?)?;
    menu.append(&MenuItem::with_id(
        app,
        "quit",
        "Quit WattWall",
        true,
        None::<&str>,
    )?)?;
    Ok(menu)
}

pub fn on_menu(app: &AppHandle, id: &str) {
    let Some(state) = app.try_state::<Watt>() else {
        return;
    };
    match id {
        "open" => show(app),
        "quit" => app.exit(0),
        "suspend" | "resume" => {
            let _ = state.engine.set_suspended(id == "suspend");
            publish(app);
        }
        "block-all" => {
            tray::refresh_menu(app);
            let on = !state.engine.block_all().unwrap_or(false);
            if on && !native_message(BLOCK_ALL_WARNING, true) {
                return;
            }
            let _ = state.engine.set_block_all(on);
            publish(app);
        }
        _ => {
            let Some(path) = id.strip_prefix(BLOCK) else {
                return;
            };
            // Windows has already flipped the tick; redraw it from the real state.
            tray::refresh_menu(app);
            let Ok(now) = snapshot(&state) else {
                return;
            };
            let Some(row) = now
                .blocked
                .iter()
                .chain(&now.seen)
                .find(|row| row.path.eq_ignore_ascii_case(path))
            else {
                return;
            };
            if row.cannot_block {
                let _ = native_message(&row.warning, false);
                return;
            }
            let next = !row.blocked;
            if next && row.needs_confirmation && !native_message(&row.warning, true) {
                return;
            }
            let _ = state.engine.set_blocked(&row.path, next, true);
            publish(app);
        }
    }
}

/// Whether a popup menu of this process is on screen.
pub fn is_open() -> bool {
    let me = unsafe { GetCurrentProcessId() };
    let mut after: Option<HWND> = None;
    loop {
        let Ok(hwnd) = (unsafe { FindWindowExW(None, after, w!("#32768"), PCWSTR::null()) }) else {
            return false;
        };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) };
        if owner == me && unsafe { IsWindowVisible(hwnd) }.as_bool() {
            return true;
        }
        after = Some(hwnd);
    }
}

fn native_message(text: &str, yes_no: bool) -> bool {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_ICONWARNING, MB_OK, MB_YESNO,
    };
    let body = HSTRING::from(text);
    let title = HSTRING::from("WattWall");
    let flags = if yes_no {
        MB_YESNO | MB_ICONWARNING
    } else {
        MB_OK | MB_ICONWARNING
    };
    let answer = unsafe { MessageBoxW(None, &body, &title, flags) };
    !yes_no || answer == IDYES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, connected: bool, blocked: bool) -> RowDto {
        RowDto {
            path: format!("C:\\Apps\\{name}"),
            name: name.to_string(),
            publisher: String::new(),
            icon: String::new(),
            blocked,
            enforced: blocked,
            connected,
            last_seen: Some(1),
            needs_confirmation: false,
            cannot_block: false,
            warning: String::new(),
            virustotal: None,
        }
    }

    #[test]
    fn lists_online_programs_by_name_and_says_which_are_blocked() {
        let blocked = [row("zeta.exe", true, true), row("idle.exe", false, true)];
        let seen = [row("Beta.exe", true, false), row("alpha.exe", true, false)];
        let plan = plan(&blocked, &seen, false, true, true, false);
        let labels: Vec<&str> = plan.online.iter().map(|item| item.label.as_str()).collect();
        assert_eq!(labels, ["alpha.exe", "Beta.exe", "zeta.exe (blocked)"]);
        assert!(plan.online[2].checked);
        assert_eq!(plan.status, "WattWall: blocking 2 programs");
        assert_eq!(plan.blocks, Blocks::On);
    }

    #[test]
    fn the_plan_ignores_what_the_menu_does_not_show() {
        let seen = [row("alpha.exe", true, false)];
        let mut later = seen.clone();
        later[0].last_seen = Some(99);
        later[0].publisher = "Someone".into();
        assert_eq!(
            plan(&[], &seen, false, false, true, false),
            plan(&[], &later, false, false, true, false),
            "a new last-seen time must not rebuild the menu"
        );
        let mut offline = seen.clone();
        offline[0].connected = false;
        assert_ne!(
            plan(&[], &seen, false, false, true, false),
            plan(&[], &offline, false, false, true, false)
        );
        let locked = plan(&[], &seen, false, false, true, true);
        assert_eq!(locked.status, "WattWall: all internet access is blocked");
        assert!(locked.block_all);
    }

    #[test]
    fn states_and_programs_that_cannot_be_blocked() {
        let mut system = row("System", true, false);
        system.cannot_block = true;
        let mut paused = row("a.exe", true, true);
        paused.enforced = false;
        let plan_off = plan(&[paused], &[system], true, true, true, false);
        assert_eq!(plan_off.status, "WattWall: all blocks are off");
        assert_eq!(plan_off.blocks, Blocks::Off);
        assert_eq!(plan_off.online[0].label, "a.exe (block paused)");
        assert_eq!(plan_off.online[1].label, "System (cannot block)");
        assert!(!plan_off.online[1].enabled);
        let nothing = plan(&[], &[], false, false, false, false);
        assert_eq!(nothing.status, "WattWall: not running as administrator");
        assert_eq!(nothing.blocks, Blocks::None);
        assert!(nothing.online.is_empty());
    }
}
