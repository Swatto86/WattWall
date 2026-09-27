//! WattWall window, tray and commands. The webview only sends a path or a
//! yes/no; every check happens here before Windows is changed.

mod com;
mod engine;
mod firewall;
mod net;
mod programs;
mod store;
mod task;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, State, WindowEvent};
use wattwall_core::{exe_name, guard, Guard, Row};

use engine::Engine;
use programs::{icon_data_url, is_elevated, publisher};

struct Watt {
    engine: Engine,
    icons: Mutex<HashMap<String, String>>,
    publishers: Mutex<HashMap<String, String>>,
    hidden: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RowDto {
    path: String,
    name: String,
    publisher: String,
    icon: String,
    blocked: bool,
    enforced: bool,
    connected: bool,
    last_seen: Option<i64>,
    needs_confirmation: bool,
    cannot_block: bool,
    warning: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StateDto {
    blocked: Vec<RowDto>,
    seen: Vec<RowDto>,
    suspended: bool,
    has_rules: bool,
    warnings: Vec<String>,
    autostart: bool,
    autostart_available: bool,
    autostart_reason: String,
    elevated: bool,
}

fn map_row(row: &Row, app: &Watt) -> RowDto {
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

fn snapshot(app: &Watt) -> Result<StateDto, String> {
    let view = app.engine.refresh()?;
    let mut warnings = app.engine.warnings()?;
    let elevated = is_elevated();
    if !elevated {
        warnings.insert(
            0,
            "WattWall is not running as administrator, so it cannot change blocks.".to_string(),
        );
    }
    let autostart = app.engine.autostart();
    Ok(StateDto {
        blocked: view.blocked.iter().map(|row| map_row(row, app)).collect(),
        seen: view.seen.iter().map(|row| map_row(row, app)).collect(),
        suspended: view.suspended,
        has_rules: view.has_rules,
        warnings,
        autostart: autostart.enabled,
        autostart_available: autostart.available,
        autostart_reason: autostart.reason,
        elevated,
    })
}

#[tauri::command]
fn app_state(state: State<Watt>) -> Result<StateDto, String> {
    snapshot(&state)
}

#[tauri::command]
fn set_blocked(
    state: State<Watt>,
    path: String,
    blocked: bool,
    confirmed: bool,
) -> Result<StateDto, String> {
    state.engine.set_blocked(&path, blocked, confirmed)?;
    snapshot(&state)
}

#[tauri::command]
fn set_suspended(state: State<Watt>, suspended: bool) -> Result<StateDto, String> {
    state.engine.set_suspended(suspended)?;
    snapshot(&state)
}

#[tauri::command]
fn set_autostart(state: State<Watt>, enabled: bool) -> Result<StateDto, String> {
    state.engine.set_autostart(enabled)?;
    snapshot(&state)
}

#[tauri::command]
fn started_hidden(state: State<Watt>) -> bool {
    state.hidden
}

#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn rebuild_tray(app: &tauri::AppHandle, state: &StateDto) {
    let Some(tray) = app.tray_by_id("main") else {
        return;
    };
    let Ok(menu) = Menu::new(app) else { return };
    let connected: Vec<&RowDto> = state
        .blocked
        .iter()
        .chain(state.seen.iter())
        .filter(|row| row.connected)
        .collect();
    if connected.is_empty() {
        if let Ok(item) = MenuItem::with_id(
            app,
            "none",
            "Nothing is using the network",
            false,
            None::<&str>,
        ) {
            let _ = menu.append(&item);
        }
    } else {
        for (index, row) in connected.iter().enumerate() {
            let id = format!("conn:{index}");
            let label = if row.cannot_block {
                format!("{} (cannot block)", row.name)
            } else {
                row.name.clone()
            };
            if let Ok(item) = CheckMenuItem::with_id(
                app,
                &id,
                &label,
                !row.cannot_block,
                row.enforced,
                None::<&str>,
            ) {
                let _ = menu.append(&item);
            }
        }
    }
    if let Ok(sep) = PredefinedMenuItem::separator(app) {
        let _ = menu.append(&sep);
    }
    let toggle = if !state.has_rules {
        ("suspend", "Turn all blocks off", false)
    } else if state.suspended {
        ("resume", "Turn all blocks on", true)
    } else {
        ("suspend", "Turn all blocks off", true)
    };
    if let Ok(item) = MenuItem::with_id(app, toggle.0, toggle.1, toggle.2, None::<&str>) {
        let _ = menu.append(&item);
    }
    if let Ok(sep) = PredefinedMenuItem::separator(app) {
        let _ = menu.append(&sep);
    }
    if let Ok(item) = MenuItem::with_id(app, "open", "Open", true, None::<&str>) {
        let _ = menu.append(&item);
    }
    if let Ok(item) = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>) {
        let _ = menu.append(&item);
    }
    let _ = tray.set_menu(Some(menu));
    let tooltip = if state.suspended {
        "WattWall — all blocks are off"
    } else if state.has_rules {
        "WattWall — blocks are on"
    } else {
        "WattWall"
    };
    let _ = tray.set_tooltip(Some(tooltip));
}

fn on_menu(app: &tauri::AppHandle, id: &str) {
    let Some(state) = app.try_state::<Watt>() else {
        return;
    };
    if id == "open" {
        show(app);
        return;
    }
    if id == "quit" {
        app.exit(0);
        return;
    }
    if id == "suspend" {
        let _ = state.engine.set_suspended(true);
        publish(app);
        return;
    }
    if id == "resume" {
        let _ = state.engine.set_suspended(false);
        publish(app);
        return;
    }
    let Some(index) = id
        .strip_prefix("conn:")
        .and_then(|text| text.parse::<usize>().ok())
    else {
        return;
    };
    let Ok(snapshot) = snapshot(&state) else {
        return;
    };
    let connected: Vec<&RowDto> = snapshot
        .blocked
        .iter()
        .chain(snapshot.seen.iter())
        .filter(|row| row.connected)
        .collect();
    let Some(row) = connected.get(index) else {
        return;
    };
    if row.cannot_block {
        let _ = native_message(&row.warning, false);
        return;
    }
    let next = !row.enforced;
    if next && row.needs_confirmation && !native_message(&row.warning, true) {
        return;
    }
    let _ = state.engine.set_blocked(&row.path, next, true);
    publish(app);
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

fn publish(app: &tauri::AppHandle) {
    let Some(state) = app.try_state::<Watt>() else {
        return;
    };
    if let Ok(snapshot) = snapshot(&state) {
        rebuild_tray(app, &snapshot);
        let _ = app.emit("state", snapshot);
    }
}

pub fn elevated_enough() -> bool {
    programs::is_elevated()
}

pub fn open_engine() -> Result<Engine, String> {
    Engine::open()
}

pub fn run_cleanup(rules: bool, task_too: bool, data: bool) -> Result<(), String> {
    engine::cleanup(rules, task_too, data)
}

pub fn run() {
    let hidden = std::env::args().any(|arg| arg == "--hidden");
    let engine = match Engine::open() {
        Ok(engine) => engine,
        Err(err) => {
            eprintln!("WattWall could not start: {err}");
            std::process::exit(1)
        }
    };
    let watt = Watt {
        engine,
        icons: Mutex::new(HashMap::new()),
        publishers: Mutex::new(HashMap::new()),
        hidden,
    };
    let mut builder = tauri::Builder::default();
    let e2e = cfg!(debug_assertions) && std::env::var("WATTWALL_E2E").is_ok();
    if !e2e {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show(app)
        }));
    }
    let built = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(watt)
        .setup(|app| {
            let handle = app.handle().clone();
            let _ = TrayIconBuilder::with_id("main")
                .tooltip("WattWall")
                .icon(
                    app.default_window_icon()
                        .cloned()
                        .unwrap_or_else(|| tauri::image::Image::new(&[], 0, 0)),
                )
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show(tray.app_handle());
                    }
                })
                .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
                .build(app)?;
            publish(&handle);
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let poll = handle.clone();
            std::thread::Builder::new()
                .name("wattwall-poll".into())
                .spawn(move || {
                    while !flag.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_secs(3));
                        if flag.load(Ordering::Relaxed) {
                            break;
                        }
                        publish(&poll);
                    }
                })
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            app.manage(stop);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_state,
            set_blocked,
            set_suspended,
            set_autostart,
            started_hidden,
            quit_app
        ])
        .build(tauri::generate_context!());
    match built {
        Ok(app) => {
            app.run(|app, event| {
                if let tauri::RunEvent::Exit = event {
                    if let Some(stop) = app.try_state::<Arc<AtomicBool>>() {
                        stop.store(true, Ordering::Relaxed);
                    }
                }
            });
        }
        Err(err) => {
            eprintln!("WattWall failed to open its window: {err}");
            std::process::exit(1)
        }
    }
}
