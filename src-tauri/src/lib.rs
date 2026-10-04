//! WattWall window and commands. The webview only sends a path or a yes/no;
//! every check happens here before Windows is changed. The tray lives in
//! `tray.rs`.

mod com;
mod dns;
mod engine;
mod fakewall;
mod firewall;
mod monitor;
mod net;
mod programs;
mod resolver;
mod rows;
mod sockets;
mod store;
mod tables;
mod task;
mod taskbar;
mod traffic;
mod tray;
mod traymenu;
mod vault;
mod virustotal;
mod vtnet;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::{Emitter, Manager, State, WindowEvent};
use wattwall_core::virustotal::Limits;

use engine::Engine;
use monitor::Monitor;
use programs::is_elevated;
use rows::{map_row, RowDto};
use virustotal::{VirusTotal, VtSummaryDto};

struct Watt {
    engine: Engine,
    icons: Mutex<HashMap<String, String>>,
    publishers: Mutex<HashMap<String, String>>,
    virustotal: VirusTotal,
    monitor: Monitor,
    hidden: bool,
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
    /// Block All: every program is cut off from the network.
    block_all: bool,
    /// The Connections view looks up host names for far addresses.
    resolve_names: bool,
    virustotal: VtSummaryDto,
}

fn snapshot(app: &Watt) -> Result<StateDto, String> {
    let view = app.engine.refresh()?;
    let mut warnings = app.engine.warnings()?;
    let elevated = !app.engine.needs_admin() || is_elevated();
    if !elevated {
        warnings.insert(
            0,
            "WattWall is not running as administrator, so it cannot change blocks.".to_string(),
        );
    }
    let autostart = app.engine.autostart();
    let block_all = app.engine.block_all()?;
    let mut blocked: Vec<RowDto> = view.blocked.iter().map(|row| map_row(row, app)).collect();
    let mut seen: Vec<RowDto> = view.seen.iter().map(|row| map_row(row, app)).collect();
    let virustotal = attach_virustotal(app, &mut blocked, &mut seen, block_all);
    Ok(StateDto {
        blocked,
        seen,
        suspended: view.suspended,
        has_rules: view.has_rules,
        warnings,
        autostart: autostart.enabled,
        autostart_available: autostart.available,
        autostart_reason: autostart.reason,
        elevated,
        block_all,
        resolve_names: app.engine.resolve_names(),
        virustotal,
    })
}

/// Give the VirusTotal check every listed program, connected ones first, then
/// blocked ones, then the rest, and attach its answer to each row.
fn attach_virustotal(
    app: &Watt,
    blocked: &mut [RowDto],
    seen: &mut [RowDto],
    offline: bool,
) -> VtSummaryDto {
    let mut slots: Vec<(bool, usize)> = Vec::new();
    slots.extend(
        (0..seen.len())
            .filter(|&i| seen[i].connected)
            .map(|i| (false, i)),
    );
    slots.extend((0..blocked.len()).map(|i| (true, i)));
    slots.extend(
        (0..seen.len())
            .filter(|&i| !seen[i].connected)
            .map(|i| (false, i)),
    );
    let path = |(in_blocked, i): (bool, usize)| {
        if in_blocked {
            blocked[i].path.clone()
        } else {
            seen[i].path.clone()
        }
    };
    slots.retain(|&slot| !path(slot).eq_ignore_ascii_case("System"));
    let wanted = slots.iter().map(|&slot| path(slot)).collect();
    let (rows, summary) = app.virustotal.update(wanted, offline);
    for ((in_blocked, i), row) in slots.into_iter().zip(rows) {
        if in_blocked {
            blocked[i].virustotal = row;
        } else {
            seen[i].virustotal = row;
        }
    }
    summary
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

/// Block All on or off. The window asks first; this does not.
#[tauri::command]
fn set_block_all(state: State<Watt>, on: bool) -> Result<StateDto, String> {
    state.engine.set_block_all(on)?;
    snapshot(&state)
}

#[tauri::command]
fn set_autostart(state: State<Watt>, enabled: bool) -> Result<StateDto, String> {
    state.engine.set_autostart(enabled)?;
    snapshot(&state)
}

/// Save a key (optional once one is saved) and the owner's limits, and turn
/// the VirusTotal check on. The key is checked and sealed in Rust and never
/// sent back to the window.
#[tauri::command]
fn configure_virustotal(
    state: State<Watt>,
    key: Option<String>,
    per_minute: u32,
    per_day: u32,
) -> Result<StateDto, String> {
    state
        .virustotal
        .configure(key, Limits::new(per_minute, per_day)?)?;
    snapshot(&state)
}

/// What VirusTotal says a key allows, for the setup dialog. `key` is the
/// typed key, or None for the saved one. Async: it waits on the network.
#[tauri::command]
async fn virustotal_quota(
    state: State<'_, Watt>,
    key: Option<String>,
) -> Result<virustotal::QuotaDto, String> {
    state.virustotal.quotas(key).await
}

#[tauri::command]
fn set_virustotal(state: State<Watt>, enabled: bool) -> Result<StateDto, String> {
    state.virustotal.set_enabled(enabled)?;
    snapshot(&state)
}

#[tauri::command]
fn remove_virustotal_key(state: State<Watt>) -> Result<StateDto, String> {
    state.virustotal.remove_key()?;
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

fn publish(app: &tauri::AppHandle) {
    let Some(state) = app.try_state::<Watt>() else {
        return;
    };
    if let Ok(snapshot) = snapshot(&state) {
        tray::show_state(app, &snapshot);
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
    let test_copy = engine.is_test_copy();
    let watt = Watt {
        virustotal: VirusTotal::open(engine.data_dir(), test_copy),
        monitor: Monitor::open(test_copy, engine.data_dir()),
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
        .manage(tray::Meter::default())
        .setup(move |app| {
            let handle = app.handle().clone();
            tray::build(&handle)?;
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
            handle.state::<Watt>().monitor.names.start_workers()?;
            let flag = stop.clone();
            let lookups = handle.clone();
            std::thread::Builder::new()
                .name("wattwall-traffic".into())
                .spawn(move || tray::watch_traffic(handle, flag))
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            let flag = stop.clone();
            std::thread::Builder::new()
                .name("wattwall-virustotal".into())
                .spawn(move || virustotal::watch(lookups, flag, test_copy))
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
            set_block_all,
            set_autostart,
            configure_virustotal,
            virustotal_quota,
            set_virustotal,
            remove_virustotal_key,
            monitor::monitor_snapshot,
            monitor::monitor_close,
            monitor::set_resolve_names,
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
                    if let Some(watt) = app.try_state::<Watt>() {
                        watt.monitor.names.stop();
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
