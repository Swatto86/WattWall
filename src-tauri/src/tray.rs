//! The tray icon, its tooltip and its menu, and the window's icons.
//!
//! Every icon is drawn from wattwall-core's `Glyph`: a brick wall that turns
//! grey while every block is off, and a send and a receive bar that follow
//! this PC's traffic once a second, like ZoneAlarm's tray meter. The tray and
//! the title bar get it at small-icon size, the taskbar button at large-icon
//! size. Only the traffic thread hands icons and the tooltip to Windows, and
//! only when they change. Other threads just record the state to show.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use wattwall_core::{meter_fill, rate_text, traffic_between, Glyph, TrayLook};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXICON, SM_CXSMICON, SYSTEM_METRICS_INDEX,
};

use crate::{publish, show, snapshot, taskbar, traffic, RowDto, StateDto, Watt};

const TRAY: &str = "main";

/// What the icons should show, and what they show now.
#[derive(Default)]
pub struct Meter {
    inner: Mutex<Shown>,
}

#[derive(Default)]
struct Shown {
    paused: bool,
    status: &'static str,
    sending: f64,
    receiving: f64,
    /// Tray and title bar.
    small: Option<(u32, TrayLook)>,
    /// Taskbar button.
    big: Option<(u32, TrayLook)>,
    tip: String,
}

impl Shown {
    fn look(&self, glyph: &Glyph) -> TrayLook {
        TrayLook {
            paused: self.paused,
            sending: meter_fill(self.sending, glyph.steps()),
            receiving: meter_fill(self.receiving, glyph.steps()),
        }
    }
}

/// The `traffic` event: this second's rates as text and in bytes per second.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TrafficDto {
    sending: String,
    receiving: String,
    sending_per_second: f64,
    receiving_per_second: f64,
}

/// Create the tray icon and give the window the same drawing.
pub fn build(app: &AppHandle) -> tauri::Result<TrayIcon> {
    let (small, big) = (small_glyph(), big_glyph());
    let look = TrayLook::default();
    if let Some(meter) = app.try_state::<Meter>() {
        if let Ok(mut shown) = meter.inner.lock() {
            shown.small = Some((small.size(), look));
            shown.big = Some((big.size(), look));
        }
    }
    let image = || Image::new_owned(small.draw(look), small.size(), small.size());
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_icon(image());
    }
    taskbar::set_big_icon(app, big.draw(look), big.size());
    TrayIconBuilder::with_id(TRAY)
        .tooltip("WattWall")
        .icon(image())
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
        .build(app)
}

/// Rebuild the menu and record the wall colour and tooltip for this state.
pub fn show_state(app: &AppHandle, state: &StateDto) {
    rebuild_menu(app, state);
    let status = if state.suspended {
        "WattWall: all blocks are off"
    } else if state.has_rules {
        "WattWall: blocks are on"
    } else {
        "WattWall: nothing is blocked"
    };
    if let Some(meter) = app.try_state::<Meter>() {
        if let Ok(mut shown) = meter.inner.lock() {
            shown.paused = state.suspended;
            shown.status = status;
        }
    }
}

/// Runs on its own thread until `stop` is set: reads the adapter counters
/// once a second, redraws the tray and tells the window the current rates.
pub fn watch_traffic(app: AppHandle, stop: Arc<AtomicBool>) {
    let mut before = traffic::counters();
    let mut at = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let after = traffic::counters();
        let now = Instant::now();
        let rates = match (&before, &after) {
            (Some(old), Some(new)) => {
                let (received, sent) = traffic_between(old, new);
                let seconds = now.duration_since(at).as_secs_f64().max(0.001);
                Some((sent as f64 / seconds, received as f64 / seconds))
            }
            _ => None,
        };
        before = after;
        at = now;
        tick(&app, rates);
    }
}

fn tick(app: &AppHandle, rates: Option<(f64, f64)>) {
    let Some(meter) = app.try_state::<Meter>() else {
        return;
    };
    let (small, big) = (small_glyph(), big_glyph());
    // Decide under the lock, talk to Windows outside it: the tray calls wait
    // for the main thread, which may itself be waiting for this lock.
    let (small_look, big_look, tip, rates) = {
        let Ok(mut shown) = meter.inner.lock() else {
            return;
        };
        if let Some((sending, receiving)) = rates {
            shown.sending = sending;
            shown.receiving = receiving;
        }
        let look = shown.look(&small);
        let small_look = (shown.small != Some((small.size(), look))).then_some(look);
        shown.small = Some((small.size(), look));
        let look = shown.look(&big);
        let big_look = (shown.big != Some((big.size(), look))).then_some(look);
        shown.big = Some((big.size(), look));
        let rates = TrafficDto {
            sending: rate_text(shown.sending),
            receiving: rate_text(shown.receiving),
            sending_per_second: shown.sending,
            receiving_per_second: shown.receiving,
        };
        let status = if shown.status.is_empty() {
            "WattWall"
        } else {
            shown.status
        };
        let tip = format!(
            "{status}\nSending {}, receiving {}",
            rates.sending, rates.receiving
        );
        let tip = (shown.tip != tip).then(|| {
            shown.tip = tip.clone();
            tip
        });
        (small_look, big_look, tip, rates)
    };
    let small_failed = small_look.is_some_and(|look| {
        let rgba = small.draw(look);
        let tray_ok = app.tray_by_id(TRAY).is_some_and(|tray| {
            let image = Image::new_owned(rgba.clone(), small.size(), small.size());
            tray.set_icon(Some(image)).is_ok()
        });
        let window_ok = app.get_webview_window("main").is_some_and(|window| {
            let image = Image::new_owned(rgba, small.size(), small.size());
            window.set_icon(image).is_ok()
        });
        !(tray_ok && window_ok)
    });
    if let Some(look) = big_look {
        taskbar::set_big_icon(app, big.draw(look), big.size());
    }
    let tip_failed = tip.is_some_and(|tip| {
        app.tray_by_id(TRAY)
            .is_none_or(|tray| tray.set_tooltip(Some(&tip)).is_err())
    });
    if small_failed || tip_failed {
        if let Ok(mut shown) = meter.inner.lock() {
            if small_failed {
                shown.small = None;
            }
            if tip_failed {
                shown.tip.clear();
            }
        }
    }
    let _ = app.emit("traffic", rates);
}

/// The drawing at the size Windows uses for tray and title-bar icons at
/// this PC's scaling.
fn small_glyph() -> Glyph {
    Glyph::new(metric(SM_CXSMICON, 16))
}

/// The drawing at the size Windows uses for the taskbar button.
fn big_glyph() -> Glyph {
    Glyph::new(metric(SM_CXICON, 32))
}

fn metric(index: SYSTEM_METRICS_INDEX, fallback: u32) -> u32 {
    let value = unsafe { GetSystemMetrics(index) };
    u32::try_from(value)
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(fallback)
}

fn rebuild_menu(app: &AppHandle, state: &StateDto) {
    let Some(tray) = app.tray_by_id(TRAY) else {
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
}

fn on_menu(app: &AppHandle, id: &str) {
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
