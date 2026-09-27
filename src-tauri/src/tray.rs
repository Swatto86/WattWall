//! The tray icon, its tooltip and its menu, and the window's icons.
//!
//! Every icon is drawn from wattwall-core's `Glyph`: a brick wall that turns
//! grey while every block is off, and a send and a receive bar that follow
//! this PC's traffic once a second, like ZoneAlarm's tray meter. The tray and
//! the title bar get it at small-icon size, the taskbar button at large-icon
//! size. Only the traffic thread hands icons, the tooltip and the menu to
//! Windows, only when they change, and not at all while a menu of WattWall's
//! is open. Other threads just record the state to show.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use wattwall_core::{meter_fill, rate_text, traffic_between, Glyph, TrayLook};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXICON, SM_CXSMICON, SYSTEM_METRICS_INDEX,
};

use crate::traymenu::{self, MenuPlan};
use crate::{show, taskbar, traffic, StateDto};

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
    menu_wanted: Option<MenuPlan>,
    menu_shown: Option<MenuPlan>,
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

/// Create the tray icon and give the window the same drawing. A left click
/// opens the window; only a right click opens the menu.
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
        .show_menu_on_left_click(false)
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
        .on_menu_event(|app, event| traymenu::on_menu(app, event.id().as_ref()))
        .build(app)
}

/// Record the menu, wall colour and tooltip wording for this state.
pub fn show_state(app: &AppHandle, state: &StateDto) {
    let status = if state.suspended {
        "WattWall: all blocks are off"
    } else if state.has_rules {
        "WattWall: blocks are on"
    } else {
        "WattWall: nothing is blocked"
    };
    let plan = traymenu::plan(
        &state.blocked,
        &state.seen,
        state.suspended,
        state.has_rules,
        state.elevated,
    );
    if let Some(meter) = app.try_state::<Meter>() {
        if let Ok(mut shown) = meter.inner.lock() {
            shown.paused = state.suspended;
            shown.status = status;
            shown.menu_wanted = Some(plan);
        }
    }
}

/// Draw the menu again from the recorded state at the next tick, for when
/// Windows changed what it shows (a tick mark flips as soon as it is clicked).
pub fn refresh_menu(app: &AppHandle) {
    if let Some(meter) = app.try_state::<Meter>() {
        if let Ok(mut shown) = meter.inner.lock() {
            shown.menu_shown = None;
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
    let menu_open = traymenu::is_open();
    let (small, big) = (small_glyph(), big_glyph());
    // Decide under the lock, talk to Windows outside it: the tray calls wait
    // for the main thread, which may itself be waiting for this lock.
    let (small_look, big_look, tip, menu, rates) = {
        let Ok(mut shown) = meter.inner.lock() else {
            return;
        };
        if let Some((sending, receiving)) = rates {
            shown.sending = sending;
            shown.receiving = receiving;
        }
        let rates = TrafficDto {
            sending: rate_text(shown.sending),
            receiving: rate_text(shown.receiving),
            sending_per_second: shown.sending,
            receiving_per_second: shown.receiving,
        };
        if menu_open {
            drop(shown);
            let _ = app.emit("traffic", rates);
            return;
        }
        let look = shown.look(&small);
        let small_look = (shown.small != Some((small.size(), look))).then_some(look);
        shown.small = Some((small.size(), look));
        let look = shown.look(&big);
        let big_look = (shown.big != Some((big.size(), look))).then_some(look);
        shown.big = Some((big.size(), look));
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
        let menu = (shown.menu_wanted != shown.menu_shown)
            .then(|| shown.menu_wanted.clone())
            .flatten();
        if menu.is_some() {
            shown.menu_shown = menu.clone();
        }
        (small_look, big_look, tip, menu, rates)
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
    let menu_failed = menu.is_some_and(|plan| {
        let built = traymenu::build(app, &plan);
        app.tray_by_id(TRAY)
            .zip(built.ok())
            .is_none_or(|(tray, menu)| tray.set_menu(Some(menu)).is_err())
    });
    if small_failed || tip_failed || menu_failed {
        if let Ok(mut shown) = meter.inner.lock() {
            if small_failed {
                shown.small = None;
            }
            if tip_failed {
                shown.tip.clear();
            }
            if menu_failed {
                shown.menu_shown = None;
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
