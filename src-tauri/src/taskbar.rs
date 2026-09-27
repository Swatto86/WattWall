//! The window's big icon, which Windows shows on the taskbar button and in
//! Alt+Tab. Tauri only sets the small title-bar icon, so this sends
//! WM_SETICON itself, on the window's thread, and frees the icon it replaces.

use std::sync::Mutex;

use tauri::{AppHandle, Manager};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateIcon, DestroyIcon, SendMessageW, HICON, ICON_BIG, WM_SETICON,
};

/// The big icon this module set last, as a raw handle, so it can be freed
/// once the next one replaces it. Zero means none yet.
static CURRENT: Mutex<isize> = Mutex::new(0);

/// Show `rgba` (square, `size` pixels, straight alpha) on the taskbar button.
pub fn set_big_icon(app: &AppHandle, rgba: Vec<u8>, size: u32) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let Some(window) = handle.get_webview_window("main") else {
            return;
        };
        // Tauri's handle comes from a newer windows crate; the pointer is the same.
        let Ok(raw) = window.hwnd() else { return };
        let Some(icon) = icon_from_rgba(&rgba, size) else {
            return;
        };
        unsafe {
            SendMessageW(
                HWND(raw.0),
                WM_SETICON,
                Some(WPARAM(ICON_BIG as usize)),
                Some(LPARAM(icon.0 as isize)),
            );
        }
        if let Ok(mut current) = CURRENT.lock() {
            if *current != 0 {
                let _ = unsafe { DestroyIcon(HICON(*current as *mut _)) };
            }
            *current = icon.0 as isize;
        }
    });
}

fn icon_from_rgba(rgba: &[u8], size: u32) -> Option<HICON> {
    let side = size as usize;
    if side == 0 || rgba.len() != side * side * 4 {
        return None;
    }
    let bgra: Vec<u8> = rgba
        .chunks_exact(4)
        .flat_map(|pixel| [pixel[2], pixel[1], pixel[0], pixel[3]])
        .collect();
    // One bit per pixel, rows padded to 16 bits: set where the pixel is
    // fully transparent. Windows uses the alpha channel; this is the fallback.
    let stride = side.div_ceil(16) * 2;
    let mut mask = vec![0u8; stride * side];
    for (index, pixel) in rgba.chunks_exact(4).enumerate() {
        if pixel[3] == 0 {
            let (y, x) = (index / side, index % side);
            mask[y * stride + x / 8] |= 0x80 >> (x % 8);
        }
    }
    let size = i32::try_from(size).ok()?;
    unsafe { CreateIcon(None, size, size, 1, 32, mask.as_ptr(), bgra.as_ptr()) }.ok()
}
