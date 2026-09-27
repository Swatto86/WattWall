//! COM on whichever thread is about to talk to the firewall or the task scheduler.

use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};

pub fn init_com() -> Result<(), String> {
    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    // Already initialised on this thread (S_OK, S_FALSE) is fine. A different
    // apartment model means the caller already set COM up; keep going.
    if hr.is_ok() || hr.0 == 1 || hr.0 == 0x80010106u32 as i32 {
        Ok(())
    } else {
        Err(win_err(hr.into()))
    }
}

pub fn win_err(err: windows::core::Error) -> String {
    if err.code().0 == 5 {
        return "WattWall has to be running as administrator to change the firewall.".to_string();
    }
    let message = err.message();
    if message.trim().is_empty() {
        format!("Windows error {}", err.code().0)
    } else {
        message.to_string()
    }
}
