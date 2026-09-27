//! Elevation and the cleanup commands. The window itself is in `lib`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = maintenance(&args) {
        std::process::exit(code);
    }
    if should_elevate() {
        elevate_and_exit();
    }
    wattwall_desktop_lib::run();
}

/// Firewall and cleanup commands. They use the same operations as the window.
/// Returns a process exit code when the command was handled.
fn maintenance(args: &[String]) -> Option<i32> {
    let cleanup = args.iter().any(|arg| arg == "--cleanup");
    let rules = args.iter().any(|arg| arg == "--cleanup-rules") || cleanup;
    let remove_task = args.iter().any(|arg| arg == "--remove-task") || cleanup;
    let data = cleanup;
    let block = value(args, "--block");
    let allow = value(args, "--allow");
    let off = args.iter().any(|arg| arg == "--blocks-off");
    let on = args.iter().any(|arg| arg == "--blocks-on");
    if !(rules || remove_task || data || block.is_some() || allow.is_some() || off || on) {
        return None;
    }
    if !wattwall_desktop_lib::elevated_enough() {
        elevate_and_exit();
    }
    if rules || remove_task || data {
        return Some(finish(wattwall_desktop_lib::run_cleanup(
            rules,
            remove_task,
            data,
        )));
    }
    let engine = match wattwall_desktop_lib::open_engine() {
        Ok(engine) => engine,
        Err(err) => {
            eprintln!("{err}");
            return Some(1);
        }
    };
    let confirmed = args.iter().any(|arg| arg == "--yes");
    let result = if let Some(path) = block {
        engine.set_blocked(&path, true, confirmed)
    } else if let Some(path) = allow {
        engine.set_blocked(&path, false, true)
    } else if off {
        engine.set_suspended(true)
    } else {
        engine.set_suspended(false)
    };
    Some(finish(result))
}

fn value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn finish(result: Result<(), String>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

fn should_elevate() -> bool {
    if wattwall_desktop_lib::elevated_enough() {
        return false;
    }
    if cfg!(debug_assertions) {
        return false;
    }
    true
}

fn elevate_and_exit() -> ! {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{w, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let exe = std::env::current_exe().unwrap_or_default();
    let wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let params: Vec<u16> = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .join(" ")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            PCWSTR(wide.as_ptr()),
            PCWSTR(params.as_ptr()),
            None,
            SW_SHOWNORMAL,
        )
    };
    std::process::exit(if result.0 as isize > 32 { 0 } else { 1 });
}
