//! Logon scheduled task. It is created only for the Program Files install,
//! and it is removed again by the off switch, uninstall and `--cleanup`.

use std::path::{Path, PathBuf};

use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskService, TaskScheduler, TASK_ACTION_EXEC,
    TASK_CREATE_OR_UPDATE, TASK_INSTANCES_IGNORE_NEW, TASK_LOGON_INTERACTIVE_TOKEN,
    TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_LOGON,
};
use windows::Win32::System::Variant::VARIANT;

use wattwall_core::is_installed_exe;

use crate::com::win_err;
use crate::programs::{current_exe, final_path, program_files};

const TASK_NAME: &str = "WattWall";

pub struct Autostart {
    pub enabled: bool,
    pub available: bool,
    pub reason: String,
}

pub fn status() -> Autostart {
    let installed = installed_exe().is_some();
    let enabled = task_target().is_some_and(|target| target_is_install(&target));
    if installed {
        Autostart {
            enabled,
            available: true,
            reason: String::new(),
        }
    } else {
        Autostart {
            enabled: false,
            available: false,
            reason: "Autostart is only available for the WattWall installed in Program Files. The portable copy asks for administrator each time it opens.".to_string(),
        }
    }
}

pub fn set(enabled: bool) -> Result<(), String> {
    if enabled {
        let exe = installed_exe().ok_or_else(|| status().reason)?;
        create(&exe)
    } else {
        remove()
    }
}

/// Drop a task that points anywhere except the Program Files install.
/// The installed app rewrites a task that points at a different copy.
pub fn repair(prefer_on: bool) -> Result<(), String> {
    let Some(target) = task_target() else {
        if prefer_on {
            if let Some(exe) = installed_exe() {
                create(&exe)?;
            }
        }
        return Ok(());
    };
    if target_is_install(&target) {
        if !prefer_on {
            remove()?;
        }
        return Ok(());
    }
    remove()?;
    if prefer_on {
        if let Some(exe) = installed_exe() {
            create(&exe)?;
        }
    }
    Ok(())
}

pub fn remove() -> Result<(), String> {
    let service = service()?;
    let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }.map_err(win_err)?;
    match unsafe { folder.DeleteTask(&BSTR::from(TASK_NAME), 0) } {
        Ok(()) => Ok(()),
        Err(err)
            if err.code().0 == 0x80070002u32 as i32 || err.code().0 == 0x80070002u32 as i32 =>
        {
            Ok(())
        }
        Err(err) if missing(&err) => Ok(()),
        Err(err) => Err(win_err(err)),
    }
}

fn missing(err: &windows::core::Error) -> bool {
    let code = err.code().0 as u32;
    code == 0x8007_0002 || code == 2
}

fn create(exe: &Path) -> Result<(), String> {
    let service = service()?;
    let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }.map_err(win_err)?;
    let task = unsafe { service.NewTask(0) }.map_err(win_err)?;
    let user = user_id();
    unsafe {
        let principal = task.Principal().map_err(win_err)?;
        principal
            .SetUserId(&BSTR::from(user.as_str()))
            .map_err(win_err)?;
        principal
            .SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)
            .map_err(win_err)?;
        principal
            .SetRunLevel(TASK_RUNLEVEL_HIGHEST)
            .map_err(win_err)?;

        let settings = task.Settings().map_err(win_err)?;
        settings
            .SetDisallowStartIfOnBatteries(VARIANT_FALSE)
            .map_err(win_err)?;
        settings
            .SetStopIfGoingOnBatteries(VARIANT_FALSE)
            .map_err(win_err)?;
        settings
            .SetStartWhenAvailable(VARIANT_TRUE)
            .map_err(win_err)?;
        settings
            .SetAllowDemandStart(VARIANT_TRUE)
            .map_err(win_err)?;
        settings
            .SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)
            .map_err(win_err)?;
        settings
            .SetExecutionTimeLimit(&BSTR::from("PT0S"))
            .map_err(win_err)?;

        let triggers = task.Triggers().map_err(win_err)?;
        let trigger = triggers.Create(TASK_TRIGGER_LOGON).map_err(win_err)?;
        trigger.SetEnabled(VARIANT_TRUE).map_err(win_err)?;
        let logon: ILogonTrigger = trigger.cast().map_err(win_err)?;
        logon
            .SetUserId(&BSTR::from(user.as_str()))
            .map_err(win_err)?;
        logon.SetDelay(&BSTR::from("PT3S")).map_err(win_err)?;

        let actions = task.Actions().map_err(win_err)?;
        let action = actions.Create(TASK_ACTION_EXEC).map_err(win_err)?;
        let exec: IExecAction = action.cast().map_err(win_err)?;
        exec.SetPath(&BSTR::from(exe.to_string_lossy().as_ref()))
            .map_err(win_err)?;
        exec.SetArguments(&BSTR::from("--hidden"))
            .map_err(win_err)?;

        let empty = VARIANT::default();
        folder
            .RegisterTaskDefinition(
                &BSTR::from(TASK_NAME),
                &task,
                TASK_CREATE_OR_UPDATE.0,
                &empty,
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )
            .map_err(win_err)?;
    }
    Ok(())
}

fn task_target() -> Option<PathBuf> {
    let service = service().ok()?;
    let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }.ok()?;
    let task = unsafe { folder.GetTask(&BSTR::from(TASK_NAME)) }.ok()?;
    let definition = unsafe { task.Definition() }.ok()?;
    let actions = unsafe { definition.Actions() }.ok()?;
    let action = unsafe { actions.get_Item(1) }.ok()?;
    let exec: IExecAction = action.cast().ok()?;
    let mut path = BSTR::new();
    unsafe { exec.Path(&mut path) }.ok()?;
    let text = String::from_utf16_lossy(&path);
    if text.is_empty() {
        return None;
    }
    final_path(Path::new(&text))
        .ok()
        .or(Some(PathBuf::from(text)))
}

fn service() -> Result<ITaskService, String> {
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }.map_err(win_err)?;
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }.map_err(win_err)?;
    Ok(service)
}

fn installed_exe() -> Option<PathBuf> {
    let exe = current_exe().ok()?;
    let root = program_files().ok()?;
    if is_installed_exe(&exe, &root) {
        Some(exe)
    } else {
        None
    }
}

fn target_is_install(target: &Path) -> bool {
    program_files()
        .ok()
        .is_some_and(|root| is_installed_exe(target, &root))
}

fn user_id() -> String {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    }
}
