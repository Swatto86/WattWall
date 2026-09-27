# WattWall — agent context

Windows tray app that adds per-program block rules to the Windows Firewall. `ARCHITECTURE.md` is the map. `CONTEXT.md` is the decisions still in force.

## Build / run / verify

- Dev: `npm run tauri dev`. The debug build does not elevate itself, so changing a real block from a dev run needs an administrator terminal. The window still lists programs.
- Iteration: `pwsh scripts/fastcheck.ps1` (`-Package wattwall-core` checks that crate only).
- Full gate: `pwsh scripts/verify.ps1` (frontend, fmt, clippy, tests, `tauri build --debug --no-bundle`, WebDriver). From PowerShell, `msedgedriver` must be on `PATH` (`C:\Users\Swatto\bin`).
- Real firewall check (elevated): `scripts/live-accept.ps1`. Install check: `scripts/install-handoff.ps1`. Both run `--cleanup`, which deletes the owner's real blocks, logon task and saved list: never run them on his PC without asking. To hand him a new build, run the new setup with `/S` over the installed copy from an elevated shell (a silent install only replaces files; the uninstall hook does nothing when silent), then check a reversible `--block`/`--allow` of `curl.exe`.
- App icons: edit `src-tauri/icons/source/*.svg`, then `node scripts/icons.mjs`. The tray and taskbar icon is drawn at run time (`crates/wattwall-core/src/meter.rs`).
- Release install is local and unsigned until a tag is published. Do not tag or publish a GitHub release unless asked.

## Constraints

- Windows only. Firewall changes go through `INetFwPolicy2`. No `netsh`, no PowerShell, no driver.
- A block is an outbound rule and an inbound rule for one exe path, group `WattWall`, description `WattWall v1`. Never edit, disable or delete a rule that does not match both the group and that description.
- The rules are the source of truth. The app stores only remembered programs and the autostart preference (`%LOCALAPPDATA%\WattWall\settings.json`).
- The release build relaunches itself elevated when it is not. Logon start is a scheduled task, highest privileges, only for `Program Files\WattWall\WattWall.exe` after junctions are resolved. Portable and `target\` builds cannot enable it.
- The webview is bundled content only: strict CSP, no remote URLs, no shell or filesystem permissions. Rust checks every path the window sends.
- Confirm before blocking `svchost.exe`, `lsass.exe`, `tailscaled.exe`, `tailscale-ipn.exe`, or WattWall itself. `System` has no program file and cannot be blocked.
- `--cleanup` removes WattWall's rules, the task and app data, and is safe to run twice. Uninstall always removes the task and asks about the rules. A silent update must not ask and must not remove the rules.
- WebDriver uses `WATTWALL_FAKE=1` and `WATTWALL_E2E=1` (debug builds only) so it does not touch the real firewall or the single-instance lock.

## Open questions

- macOS and Linux. On macOS, blocking outbound traffic per app needs Apple's Network Extension and a paid developer ID.
- Store (UWP) apps, individual services inside `svchost`, per-domain or per-port rules, and an alert when a blocked app tries to connect (that needs a change to Windows' audit policy).
