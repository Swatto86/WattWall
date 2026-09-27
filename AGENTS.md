# WattWall — agent context

Windows tray app that adds per-program block rules to the Windows Firewall. `ARCHITECTURE.md` is the map. `CONTEXT.md` is the decisions still in force.

## Build / run / verify

- Dev: `npm run tauri dev`. The debug build does not elevate itself, so changing a real block from a dev run needs an administrator terminal. The window still lists programs.
- Iteration: `pwsh scripts/fastcheck.ps1` (`-Package wattwall-core` checks that crate only).
- Full gate: `pwsh scripts/verify.ps1` (frontend, fmt, clippy, tests, `tauri build --debug --no-bundle`, WebDriver). From PowerShell, `msedgedriver` must be on `PATH` (`C:\Users\Swatto\bin`).
- Install check (elevated): after `AGENT_RELEASE=1 npx tauri build`, run `scripts/install-handoff.ps1`. It upgrades the installed copy in place (a silent setup over it only replaces files; the uninstall hook does nothing when silent), keeps the owner's rules, saved list and logon task, blocks and allows `curl.exe` against the real firewall, and restarts WattWall through the logon task with its window hidden. `-WipeUserRulesAndData` also tests `--cleanup`, which deletes his rules, logon task and saved list: never use it on his PC without asking.
- Real firewall check (elevated): `scripts/live-accept.ps1`. It runs `--cleanup` before and after, so the same warning applies.
- App icons: edit `src-tauri/icons/source/*.svg`, then `node scripts/icons.mjs`. The tray and taskbar icon is drawn at run time (`crates/wattwall-core/src/meter.rs`).
- Release install is local and unsigned until a tag is published. Do not tag or publish a GitHub release unless asked.

## Constraints

- Windows only. Firewall changes go through `INetFwPolicy2`. No `netsh`, no PowerShell, no driver.
- A block is an outbound rule and an inbound rule for one exe path, group `WattWall`, description `WattWall v1`. Never edit, disable or delete a rule that does not match both the group and that description.
- The rules are the source of truth. In `%LOCALAPPDATA%\WattWall` the app keeps remembered programs and the autostart preference (`settings.json`), the VirusTotal choice, limits, hashes and answers (`virustotal.json`), and the VirusTotal key sealed in `secrets.bin`. The sealing key is the one Credential Manager item, `WattWall/vault-key`; `--cleanup` removes it with the folder.
- Network: GitHub for updates and, only when the owner turns it on, VirusTotal (`GET /api/v3/files/<sha256>`, hashes only, never files). The key never reaches the webview. Live check of the real request: `cargo test -p wattwall-desktop live_ -- --ignored`.
- The release build relaunches itself elevated when it is not. Logon start is a scheduled task, highest privileges, only for `Program Files\WattWall\WattWall.exe` after junctions are resolved. Portable and `target\` builds cannot enable it.
- The webview is bundled content only: strict CSP, no remote URLs, no shell or filesystem permissions. Rust checks every path the window sends.
- Confirm before blocking `svchost.exe`, `lsass.exe`, `tailscaled.exe`, `tailscale-ipn.exe`, or WattWall itself. `System` has no program file and cannot be blocked.
- `--cleanup` removes WattWall's rules, the task and app data, and is safe to run twice. Uninstall always removes the task and asks about the rules. A silent update must not ask and must not remove the rules.
- WebDriver uses `WATTWALL_FAKE=1` and `WATTWALL_E2E=1` (debug builds only) so it does not touch the real firewall, the single-instance lock, Credential Manager or the network (VirusTotal answers from a table).
- The tray menu must stay open while the owner reads it: nothing may change the tray, its menu or the window icons while a WattWall popup menu is on screen (`traymenu::is_open`).

## Open questions

- macOS and Linux. On macOS, blocking outbound traffic per app needs Apple's Network Extension and a paid developer ID.
- Store (UWP) apps, individual services inside `svchost`, per-domain or per-port rules, and an alert when a blocked app tries to connect (that needs a change to Windows' audit policy).
