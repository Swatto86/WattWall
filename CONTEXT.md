# WattWall — decisions in force

## Firewall

WattWall uses the Windows Firewall COM API (`INetFwPolicy2`). A driver of our own would not load with Memory Integrity on. `netsh` and PowerShell would be a second language and a second failure mode for the same rules.

One block is an outbound block and an inbound block for that exe, profiles all, protocol any, group `WattWall`, description `WattWall v1`. The name is `WattWall Out` or `WattWall In` plus a hash of the lower-cased path, because a path can be longer than a rule name. Rules that do not carry both the group and the description are left alone, including a rule someone put in the WattWall group by hand.

The rules are the source of truth for what is blocked. `%LOCALAPPDATA%\WattWall\settings.json` only remembers programs that have used the network (so they stay in the list with a last-seen time) and whether logon start is wanted. The remembered list drops the oldest unblocked programs past 400.

"Turn all blocks off" sets our rules to disabled. It does not delete them. A new block made while they are off is created disabled, so the pause stays in force. "Turn all blocks on" enables them and closes existing TCP connections for those programs.

Windows does not drop a connection it has already allowed when a block rule appears. WattWall then closes it. IPv4 uses the documented `SetTcpEntry`. IPv6 has no documented equivalent; WattWall calls `NsiSetAllParameters` in `nsi.dll`, which is the same call `SetTcpEntry` makes. That is user mode, not a driver. UDP bindings are not connections; the rule stops the next datagram.

`System` (pid 4) has no program file, so a firewall rule cannot name it. The window says so instead of pretending to block it.

## Elevation and logon start

Changing rules needs administrator. The release exe asks for it when it is not already elevated. The debug exe does not, so tests and `tauri dev` can open the window without a prompt; a real block from a debug build still needs an elevated process.

Logon start is a scheduled task that runs the installed exe with highest privileges and `--hidden`. The task is already elevated, so there is no UAC prompt at logon. A Run key cannot do that.

Autostart is offered only when this process's real path, after junctions, is `Program Files\WattWall\WattWall.exe`. The program file is named `WattWall.exe` (not the crate name) so that check matches what the installer writes. A copy under Downloads, Temp, or `target\` is refused, and a task that points at such a copy is removed. The installed app turns the task on the first time it runs, and Settings can turn it off. The portable exe cannot turn it on.

The installer is per-machine, under Program Files, because the task launches that exe as administrator. A copy in a user-writable folder could be replaced and would then run as administrator at the next logon.

## Window

The webview is elevated when the app is. It loads only the bundled page, the CSP has no remote hosts, and the capability set has no shell or filesystem access. Rust checks every path: absolute, `.exe`, and the file must exist before a new block.

Closing the window hides it. Quit is the tray item (and `quit_app`). The program is a window app, so opening it does not create a command prompt. A command such as `--cleanup`, launched from an existing prompt, prints into that prompt.

The lists are tables with fixed columns (Program, VirusTotal when it is on, Status, the button) so results line up. The window follows the Windows light or dark setting. The lists are updated in place rather than rebuilt, so the three-second refresh keeps keyboard focus and does not reload program icons. While a dialog is open the rest of the window is inert, and focus returns where it was.

The debug build's file-backed firewall needs no administrator, so the "not running as administrator" warning only appears against the real firewall (`Engine::needs_admin`).

## Tray and taskbar meter

At the owner's request the tray icon is dynamic, like ZoneAlarm's: a brick wall with a red bar for bytes sent and a green bar for bytes received, redrawn once a second, and a grey wall while blocks are off. The taskbar button shows the same drawing while the window is open. It is drawn in Rust (`wattwall-core` `meter.rs`) at the exact sizes Windows asks for (`SM_CXSMICON` for the tray and title bar, `SM_CXICON` for the taskbar), on a 16-pixel grid with every edge rounded to a whole pixel, so it stays sharp at every scaling. The bars are logarithmic from 1 KB/s to 10 MB/s so ordinary background traffic still shows.

The counters are `GetIfTable2` octets from hardware adapters that are up, skipping the filter rows Windows lists beside each adapter (they repeat its counters) and virtual adapters such as a VPN (their traffic also crosses a hardware adapter). Rates are summed per adapter between two readings, so an adapter that appears or resets is not a burst.

Only the traffic thread hands icons and the tooltip to Windows, and only when a bar height, the paused state or the text changes. Tray calls wait for the main thread, so the thread decides under a lock and calls Windows after releasing it. Tauri only sets a window's small icon, so `taskbar.rs` sends `WM_SETICON` for the big one on the main thread and frees the icon it replaces. A taskbar shortcut the user pinned may still show the installed icon; that was not tested.

The app icon (installer, exe, Start menu) is the static orange tile from `src-tauri/icons/source`. Its 16-pixel layer is drawn separately with three courses of bricks, because four blur together at that size.

## VirusTotal

At the owner's request WattWall can check programs with VirusTotal, like Process Explorer. It is off until he turns it on; the setup dialog asks for his own API key and his key's limits (lookups a minute and a day), starting from the free Public API's 4 and 500, because keys differ and he wanted to set them rather than have them fixed. Only a file's SHA-256 is sent, never the file, which tells VirusTotal which programs he runs; the dialog says so. Answers are kept in `virustotal.json`: a found file is looked up again after a week, an unknown one after a day. A "quota used up" answer (429) pauses lookups for five minutes, and for an hour after three in a row. A rejected key (401 or 403) stops lookups until a new key is saved.

The key is sealed in `secrets.bin` (AES-256-GCM, fresh nonce, temp file and rename) under a 32-byte key that is the only Credential Manager item, read at most once per process; an absent file costs no Credential Manager read. This is the vault pattern from WattMail, built with `ring` and the Credential Manager API because both were already in the build (no `aes-gcm` or `keyring` crates). The key goes from the setup dialog to Rust once and is never sent back to the window. `--cleanup` removes the folder and the Credential Manager item.

The setup dialog can read the key's real limits from VirusTotal (`/users/{key}/overall_quotas`, falling back to `/users/{key}`; VirusTotal documents that these do not use quota): the daily allowance, and a sixtieth of the hourly one a minute. A refused lookup shows VirusTotal's own reason, such as "Quota exceeded". The owner's key made one lookup and was then refused, so the reason and the real limits matter more than the documented free limits.

Clicking a result opens a details dialog with the detections and a Copy report link button. WattWall runs elevated, so it does not open a browser itself.

## Block All

At the owner's request (he remembered ZoneAlarm's internet lock), Block All cuts every program off the network. It is two rules like a block but with no program, named exactly `WattWall Block All Out` and `WattWall Block All In`, so the "only our rules" test still matches names exactly. Block rules win over allow rules in Windows Firewall, so programs that other software allowed are cut off too. Windows keeps connections it already allowed, so turning it on closes every TCP connection whose far end is not this PC; loopback keeps working. It is not part of "Turn all blocks off", and it survives restarts because the rules are the record. The window and the tray menu ask first, since it also cuts remote access such as Tailscale. VirusTotal lookups wait while it is on. From an elevated prompt, `--allow-all` turns it off and `--cleanup-rules` removes it with every other WattWall rule.

## Tray menu

A left click opens the window; the menu is on the right click only (Tauri shows it on both by default, and the window opening closed it at once). The menu starts with the state line, then "Online now: tick one to block it" over the programs online now, sorted by name and marked (blocked) or (block paused). It is described by a plan and replaced only when the plan changes, and nothing changes the tray, its menu or the window icons while a WattWall popup menu is on screen. Before this, the menu closed itself about a second after it opened; a foreground right-click probe showed it.

## Updates

Same shape as WattMail: check the signed `latest.json` at launch and every four hours, download, install and relaunch with only a banner. The install is quiet. Because this process is already elevated, the per-machine installer inherits that and does not show a second UAC prompt. The uninstall hook sees a silent update and does not ask about rules and does not remove the logon task. A real uninstall asks about the rules and always removes the task.

The updater cannot download a private GitHub release without a login, so the repository is public, same as WattMail. The signing key is `~\.tauri\wattwall-updater.key` (empty password) and the `TAURI_SIGNING_PRIVATE_KEY` secret. It is not in the repo.

## Not in v1

Recorded as open questions in `AGENTS.md`: macOS and Linux; Store apps; a single service inside `svchost`; per-domain or per-port rules; an alert when a blocked program tries to connect.
