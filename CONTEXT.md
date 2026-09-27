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

## Updates

Same shape as WattMail: check the signed `latest.json` at launch and every four hours, download, install and relaunch with only a banner. The install is quiet. Because this process is already elevated, the per-machine installer inherits that and does not show a second UAC prompt. The uninstall hook sees a silent update and does not ask about rules and does not remove the logon task. A real uninstall asks about the rules and always removes the task.

The updater cannot download a private GitHub release without a login, so the repository is public, same as WattMail. The signing key is `~\.tauri\wattwall-updater.key` (empty password) and the `TAURI_SIGNING_PRIVATE_KEY` secret. It is not in the repo.

## Not in v1

Recorded as open questions in `AGENTS.md`: macOS and Linux; Store apps; a single service inside `svchost`; per-domain or per-port rules; an alert when a blocked program tries to connect.
