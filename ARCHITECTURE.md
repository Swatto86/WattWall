# WattWall architecture

WattWall is a Windows tray program. It adds block rules for chosen executables to the firewall Windows already runs. It does not install a driver and does not replace Windows' defaults: outbound traffic stays allowed except for those rules, and unsolicited inbound traffic stays blocked.

## Tech stack

- Rust workspace, edition 2021, toolchain pinned in `rust-toolchain.toml`. `wattwall-core` has no Windows calls. `src-tauri` is the Tauri 2 shell and the only crate that talks to Win32.
- Window: Vite, TypeScript, no framework. Tray and commands are Rust.
- Firewall: COM `INetFwPolicy2` / `INetFwRule` (`windows` crate).
- Who is on the network: `GetExtendedTcpTable` and `GetExtendedUdpTable`, IPv4 and IPv6, every few seconds, then `QueryFullProcessImageNameW`.
- An existing TCP connection is closed with `SetTcpEntry` (IPv4) or `NsiSetAllParameters` (IPv6). UDP has no connection to close; the rule stops the next datagram.
- Logon start: Task Scheduler, task name `WattWall`, logon trigger, highest privileges, argument `--hidden`.
- Updates: `tauri-plugin-updater`, signed manifest at `Swatto86/WattWall` `releases/latest/download/latest.json`. Quiet NSIS install.
- Package: per-machine NSIS into `C:\Program Files\WattWall`, plus the raw exe as the portable build. WebView2 is the system runtime, not bundled.

## Component map

- `crates/wattwall-core` — which rules are ours, which programs need a warning, how the Blocked and Seen lists are built, which path autostart may point at.
- `src-tauri/src/firewall.rs` — create, enable, disable and delete only our rules. Debug builds can use a JSON stand-in when `WATTWALL_FAKE=1`.
- `src-tauri/src/net.rs` — connection snapshot and closing TCP for one program.
- `src-tauri/src/programs.rs` — pid to path, icon, publisher (only when the signature checks out), elevation, final path.
- `src-tauri/src/task.rs` — create, read and delete the logon task.
- `src-tauri/src/engine.rs` — block, allow, suspend, remember, cleanup.
- `src-tauri/src/lib.rs` — window, tray menu, commands. `main.rs` handles `--cleanup`, `--cleanup-rules`, `--remove-task` and elevation.
- `src/main.ts` — the list, search, dialogs, update banner.
- `scripts/verify.ps1` — full gate. `scripts/e2e.mjs` — WebDriver journey on an isolated profile.

## Data flow

The poll thread reads the connection tables and our firewall rules, updates last-seen times, and emits a `state` event. The window draws that. A Block or Allow click sends the path to `set_blocked`. Rust canonicalises the path, refuses `System`, and asks for confirmation for the named dangerous programs unless the caller already confirmed. It then writes or deletes the two rules. If the block is in force, it closes that program's TCP connections. Suspend sets `Enabled` on every WattWall rule and, when turning blocks back on, closes those connections again.

Settings are written to a temp file and renamed. A failed write leaves the previous file.

## Release profile

`[profile.release]` is fat LTO, `strip`, `panic = abort`. Dev builds use line tables only. CI is Windows-only because the product is Windows-only.
