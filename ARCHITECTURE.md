# WattWall architecture

WattWall is a Windows tray program. It adds block rules for chosen executables to the firewall Windows already runs. It does not install a driver and does not replace Windows' defaults: outbound traffic stays allowed except for those rules, and unsolicited inbound traffic stays blocked.

## Tech stack

- Rust workspace, edition 2021, toolchain pinned in `rust-toolchain.toml`. `wattwall-core` has no Windows calls. `src-tauri` is the Tauri 2 shell and the only crate that talks to Win32.
- Window: Vite, TypeScript, no framework. Tray and commands are Rust.
- Firewall: COM `INetFwPolicy2` / `INetFwRule` (`windows` crate).
- Who is on the network: `GetExtendedTcpTable` and `GetExtendedUdpTable`, IPv4 and IPv6, every few seconds, then `QueryFullProcessImageNameW`.
- Connections view: the same tables read in full (both ends, state, owning process) every two seconds while the view is open, decoded from bytes in `wattwall-core`. Host names: the PTR record of each far address through `DnsQuery_W` (DNS only), on four worker threads.
- An existing TCP connection is closed with `SetTcpEntry` (IPv4) or `NsiSetAllParameters` (IPv6). UDP has no connection to close; the rule stops the next datagram.
- Traffic meter: `GetIfTable2` octet counters of hardware adapters, once a second.
- Logon start: Task Scheduler, task name `WattWall`, logon trigger, highest privileges, argument `--hidden`.
- Updates: `tauri-plugin-updater`, signed manifest at `Swatto86/WattWall` `releases/latest/download/latest.json`. Quiet NSIS install.
- Package: per-machine NSIS into `C:\Program Files\WattWall`, plus the raw exe as the portable build. WebView2 is the system runtime, not bundled.

## Component map

- `crates/wattwall-core/src/monitor/`: everything the Connections view decides without Windows. `wire.rs` decodes table bytes (its byte offsets are checked against Windows' structs when the shell compiles), `flows.rs` tells incoming from outgoing, `reach.rs` says how far away an address is, `tracker.rs` keeps connections that just closed for a minute, `names.rs` is the bookkeeping behind host-name lookups, `hostname.rs` the text side of a name (which are fit to show, what an address is called in DNS), and `dto.rs` and `view.rs` shape and order what the window gets.
- `crates/wattwall-core`: `virustotal.rs` reads reports, decides when a file is due again and paces lookups within the owner's limits. Also: which rules are ours, which programs need a warning, how the Blocked and Seen lists are built, which path autostart may point at. `meter.rs` draws the tray glyph as RGBA and turns byte counters into bar heights and rate text.
- `src-tauri/src/firewall.rs`: create, enable, disable and delete only our rules, including the two Block All rules. `fakewall.rs` is the debug builds' JSON stand-in (`WATTWALL_FAKE=1`).
- `src-tauri/src/net.rs`: connection snapshot, and closing TCP for one program or, for Block All, every connection that leaves the PC.
- `src-tauri/src/sockets.rs`: the tables as typed sockets plus the program each owning process runs (and the test mode's `fake-sockets.json`). `dns.rs`: the lookup workers and the cache of what they found. `resolver.rs`: what answers one address, the DNS client's PTR record or the test mode's `fake-dns.json`. `tables.rs`: the raw TCP and UDP tables, read again when one grows under the reader. `monitor.rs`: the two commands, `monitor_snapshot` and `set_resolve_names`, and the state kept between looks. `rows.rs`: a program's row as the window gets it.
- `src-tauri/src/traffic.rs`: adapter byte counters for the meter.
- `src-tauri/src/programs.rs`: pid to path, icon, publisher (only when the signature checks out), elevation, final path.
- `src-tauri/src/task.rs`: create, read and delete the logon task.
- `src-tauri/src/engine.rs`: block, allow, suspend, remember, cleanup.
- `src-tauri/src/tray.rs`: tooltip and the one-second loop that redraws the tray, title-bar and taskbar icons and swaps in the menu. `traymenu.rs` describes the menu as a plan, handles its items and tells whether a WattWall menu is open. `taskbar.rs` sets the window's big icon, which Tauri does not expose.
- `src-tauri/src/virustotal.rs`: the VirusTotal check's state, the worker that hashes and looks up one thing at a time, and what the window gets. `vtnet.rs` hashes files and makes the request (or the test mode's table). `vault.rs` seals the key in `secrets.bin` with AES-256-GCM (`ring`) under a key kept in Credential Manager.
- `src-tauri/src/lib.rs`: window, commands, the poll and traffic threads. `main.rs` handles `--cleanup`, `--cleanup-rules`, `--remove-task` and elevation.
- `src/main.ts`: wires up the state and traffic events, commands, dialogs and updates. `src/view.ts`: markup and the two lists, updated in place. `src/connections.ts`: the Connections view's wording and filters, with `connections.selfcheck.ts`. `src/monitor.ts`: its tabs, filter chips and lines, and the two-second look. `src/model.ts`: the wording and scales, with `model.selfcheck.ts`. `src/vt.ts`: the VirusTotal settings, setup dialog and details dialog.
- `src-tauri/icons/source/*.svg`: app icon sources; `scripts/icons.mjs` renders every icon file from them.
- `scripts/verify.ps1`: full gate. `scripts/e2e.mjs`: WebDriver journey on an isolated profile.

## Data flow

The poll thread reads the connection tables and our firewall rules, updates last-seen times, and emits a `state` event. The window draws that. A Block or Allow click sends the path to `set_blocked`. Rust canonicalises the path, refuses `System`, and asks for confirmation for the named dangerous programs unless the caller already confirmed. It then writes or deletes the two rules. If the block is in force, it closes that program's TCP connections. Suspend sets `Enabled` on every WattWall rule and, when turning blocks back on, closes those connections again.

The Connections view works the other way round: nothing runs for it until the owner opens it. While it is open and the window is showing, the window asks `monitor_snapshot` every two seconds. Rust reads the four tables, decodes them, works out each connection's direction, folds the look into the tracker (so a connection that vanished stays listed, closed, for a minute), queues unnamed far addresses for the lookup workers and answers with the lines in display order, using whatever names have come back so far. A later look picks up names that arrive afterwards. A hidden or minimized window gets `null`, and nothing is read or asked; leaving the view, or turning names off, drops the lookups still waiting (`monitor_close`).

A second thread reads the adapter counters every second. It redraws the tray icon (small-icon size), the window's title-bar icon (the same image) and its taskbar icon (large-icon size) when a bar height or the paused state changes, updates the tooltip, and emits a `traffic` event that the header's rates and graph draw. Only this thread talks to Windows about icons; the poll thread just records whether blocks are off.

A third thread runs the VirusTotal check when it is on. Each second it takes one step: hash the next listed program whose file is new or changed (connected programs first, then blocked, then the rest), or, when the pacer allows, look up the next hash that has no fresh answer. An answer refreshes the window. Only hashes and the key leave the PC.

Settings are written to a temp file and renamed. A failed write leaves the previous file.

## Release profile

`[profile.release]` is fat LTO, `strip`, `panic = abort`. Dev builds use line tables only. CI is Windows-only because the product is Windows-only.
