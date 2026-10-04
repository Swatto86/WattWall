# WattWall

WattWall blocks the programs you choose, using the Windows Firewall that is already on your PC. Pick a program, press Block, and it can no longer reach the network in either direction. Every other program carries on as before, and Windows still blocks unsolicited inbound traffic as it always has.

![WattWall: blocked programs at the top, programs seen on the network below, live traffic in the header](docs/wattwall.png)

## What it does

- **Shows who is on the network.** Every program with a connection or an open port appears with its icon, verified publisher and when it was last seen. Programs you have blocked are listed at the top.
- **Shows every connection, incoming and outgoing.** The Connections tab lists each TCP connection with the program that owns it, which way it goes, where the other end is (with its host name when DNS has one, and its address and port) and which port on this PC it uses. Ports that programs are listening on are listed too, and a connection that has just closed stays on the list for a minute. Filter by direction or search by program, host or port, and block a program from its own line.
- **Blocks in one click.** Block adds two firewall rules for that program's file, outbound and inbound, and closes the connections it already has. Allow removes them. Block a program lets you pick any `.exe`.
- **Block all internet access.** One switch cuts every program off the network, like ZoneAlarm's internet lock, and closes the connections they have open. Allow internet (or `WattWall.exe --allow-all` from an administrator prompt) turns it off.
- **Turn all blocks off, and on again.** Handy for checking whether a block is what stopped something working. The rules are switched off, not deleted.
- **Live tray and taskbar icon.** A small brick wall with a red bar for data sent and a green bar for data received, redrawn every second, like ZoneAlarm's tray meter. The wall turns grey while blocks are off. The taskbar button shows the same icon while the window is open, and the window header shows the last minute as a graph.
- **Checks programs with VirusTotal, if you want.** Like Process Explorer, WattWall can look up each program's SHA-256 hash and show how many security engines flag it, for example VT 0/72. It uses your own VirusTotal API key and your key's limits, sends only hashes, never files, and is off until you turn it on in Settings. The key is stored encrypted.
- **Starts with Windows, hidden in the tray.** The installed copy starts at sign-in without opening its window and without a UAC prompt. Turn it off in Settings.
- **Updates itself** from this repository's releases: download, install and restart, with only a banner.
- **Asks first** before blocking programs Windows or your VPN need (`svchost.exe`, `lsass.exe`, `tailscaled.exe`, `tailscale-ipn.exe`) or WattWall itself. `System` has no program file, so it cannot be blocked.

## The Connections tab

- **Incoming or outgoing** is worked out from the ports, because Windows does not record who started a connection: one to a port a program is listening on is incoming, one from a fresh port is outgoing. A program that connects out from the port it also listens on is usually shown as incoming.
- **UDP** shows only the open ports (as Listening). Windows keeps no record of who a UDP program talks to, so a browser's QUIC traffic does not appear as a connection.
- **Host names** come from asking your PC's own DNS server what name belongs to each remote address (nothing on your local network is probed). That is the name of the address, not the name the program asked for, so a big site may show a name like `ec2-3-4-5-6.compute-1.amazonaws.com`, and the owner of an address chooses its name, so treat it as a hint, not proof. A device on your own network gets a name only if your DNS server knows it. Asking tells your DNS server which addresses you connect to, so Settings has a "Look up host names" switch. WattWall looks nothing up until you open the tab, and stops when you leave it, hide the window in the tray or minimize it.
- **Nothing is saved.** Connections are not written to disk; the list starts empty each time WattWall starts.
- Connections between programs on this PC (loopback) are hidden until you tick "Include this PC's own connections".

## Where the rules live

Each block is two rules in Windows Defender Firewall, in a group named WattWall. You can see them in `wf.msc`. WattWall only ever changes rules it created, and those rules are the record of what is blocked. The app itself keeps the list of programs it has seen, the start-with-Windows choice and the host-names choice in `settings.json` and, if you turn VirusTotal on, its answers in `virustotal.json` and your key, encrypted, in `secrets.bin`, all in `%LOCALAPPDATA%\WattWall`.

## The tray menu

Left-click the tray icon to open WattWall. Right-click it for the menu: whether blocks are on, the programs using the network right now (tick one to block it, untick to allow it), Turn all blocks off or on, Open and Quit.

## Install

Download from [Releases](https://github.com/Swatto86/WattWall/releases):

- `WattWall_<version>_x64-setup.exe` installs for all users into `C:\Program Files\WattWall`, starts with Windows and updates itself.
- `WattWall_<version>_x64-portable.exe` runs on its own. It asks for administrator each time it opens and cannot start with Windows.
- `SHA256SUMS.txt` has a checksum for every file.

Requirements: Windows 10 or 11, 64-bit, and the [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) (part of Windows 11; the installer fetches it if it is missing). Changing firewall rules needs administrator, so WattWall asks for it when it opens. The logon start is already elevated, so it does not ask.

## Remove everything

`WattWall.exe --allow-all` turns Block All off. `WattWall.exe --cleanup` removes WattWall's firewall rules, the logon task and WattWall's saved list. Running it again does nothing and is not an error. Uninstalling asks whether to remove the rules and always removes the logon task.

## Build from source

Needs Rust (the version in `rust-toolchain.toml`, MSVC), Node 22 or later and the [Tauri prerequisites for Windows](https://v2.tauri.app/start/prerequisites/).

```powershell
npm ci
npm run tauri dev
pwsh scripts/verify.ps1
```

`tauri dev` runs a debug build, which does not elevate itself: it lists programs, but changing a real block needs an administrator terminal. `scripts/verify.ps1` is the full gate: formatting, clippy, Rust and frontend tests, a debug build and a WebDriver journey that drives the real app against a file-backed stand-in for the firewall. The app icons are drawn from `src-tauri/icons/source` by `node scripts/icons.mjs`; the tray icon is drawn at run time.

`ARCHITECTURE.md` maps the code and `CONTEXT.md` records the decisions behind it.

## Licence

[MIT](LICENSE)
