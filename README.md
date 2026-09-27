# WattWall

WattWall adds a block for programs you choose to the Windows Firewall that is already on this PC. Windows still allows every other program out, and still blocks unsolicited inbound traffic. WattWall does not replace that.

Each block is two firewall rules, outbound and inbound, for that program's file, in a group named WattWall. You can see them in Windows Firewall (`wf.msc`). Turning all blocks off disables those rules until you turn them back on. Allow removes them.

The installed copy lives in `C:\Program Files\WattWall`. It can start at logon, already allowed to change the firewall, so Windows does not ask every boot. The portable exe runs on its own and asks for administrator each time you open it. It cannot turn on logon start.

## Requirements

Windows 10 or 11, 64-bit, and the [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/). The installer downloads it if it is missing. The portable exe does not.

## Cleanup

`WattWall.exe --cleanup` removes WattWall's firewall rules, the logon task, and WattWall's saved list. Running it again does nothing and is not an error. Uninstall asks whether to remove the rules. It always removes the logon task.

WattWall never changes a firewall rule it did not create.
