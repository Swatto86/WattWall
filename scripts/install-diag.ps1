#Requires -Version 5.1
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Swatto\WattWall\install-diag.log'
function L([string]$m) { Add-Content -LiteralPath $log -Value $m }
'' | Set-Content -LiteralPath $log
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = [Security.Principal.WindowsPrincipal]::new($id)
L ("elevated=" + $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
$setup = 'C:\Users\Swatto\WattWall\target\release\bundle\nsis\WattWall_0.1.0_x64-setup.exe'
L ("setup-exists=" + (Test-Path -LiteralPath $setup))
$proc = Start-Process -FilePath $setup -ArgumentList '/S' -Wait -PassThru
L ("exit=" + $proc.ExitCode)
L '--- program files ---'
Get-ChildItem 'C:\Program Files' -Directory | Where-Object { $_.Name -like '*Watt*' -or $_.Name -like '*watt*' } | ForEach-Object { L $_.FullName }
L '--- appdata ---'
Get-ChildItem "$env:LOCALAPPDATA\Programs" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Watt*' } | ForEach-Object { L $_.FullName }
L 'done'
