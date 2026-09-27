#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Upgrades the installed WattWall in place from the local release build and checks it,
  keeping the owner's firewall rules, saved program list and logon task.

.DESCRIPTION
  Build the installer first (AGENT_RELEASE=1 npx tauri build). Run from an elevated shell.
  1. Records WattWall's rules, the saved program count and the logon task.
  2. Stops only the installed WattWall and runs the new setup with /S. A silent install over
     the installed copy replaces the files; the uninstall hook does nothing when silent.
  3. Checks the installed version, then blocks and allows curl.exe against the real firewall
     (reversible) and checks the rule count, the saved list and the logon task are as before.
  4. Starts WattWall the way sign-in does (the logon task, with --hidden) and checks its window
     stays hidden.
  -WipeUserRulesAndData also tests --cleanup, which DELETES every WattWall rule, the logon task
  and the saved program list. Never use it on the owner's PC without asking him.
  -TestBlockAll also turns Block All on and off with --block-all and --allow-all. Every program
  on this PC loses the network for those seconds and open connections are closed, so ask first.
#>
[CmdletBinding()]
param(
    # Defaults to the local build of the version in src-tauri/tauri.conf.json.
    [string] $Setup,
    [string] $InstalledExe = (Join-Path $env:ProgramFiles 'WattWall\WattWall.exe'),
    [string] $Log,
    [switch] $WipeUserRulesAndData,
    [switch] $TestBlockAll
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json).version
if (-not $Setup) { $Setup = Join-Path $root "target\release\bundle\nsis\WattWall_${version}_x64-setup.exe" }
if (-not $Log) { $Log = Join-Path $root 'install-handoff.log' }
$probe = Join-Path $env:SystemRoot 'System32\curl.exe'
$settings = Join-Path $env:LOCALAPPDATA 'WattWall\settings.json'

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class WattWallWindow {
    delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr hwnd, StringBuilder name, int size);
    // 0: no WattWall window yet, 1: hidden, 2: visible.
    public static int State(uint processId) {
        int state = 0;
        EnumWindows((hwnd, lParam) => {
            uint owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner != processId) return true;
            var name = new StringBuilder(64);
            GetClassName(hwnd, name, name.Capacity);
            if (name.ToString() != "Tauri Window") return true;
            state = IsWindowVisible(hwnd) ? 2 : 1;
            return false;
        }, IntPtr.Zero);
        return state;
    }
}
"@

function Write-Log([string] $Message) {
    Add-Content -LiteralPath $Log -Value $Message
    Write-Host $Message
}

function Get-WattWallRules {
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    @($policy.Rules) | Where-Object { $_.Grouping -eq 'WattWall' -and $_.Description -eq 'WattWall v1' }
}

function Get-RememberedCount {
    if (-not (Test-Path -LiteralPath $settings)) { return -1 }
    $saved = Get-Content -LiteralPath $settings -Raw | ConvertFrom-Json
    if ($null -eq $saved.remembered) { return 0 }
    return @($saved.remembered).Count
}

function Get-InstalledProcess {
    Get-Process -Name 'WattWall' -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $InstalledExe }
}

function Invoke-WattWall([string[]] $Arguments) {
    $process = Start-Process -FilePath $InstalledExe -ArgumentList $Arguments -Wait -PassThru
    return $process.ExitCode
}

function Test-Online {
    & $probe -4 -s -o NUL --max-time 15 https://example.com
    return ($LASTEXITCODE -eq 0)
}

function Get-LogonTask {
    Get-ScheduledTask -TaskName 'WattWall' -ErrorAction SilentlyContinue
}

function Assert-LogonTask($Task) {
    $action = $Task.Actions[0]
    Write-Log "task execute=$($action.Execute) arguments=$($action.Arguments) runlevel=$($Task.Principal.RunLevel)"
    if ($action.Execute -ne $InstalledExe) { throw "the logon task runs $($action.Execute), not $InstalledExe" }
    if ($action.Arguments -ne '--hidden') { throw "the logon task passes '$($action.Arguments)', not --hidden" }
    if ($Task.Principal.RunLevel -ne 'Highest') { throw "the logon task runs at $($Task.Principal.RunLevel), not Highest" }
}

function Start-WattWall {
    if (Get-LogonTask) {
        Start-ScheduledTask -TaskName 'WattWall'
    } else {
        Start-Process -FilePath $InstalledExe -ArgumentList '--hidden' | Out-Null
    }
}

'' | Set-Content -LiteralPath $Log
$restartAfterFailure = $false
try {
    if (-not (Test-Path -LiteralPath $Setup)) { throw "No installer at $Setup. Build it with: AGENT_RELEASE=1 npx tauri build" }
    Write-Log "setup=$Setup"
    if ($WipeUserRulesAndData) {
        Write-Log 'WipeUserRulesAndData: this run DELETES every WattWall firewall rule, the logon task and the saved program list.'
    }

    $running = @(Get-InstalledProcess)
    $restartAfterFailure = $running.Count -gt 0
    $running | Stop-Process -Force
    $running | ForEach-Object { [void] $_.WaitForExit(10000) }

    $rulesBefore = @(Get-WattWallRules)
    $paused = @($rulesBefore | Where-Object { -not $_.Enabled }).Count -gt 0
    $rememberedBefore = Get-RememberedCount
    $taskBefore = Get-LogonTask
    $previous = if (Test-Path -LiteralPath $InstalledExe) { (Get-Item -LiteralPath $InstalledExe).VersionInfo.ProductVersion } else { 'none' }
    Write-Log "before: version=$previous rules=$($rulesBefore.Count) blocks-off=$paused remembered=$rememberedBefore task=$([bool] $taskBefore) was-running=$restartAfterFailure"
    $probeRules = @($rulesBefore | Where-Object { ($_.ApplicationName -replace '^\\\\\?\\', '') -ieq $probe })
    if ($probeRules.Count -gt 0) { throw "curl.exe is already blocked; the block check would remove that block. Allow it first." }

    $install = Start-Process -FilePath $Setup -ArgumentList '/S' -Wait -PassThru
    Write-Log "installer-exit=$($install.ExitCode)"
    if ($install.ExitCode -ne 0) { throw "the installer failed with $($install.ExitCode)" }
    $installed = (Get-Item -LiteralPath $InstalledExe).VersionInfo.ProductVersion
    Write-Log "installed version=$installed path=$InstalledExe"
    if ($installed -ne $version) { throw "expected $version at $InstalledExe, found $installed" }

    if (-not (Test-Online)) { throw 'curl.exe cannot reach https://example.com before blocking, so the block cannot be checked' }
    $quotedProbe = '"' + $probe + '"'
    $code = Invoke-WattWall @('--block', $quotedProbe, '--yes')
    Write-Log "block-exit=$code"
    if ($code -ne 0) { throw "--block failed with $code" }
    $added = @(Get-WattWallRules).Count - $rulesBefore.Count
    $online = Test-Online
    Write-Log "rules-added=$added online-while-blocked=$online"
    if ($added -ne 2) { throw "a block must add two rules, it added $added" }
    if ($paused -and -not $online) { throw 'a block made while blocks are off must stay off' }
    if (-not $paused -and $online) { throw 'curl.exe still reached the network while blocked' }
    $code = Invoke-WattWall @('--allow', $quotedProbe)
    Write-Log "allow-exit=$code"
    if ($code -ne 0) { throw "--allow failed with $code" }
    $rulesAfter = @(Get-WattWallRules).Count
    $online = Test-Online
    Write-Log "rules-after=$rulesAfter online-after-allow=$online"
    if ($rulesAfter -ne $rulesBefore.Count) { throw "rule count is $rulesAfter, was $($rulesBefore.Count)" }
    if (-not $online) { throw 'curl.exe cannot reach the network after allow' }

    if ($TestBlockAll) {
        $code = Invoke-WattWall @('--block-all')
        $blockAllRules = @(Get-WattWallRules | Where-Object { $_.Name -like 'WattWall Block All *' }).Count
        $online = Test-Online
        Write-Log "block-all-exit=$code block-all-rules=$blockAllRules online-during-block-all=$online"
        $code2 = Invoke-WattWall @('--allow-all')
        $left = @(Get-WattWallRules | Where-Object { $_.Name -like 'WattWall Block All *' }).Count
        $back = Test-Online
        Write-Log "allow-all-exit=$code2 block-all-rules-after=$left online-after-allow-all=$back"
        if ($code -ne 0 -or $blockAllRules -ne 2) { throw 'Block All did not add its two rules' }
        if ($online) { throw 'curl.exe still reached the network during Block All' }
        if ($code2 -ne 0 -or $left -ne 0) { throw 'Allow all did not remove the Block All rules' }
        if (-not $back) { throw 'curl.exe cannot reach the network after Allow all' }
    }

    $rememberedAfter = Get-RememberedCount
    Write-Log "remembered-after=$rememberedAfter"
    if ($rememberedAfter -ne $rememberedBefore) { throw "the saved list changed from $rememberedBefore to $rememberedAfter" }
    $taskAfter = Get-LogonTask
    if ($taskBefore -and -not $taskAfter) { throw 'the upgrade removed the logon task' }
    if ($taskAfter) { Assert-LogonTask $taskAfter }

    if ($WipeUserRulesAndData) {
        $reinstall = Start-Process -FilePath $Setup -ArgumentList '/S', '/UPDATE' -Wait -PassThru
        Write-Log "update-style-reinstall-exit=$($reinstall.ExitCode)"
        if ($reinstall.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $InstalledExe)) { throw 'the update-style reinstall failed' }
        foreach ($attempt in 1, 2) {
            $code = Invoke-WattWall @('--cleanup')
            Write-Log "cleanup-$attempt-exit=$code"
            if ($code -ne 0) { throw "--cleanup run $attempt failed with $code" }
        }
        if (@(Get-WattWallRules).Count -ne 0) { throw 'cleanup left WattWall rules' }
        if (Get-LogonTask) { throw 'cleanup left the logon task' }
        if (Test-Path -LiteralPath $settings) { throw 'cleanup left the saved list' }
    }

    Start-WattWall
    $restartAfterFailure = $false
    $started = $null
    foreach ($i in 1..30) {
        Start-Sleep -Milliseconds 500
        $started = Get-InstalledProcess | Select-Object -First 1
        if ($started) { break }
    }
    if (-not $started) { throw 'WattWall did not start' }
    $state = 0
    foreach ($i in 1..30) {
        $state = [WattWallWindow]::State([uint32] $started.Id)
        if ($state -ne 0) { break }
        Start-Sleep -Milliseconds 500
    }
    if ($state -eq 0) { throw 'WattWall started but never created its window' }
    Start-Sleep -Seconds 5
    $state = [WattWallWindow]::State([uint32] $started.Id)
    Write-Log "started pid=$($started.Id) window=$(if ($state -eq 1) { 'hidden' } else { 'visible' })"
    if ($state -ne 1) { throw 'a --hidden start showed the window; it must stay in the tray' }

    if ($WipeUserRulesAndData) {
        $task = $null
        foreach ($i in 1..30) {
            $task = Get-LogonTask
            if ($task) { break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $task) { throw 'WattWall did not turn logon start back on after the cleanup' }
        Assert-LogonTask $task
    }
    Write-Log 'INSTALL OK'
} catch {
    Write-Log ("ERROR: " + $_)
    Write-Log $_.ScriptStackTrace
    throw
} finally {
    if ($restartAfterFailure) {
        try {
            Start-WattWall
            Write-Log 'WattWall was running before, so it was started again.'
        } catch {
            Write-Log ("WattWall could not be started again: " + $_)
        }
    }
}
