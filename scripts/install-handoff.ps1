#Requires -Version 5.1
# Installs the local release, checks logon start, a real block, a quiet
# update-style reinstall, and --cleanup twice. Then starts WattWall again
# so the logon task is back. Run elevated.
[CmdletBinding()]
param(
    [string] $Setup = 'C:\Users\Swatto\WattWall\target\release\bundle\nsis\WattWall_0.1.0_x64-setup.exe',
    [string] $InstalledExe = 'C:\Program Files\WattWall\WattWall.exe'
)
$ErrorActionPreference = 'Stop'
$log = 'C:\Users\Swatto\WattWall\install-handoff.log'
function Write-Log([string] $Message) {
    Add-Content -LiteralPath $log -Value $Message
}
'' | Set-Content -LiteralPath $log
try {
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    $started = $null
    $oldUninstall = 'C:\Program Files\WattWall\uninstall.exe'
    if (Test-Path -LiteralPath $oldUninstall) {
        Write-Log 'remove previous install'
        $old = Start-Process -FilePath $oldUninstall -ArgumentList '/S' -Wait -PassThru
        Write-Log ("uninstall-exit=" + $old.ExitCode)
        Start-Sleep -Seconds 1
    }
    Write-Log "install $Setup"
    $proc = Start-Process -FilePath $Setup -ArgumentList '/S' -Wait -PassThru
    Write-Log ("installer-exit=" + $proc.ExitCode)
    if (-not (Test-Path -LiteralPath $InstalledExe)) { throw "not installed at $InstalledExe" }
    $version = (Get-Item -LiteralPath $InstalledExe).VersionInfo.ProductVersion
    Write-Log "installed-version=$version"
    Write-Log "installed-path=$InstalledExe"

    Write-Log 'first launch creates the logon task'
    $started = Start-Process -FilePath $InstalledExe -ArgumentList '--hidden' -PassThru
    $task = $null
    foreach ($i in 1..30) {
        $task = Get-ScheduledTask -TaskName 'WattWall' -ErrorAction SilentlyContinue
        if ($task) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $task) { throw 'logon task was not created' }
    Write-Log ("task-runlevel=" + $task.Principal.RunLevel)
    Write-Log ("task-execute=" + $task.Actions[0].Execute)
    Write-Log ("task-args=" + $task.Actions[0].Arguments)
    if ($started -and -not $started.HasExited) { Stop-Process -Id $started.Id -Force; $started = $null }
    Get-Process -Name 'WattWall' -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1

    Write-Log 'run the logon task'
    Start-ScheduledTask -TaskName 'WattWall'
    $fromTask = $null
    foreach ($i in 1..20) {
        $fromTask = Get-Process -Name 'WattWall' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($fromTask) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $fromTask) { throw 'the logon task did not start WattWall' }
    Write-Log ("task-started-pid=" + $fromTask.Id + " main-window=" + $fromTask.MainWindowHandle)
    Stop-Process -Id $fromTask.Id -Force

    Write-Log 'block curl with the installed copy'
    & $InstalledExe --block $curl --yes
    if ($LASTEXITCODE -ne 0) { throw "block failed $LASTEXITCODE" }
    & $curl -4 --max-time 15 https://example.com
    if ($LASTEXITCODE -eq 0) { throw 'curl succeeded while blocked' }
    & $InstalledExe --allow $curl
    if ($LASTEXITCODE -ne 0) { throw "allow failed $LASTEXITCODE" }

    Write-Log 'quiet update-style reinstall'
    $re = Start-Process -FilePath $Setup -ArgumentList '/S','/UPDATE' -Wait -PassThru
    Write-Log ("reinstall-exit=" + $re.ExitCode)
    if (-not (Test-Path -LiteralPath $InstalledExe)) { throw 'reinstall removed WattWall' }

    Write-Log 'cleanup twice'
    & $InstalledExe --cleanup
    if ($LASTEXITCODE -ne 0) { throw "cleanup 1 failed $LASTEXITCODE" }
    & $InstalledExe --cleanup
    if ($LASTEXITCODE -ne 0) { throw "cleanup 2 failed $LASTEXITCODE" }
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $left = @($policy.Rules) | Where-Object { $_.Grouping -eq 'WattWall' -and $_.Description -eq 'WattWall v1' }
    if (@($left).Count -ne 0) { throw 'cleanup left rules' }
    $taskLeft = Get-ScheduledTask -TaskName 'WattWall' -ErrorAction SilentlyContinue
    if ($taskLeft) { throw 'cleanup left the logon task' }

    Write-Log 'start again so logon start is restored'
    $started = Start-Process -FilePath $InstalledExe -ArgumentList '--hidden' -PassThru
    foreach ($i in 1..30) {
        if (Get-ScheduledTask -TaskName 'WattWall' -ErrorAction SilentlyContinue) { break }
        Start-Sleep -Milliseconds 500
    }
    Write-Log 'INSTALL OK'
    Write-Log 'INSTALL OK'
} catch {
    Write-Log ("ERROR: " + $_)
    Write-Log $_.ScriptStackTrace
    throw
} finally {
    if ($started -and -not $started.HasExited) { }
}
