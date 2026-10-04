#Requires -Version 5.1
# Live check of the real Windows Firewall. Run elevated.
# Leaves no WattWall rules and no probe rule behind.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Exe,
    # user@host of a machine this PC already reaches over SSH. The check proves that route still works
    # while WattWall's rules are in place and after they are removed. It is a parameter because the
    # maintainer's own machines are not named in this public repository.
    [Parameter(Mandatory)] [string] $SshTarget
)
$ErrorActionPreference = 'Stop'
$log = Join-Path $env:TEMP 'wattwall-live.log'
Start-Transcript -LiteralPath $log -Force | Out-Null
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (-not (Test-Path -LiteralPath $Exe)) { throw "Missing $Exe" }
if (-not (Test-Path -LiteralPath $curl)) { throw "Missing $curl" }

function Invoke-WattWall {
    param([Parameter(ValueFromRemainingArguments)] [string[]] $Args)
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) { throw "WattWall $($Args -join ' ') failed ($LASTEXITCODE)" }
}

function Get-WattWallRules {
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    @($policy.Rules) | Where-Object { $_.Grouping -eq 'WattWall' -and $_.Description -eq 'WattWall v1' }
}

$hold = $null
$probeName = 'WattWall connection probe'
try {
    Write-Output 'ssh before'
    ssh -o BatchMode=yes -o ConnectTimeout=15 $SshTarget 'echo ssh-ok'

    Write-Output 'cleanup twice'
    Invoke-WattWall --cleanup
    Invoke-WattWall --cleanup
    $left = @(Get-WattWallRules)
    if ($left.Count -ne 0) { throw "cleanup left $($left.Count) rules" }

    Write-Output 'hold a connection'
    $out = Join-Path $env:TEMP 'wattwall-slow.bin'
    $hold = Start-Process -FilePath $curl -ArgumentList @('-4', '-o', $out, '--limit-rate', '100', '--max-time', '90', 'https://www.rfc-editor.org/rfc/rfc791.txt') -PassThru -WindowStyle Hidden
    $seen = $false
    foreach ($i in 1..20) {
        $conn = @(Get-NetTCPConnection -OwningProcess $hold.Id -ErrorAction SilentlyContinue)
        if ($conn.Count -gt 0) { $seen = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $seen) { throw 'the held curl never opened a connection' }

    Write-Output 'does Windows drop it when a block rule appears'
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $probe = New-Object -ComObject HNetCfg.FWRule
    $probe.Name = $probeName
    $probe.ApplicationName = $curl
    $probe.Direction = 2
    $probe.Action = 0
    $probe.Enabled = $true
    $probe.Profiles = 2147483647
    $probe.Protocol = 256
    $policy.Rules.Add($probe)
    Start-Sleep -Seconds 2
    $still = @(Get-NetTCPConnection -OwningProcess $hold.Id -ErrorAction SilentlyContinue)
    $policy.Rules.Remove($probeName)
    Write-Output ("windows-left-connections=" + $still.Count)
    $still | ForEach-Object { Write-Output ("windows-left " + $_.LocalAddress + " -> " + $_.RemoteAddress + " " + $_.State) }

    Write-Output 'WattWall block cuts it'
    Invoke-WattWall --block $curl --yes
    Start-Sleep -Seconds 1
    $after = @(Get-NetTCPConnection -OwningProcess $hold.Id -ErrorAction SilentlyContinue)
    Write-Output ("wattwall-left-connections=" + $after.Count)
    $after | ForEach-Object { Write-Output ("left " + $_.LocalAddress + " -> " + $_.RemoteAddress + " " + $_.State) }
    $established = @($after | Where-Object { $_.State -eq 'Established' -or $_.State -eq 'SynSent' -or $_.State -eq 'SynReceived' -or $_.State -eq 'CloseWait' -or $_.State -eq 'FinWait1' -or $_.State -eq 'FinWait2' })
    if ($established.Count -ne 0) { throw 'WattWall did not cut the open connection' }
    $rules = @(Get-WattWallRules)
    if ($rules.Count -lt 2) { throw "expected outbound and inbound rules, saw $($rules.Count)" }

    Write-Output 'curl fails while blocked'
    & $curl -4 --max-time 15 https://example.com
    if ($LASTEXITCODE -eq 0) { throw 'curl succeeded while blocked' }

    Write-Output 'blocks off'
    Invoke-WattWall --blocks-off
    & $curl -4 --max-time 20 https://example.com
    if ($LASTEXITCODE -ne 0) { throw 'curl failed while blocks were off' }

    Write-Output 'blocks on'
    Invoke-WattWall --blocks-on
    & $curl -4 --max-time 15 https://example.com
    if ($LASTEXITCODE -eq 0) { throw 'curl succeeded after blocks were turned back on' }

    Write-Output 'allow'
    Invoke-WattWall --allow $curl
    & $curl -4 --max-time 20 https://example.com
    if ($LASTEXITCODE -ne 0) { throw 'curl failed after allow' }
    if (@(Get-WattWallRules).Count -ne 0) { throw 'allow left rules behind' }

    Write-Output 'ssh after'
    ssh -o BatchMode=yes -o ConnectTimeout=15 $SshTarget 'echo ssh-ok'
    Write-Output 'LIVE OK'
} finally {
    if ($hold -and -not $hold.HasExited) { Stop-Process -Id $hold.Id -Force -ErrorAction SilentlyContinue }
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        $policy.Rules.Remove($probeName)
    } catch {}
    if (Test-Path -LiteralPath $Exe) {
        & $Exe --allow $curl
        & $Exe --cleanup
    }
    Stop-Transcript | Out-Null
}
