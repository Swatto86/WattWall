#Requires -Version 5.1
# package.json, tauri.conf.json and the workspace version must agree.
# src-tauri/Cargo.toml uses version.workspace, so it cannot name a different one.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Read-Version([string] $Path, [string] $Pattern) {
    $match = Select-String -LiteralPath $Path -Pattern $Pattern | Select-Object -First 1
    if (-not $match) { throw "version check is broken: read nothing from $Path" }
    return $match.Matches[0].Groups[1].Value
}

$inherits = Select-String -LiteralPath 'src-tauri\Cargo.toml' -Pattern 'version\.workspace\s*=\s*true' | Select-Object -First 1
if (-not $inherits) { throw 'src-tauri/Cargo.toml must use version.workspace so it cannot drift' }

# Anchored to the start of the line so rust-version cannot answer instead.
$workspace = Read-Version 'Cargo.toml' '^version\s*=\s*"([^"]+)"'
$tauri = Read-Version 'src-tauri\tauri.conf.json' '"version": "([^"]+)"'
$npm = Read-Version 'package.json' '"version": "([^"]+)"'
if ($workspace -ne $tauri -or $workspace -ne $npm) {
    throw "version mismatch: Cargo.toml $workspace, tauri.conf.json $tauri, package.json $npm"
}
Write-Output "version agreement OK ($workspace)"
