#Requires -Version 5.1
<#
.SYNOPSIS
  Fast iteration gate. Formatting and a typecheck; clippy for the whole workspace.
  -Package <crate> checks that crate only.
#>
[CmdletBinding()]
param([string] $Package)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if ($Package) {
    cargo check --locked -p $Package --all-targets
    exit $LASTEXITCODE
}

cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npx tsc --noEmit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo clippy --locked --workspace --all-targets -- -D warnings
exit $LASTEXITCODE
