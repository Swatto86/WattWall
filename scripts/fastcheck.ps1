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

# File-size guideline (the agent-standards engineering skill): a code file over 400 lines needs a
# reason on record or a split; files already over it are listed in
# scripts/file-size-baseline.txt and may not grow.
$sizeCheck = Join-Path $HOME '.agents/scripts/check-file-size.ps1'
if (Test-Path -LiteralPath $sizeCheck) {
    pwsh -NoProfile -File $sizeCheck -Root (Get-Location).Path
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host 'skip - file size check: ~/.agents/scripts/check-file-size.ps1 not found'
}

cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npx tsc --noEmit
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo clippy --locked --workspace --all-targets -- -D warnings
exit $LASTEXITCODE
