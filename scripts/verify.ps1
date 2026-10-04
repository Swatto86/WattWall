#Requires -Version 5.1
# Full gate: format, clippy, tests, a debug app binary, and the WebDriver journey.
# Installer packaging is the release workflow, not this script.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

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

npm run build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
pwsh -NoProfile -File scripts\check-versions.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo clippy --locked --workspace --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test --locked --workspace --all-targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npx tauri build --debug --no-bundle
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$driver = Join-Path $env:USERPROFILE 'bin'
if (Test-Path (Join-Path $driver 'msedgedriver.exe')) {
    $env:PATH = "$driver;$env:PATH"
}
$env:WATTWALL_REQUIRE_E2E = '1'
npm run test:e2e
exit $LASTEXITCODE
