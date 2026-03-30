# Copyright(c) The Maintainers of Nanvix.
# Licensed under the MIT License.

# Thin wrapper that delegates to the nanvix-zutil CLI.
# Requires nanvix-zutil to be installed (pip install nanvix-zutil).

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = 'Stop'

$repoRoot = git rev-parse --show-toplevel
$venvPython = Join-Path $repoRoot ".nanvix\venv\Scripts\python.exe"
$venvActivate = Join-Path $repoRoot ".nanvix\venv\Scripts\Activate.ps1"

if (-not (Get-Command nanvix-zutil -ErrorAction SilentlyContinue)) {
    if (-not (Test-Path $venvPython)) {
        Write-Host "nanvix-zutil not found — bootstrapping from nanvix/zutils latest release..." -ForegroundColor Yellow
        $release = Invoke-RestMethod "https://api.github.com/repos/nanvix/zutils/releases/latest"
        $wheelUrl = ($release.assets | Where-Object { $_.name -like "*.whl" } | Select-Object -First 1).browser_download_url
        python3 -m venv (Join-Path $repoRoot ".nanvix\venv")
        & $venvPython -m pip install --quiet $wheelUrl
    }
    if (Test-Path $venvActivate) { & $venvActivate }
}

& nanvix-zutil @RemainingArgs
exit $LASTEXITCODE
