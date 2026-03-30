# Copyright(c) The Maintainers of Nanvix.
# Licensed under the MIT License.

# Thin wrapper that delegates to the nanvix-zutil CLI.
# Requires nanvix-zutil to be installed (pip install nanvix-zutil).

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = 'Stop'

# If nanvix-zutil is already on PATH (e.g. CI), use it directly.
if (Get-Command nanvix-zutil -ErrorAction SilentlyContinue) {
    & nanvix-zutil @Args
    exit $LASTEXITCODE
}

$repoRoot = git rev-parse --show-toplevel
$venvDir = Join-Path $repoRoot ".nanvix\venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$venvZutil = Join-Path $venvDir "Scripts\nanvix-zutil.exe"

if (-not (Test-Path $venvZutil) -and -not (Get-Command nanvix-zutil -ErrorAction SilentlyContinue)) {
    Write-Host "nanvix-zutil not found — bootstrapping from nanvix/zutils latest release..." -ForegroundColor Yellow
    $release = Invoke-RestMethod "https://api.github.com/repos/nanvix/zutils/releases/latest"
    $wheelUrl = ($release.assets | Where-Object { $_.name -like "*.whl" } | Select-Object -First 1).browser_download_url
    if (-not $wheelUrl) {
        throw "No .whl asset found in latest nanvix/zutils release. Install manually: pip install nanvix-zutil"
    }
    # Discover a Python 3 interpreter
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv $venvDir
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python -m venv $venvDir
    } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        & python3 -m venv $venvDir
    } else {
        throw "Python 3 not found. Install Python 3 and ensure py, python, or python3 is on PATH."
    }
    & $venvPython -m pip install --quiet $wheelUrl
}

# Prefer the venv copy; fall back to global.
if (Test-Path $venvZutil) {
    & $venvZutil @Args
} elseif (Get-Command nanvix-zutil -ErrorAction SilentlyContinue) {
    & nanvix-zutil @Args
} else {
    throw "nanvix-zutil not found in venv ($venvDir) or on PATH."
}
exit $LASTEXITCODE
