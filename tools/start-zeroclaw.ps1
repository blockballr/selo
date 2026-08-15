# Start the ZeroClaw selo agent with secrets sourced from .env.
#
# Secrets never appear on the command line. This script loads every
# ZEROCLAW_* variable from the repo's .env into the process environment and
# then starts ZeroClaw, which resolves those secrets through its
# env-override mechanism. The config at ~/.zeroclaw/config.toml contains no
# secret literals, so nothing here needs to know a token value.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools/start-zeroclaw.ps1 [start|daemon]
#
#   start   - zeroclaw channel start   (interactive, Ctrl+C to stop)
#   daemon  - zeroclaw daemon          (background autonomous run)
#   status  - print env resolution + security posture, do not launch

param([string]$Mode = "start")

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot ".env"
$ZeroClaw = Get-Command zeroclaw -ErrorAction SilentlyContinue

if (-not $ZeroClaw) {
    Write-Host "zeroclaw not found on PATH. Install it first." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $EnvFile)) {
    Write-Host "No .env found at $EnvFile" -ForegroundColor Red
    exit 1
}

# Load every KEY=VALUE line into the process environment. Only ZEROCLAW_*
# variables are meaningful to the runtime, but loading all of them keeps the
# shell that launches this script from needing its own exports.
$loaded = 0
foreach ($line in (Get-Content $EnvFile)) {
    $trimmed = $line.Trim()
    if ($trimmed -eq "" -or $trimmed.StartsWith("#")) { continue }
    if ($trimmed -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        $key = $Matches[1]
        $val = $Matches[2]
        [Environment]::SetEnvironmentVariable($key, $val)
        $loaded++
    }
}
Write-Host "Loaded $loaded variables from $EnvFile"

switch ($Mode.ToLower()) {
    "status" {
        & $ZeroClaw.Source config list --filter channels.telegram 2>&1 | Select-String "bot_token"
        & $ZeroClaw.Source config list --filter providers.models.opencode 2>&1 | Select-String "api_key|model"
        & $ZeroClaw.Source security status --agent selo 2>&1
    }
    "daemon" {
        & $ZeroClaw.Source daemon
    }
    default {
        & $ZeroClaw.Source channel start
    }
}
