# ==============================================================================
# start_demo.ps1 — Sentinel Edge AIOps Platform Automated Demo Launcher
# Windows PowerShell Orchestrator
# ==============================================================================

[CmdletBinding()]
param (
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$PlatformRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $PlatformRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "       Sentinel Edge // AIOps Observability Platform Demo Launcher    " -ForegroundColor Green
Write-Host "       Two-tier, Local-First, Multi-Tenant Privacy-Preserving AIOps  " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify virtualenv exists
if (-not (Test-Path "$PlatformRoot\.venv\Scripts\Activate.ps1")) {
    Write-Warning "Virtual environment not detected at .venv\. Creating and installing dependencies..."
    python -m venv "$PlatformRoot\.venv"
    & "$PlatformRoot\.venv\Scripts\python.exe" -m pip install -e ".[dev]"
}

# 2. Verify or generate tenant viewer tokens in .env
if (-not (Test-Path "$PlatformRoot\.env")) {
    Write-Host "[*] Generating random tenant viewer tokens via tools/gen_tokens.py..." -ForegroundColor Cyan
    & "$PlatformRoot\.venv\Scripts\python.exe" "$PlatformRoot\tools\gen_tokens.py"
}

$pyExe = if (Test-Path "$PlatformRoot\.venv\Scripts\python.exe") { "$PlatformRoot\.venv\Scripts\python.exe" } else { "python" }

# Helper to spawn a dedicated PowerShell window for a long-running service
function Spawn-ServiceWindow {
    param (
        [string]$Title,
        [string]$Subcommand
    )
    Write-Host "  [+] Launching $Title..." -ForegroundColor Green
    $initScript = @"
`$host.UI.RawUI.WindowTitle = '$Title'
Set-Location '$PlatformRoot'
`$env:PYTHONIOENCODING = 'utf-8'

# Load .env file variables if present
if (Test-Path '.env') {
    Get-Content '.env' | ForEach-Object {
        `$line = `$_.Trim()
        if (`$line -and -not `$line.StartsWith('#') -and `$line.Contains('=')) {
            `$parts = `$line.Split('=', 2)
            `$k = `$parts[0].Trim()
            `$v = `$parts[1].Trim()
            if (`$k) { Set-Item -Path "env:`$k" -Value `$v }
        }
    }
}

# Activate virtualenv
if (Test-Path '.venv\Scripts\Activate.ps1') {
    . .\.venv\Scripts\Activate.ps1
}

Write-Host '======================================================================' -ForegroundColor Cyan
Write-Host '  RUNNING: $Title' -ForegroundColor Green
Write-Host '  (Keep this window open during demonstration)' -ForegroundColor Yellow
Write-Host '======================================================================' -ForegroundColor Cyan
Write-Host ''

$Subcommand
"@
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $initScript
}

# ── 1. Telemetry Simulator Server (Port 9000) ─────────────────────────────────
Spawn-ServiceWindow -Title "1. Telemetry Simulator (:9000)" `
    -Subcommand "& '$pyExe' -m uvicorn tools.sim_stream_server:app --host 0.0.0.0 --port 9000 --reload"

Start-Sleep -Seconds 2

# ── 2. Central SaaS — EU Regional Instance (Port 8000 / Tenant Acme) ─────────
Spawn-ServiceWindow -Title "2. SaaS EU Instance (:8000 - Tenant: acme)" `
    -Subcommand "`$env:REGION = 'eu'; `$env:SAAS_DB_PATH = 'saas_eu.db'; & '$pyExe' -m uvicorn saas.main:app --host 0.0.0.0 --port 8000 --no-access-log --reload"

Start-Sleep -Seconds 2

# ── 3. Central SaaS — IN Regional Instance (Port 8002 / Tenant Globex) ─────────
Spawn-ServiceWindow -Title "3. SaaS IN Instance (:8002 - Tenant: globex)" `
    -Subcommand "`$env:REGION = 'in'; `$env:SAAS_DB_PATH = 'saas_in.db'; & '$pyExe' -m uvicorn saas.main:app --host 0.0.0.0 --port 8002 --no-access-log --reload"

Start-Sleep -Seconds 2

# ── 4. Edge Collector Daemon (col-acme-eu-1) ──────────────────────────────────
Spawn-ServiceWindow -Title "4. Collector Edge (col-acme-eu-1)" `
    -Subcommand "`$env:COLLECTOR_ID = 'col-acme-eu-1'; `$env:COLLECTOR_DB_PATH = 'collector_local.db'; & '$pyExe' tools/live_feed_daemon.py"

Start-Sleep -Seconds 2

# ── 5. Open Dashboard in Default Browser ──────────────────────────────────────
$dashboardUrl = "http://localhost:8000/dashboard/"
Write-Host ""
Write-Host "[*] Services successfully launched." -ForegroundColor Green
Write-Host "[*] Dashboard URL: $dashboardUrl" -ForegroundColor Cyan

if (-not $NoBrowser) {
    Write-Host "[*] Opening browser..." -ForegroundColor Green
    Start-Process $dashboardUrl
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  All services are running in dedicated background windows!          " -ForegroundColor Green
Write-Host "  Refer to RUN_DEMO.md for step-by-step audit & evaluation commands. " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan
