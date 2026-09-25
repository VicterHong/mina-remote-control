# =============================================================================
# Install Mina Local Daemon as a Windows service via NSSM
# =============================================================================
# Prerequisites: Install NSSM (https://nssm.cc/download)
#
# Profiles:
#   low-spec (default) — tuned for weak laptops (Bay Trail-class low-spec):
#       Below-normal process priority + CPU affinity mask (last core only)
#       + restart throttling. (Windows has no per-service memory cap in
#       NSSM; the daemon idles at ~25-35 MB RSS, so priority + affinity
#       are the effective protections.)
#   normal             — default priority, all cores (MINA_PROFILE=normal)
#
# Usage (elevated PowerShell):
#   $env:MINA_API_KEY="..."; $env:MINA_HMAC_SECRET="..."
#   powershell -ExecutionPolicy Bypass -File install_service.ps1
#   powershell -ExecutionPolicy Bypass -File install_service.ps1 -Profile normal
# =============================================================================

param(
    [string]$ApiKey = $env:MINA_API_KEY,
    [string]$HmacSecret = $env:MINA_HMAC_SECRET,
    [int]$Port = 8765,
    [ValidateSet("low-spec", "normal")]
    [string]$Profile = $(if ($env:MINA_PROFILE) { $env:MINA_PROFILE } else { "low-spec" }),
    [int]$CpuAffinityCore = -1   # -1 = auto (last core)
)

$ErrorActionPreference = "Stop"

if (-not $ApiKey -or -not $HmacSecret) {
    Write-Host "ERROR: Set MINA_API_KEY and MINA_HMAC_SECRET env vars first" -ForegroundColor Red
    exit 1
}

$DaemonDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = (Get-Command python).Source
$DaemonPath = Join-Path $DaemonDir "mina_daemon.py"
$LogDir = Join-Path $env:USERPROFILE ".mina\logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Check NSSM
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssm) {
    Write-Host "ERROR: NSSM not found. Install from https://nssm.cc/download" -ForegroundColor Red
    exit 1
}

# Remove existing service (idempotent re-install)
$existing = Get-Service -Name "mina-daemon" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Existing mina-daemon service found — removing before reinstall..."
    nssm stop mina-daemon 2>$null | Out-Null
    nssm remove mina-daemon confirm | Out-Null
    Start-Sleep -Seconds 2
}

# ── Install service ──────────────────────────────────────────────
nssm install mina-daemon $PythonExe "$DaemonPath --host 127.0.0.1 --port $Port"
nssm set mina-daemon AppDirectory $DaemonDir
nssm set mina-daemon AppEnvironmentExtra "MINA_API_KEY=$ApiKey" "MINA_HMAC_SECRET=$HmacSecret"
nssm set mina-daemon AppStdout (Join-Path $LogDir "mina_stdout.log")
nssm set mina-daemon AppStderr (Join-Path $LogDir "mina_stderr.log")
nssm set mina-daemon AppStdoutCreationDisposition 4
nssm set mina-daemon AppStderrCreationDisposition 4
nssm set mina-daemon AppRestartDelay 5000
nssm set mina-daemon Start SERVICE_AUTO_START

if ($Profile -eq "low-spec") {
    # ── Resource limits (low-spec profile — low-spec class hardware) ──
    nssm set mina-daemon AppPriority BELOW_NORMAL_PRIORITY_CLASS
    nssm set mina-daemon AppNoConsole 1

    # Pin the daemon to a single (last) logical core so it never competes
    # with the foreground workload on this 2-core Bay Trail SoC.
    $coreCount = [Environment]::ProcessorCount
    if ($CpuAffinityCore -lt 0) { $CpuAffinityCore = $coreCount - 1 }
    $mask = [math]::Pow(2, $CpuAffinityCore)
    nssm set mina-daemon AppAffinity $mask
    Write-Host "✓ Profile: low-spec (priority=BelowNormal, affinity=core $CpuAffinityCore of $coreCount)" -ForegroundColor Yellow
} else {
    Write-Host "✓ Profile: normal (default priority, all cores)"
}

# AppExit: restart on any exit (bounded by AppRestartDelay)
nssm set mina-daemon AppExit Default Restart | Out-Null

nssm start mina-daemon
Start-Sleep -Seconds 2

$svc = Get-Service -Name "mina-daemon" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "✓ Mina daemon installed and started" -ForegroundColor Green
    Write-Host "  Status: Get-Service mina-daemon"
    Write-Host "  Logs:   $LogDir\"
    Write-Host "  Verify limits: nssm get mina-daemon AppPriority; nssm get mina-daemon AppAffinity"
} else {
    Write-Host "✗ Service failed to start — check $LogDir\mina_stderr.log" -ForegroundColor Red
    exit 1
}
