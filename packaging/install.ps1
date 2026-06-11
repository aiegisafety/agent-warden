# install.ps1 — install Agent Warden for the current user (no admin required).
#
# Copies the bin\ payload to %LOCALAPPDATA%\AgentWarden and adds it to your user
# PATH (idempotent). Run from the extracted zip folder:
#
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Per-user install → no administrator rights needed. Re-running upgrades in place.
# Licensed under the Apache License 2.0.
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:LOCALAPPDATA "AgentWarden"))
$ErrorActionPreference = "Stop"

$Here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcBin = Join-Path $Here "bin"
$DstBin = Join-Path $InstallDir "bin"

function Ok($m) { Write-Host "  [OK] $m" -ForegroundColor Green }

if (-not (Test-Path $SrcBin)) {
  Write-Host "[FAIL] bin\ not found next to install.ps1 — run this from the extracted release folder." -ForegroundColor Red
  exit 1
}

Write-Host "`n==> Installing Agent Warden to $InstallDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $DstBin | Out-Null
Copy-Item -Force (Join-Path $SrcBin "*.exe") $DstBin
# Bundle the OpenClaw adapter + docs alongside, if present.
foreach ($extra in @("openclaw-adapter","README.md","LICENSE","NOTICE","CHANGELOG.md","uninstall.ps1")) {
  $s = Join-Path $Here $extra
  if (Test-Path $s) { Copy-Item -Recurse -Force $s (Join-Path $InstallDir (Split-Path $extra -Leaf)) }
}
Ok "binaries copied to $DstBin"

# --- add to user PATH (idempotent) -------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($null -eq $userPath) { $userPath = "" }
$parts = $userPath.Split(";") | Where-Object { $_ -ne "" }
if ($parts -notcontains $DstBin) {
  $newPath = (($parts + $DstBin) -join ";")
  [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
  Ok "added $DstBin to your user PATH"
  Write-Host "      (open a NEW terminal for PATH to take effect)" -ForegroundColor Yellow
} else {
  Ok "PATH already contains $DstBin"
}

# --- smoke test ---------------------------------------------------------------
$bridge = Join-Path $DstBin "aw-openclaw-bridge.exe"
if (Test-Path $bridge) {
  Write-Host "`n==> Verifying install" -ForegroundColor Cyan
  & $bridge -selftest
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " AGENT WARDEN INSTALLED" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Open a NEW terminal, then try:"
Write-Host "    awarden -h"
Write-Host "    aw-openclaw-bridge -version"
Write-Host "    aw-confined-run -h        (Tier-2 OS confinement demo; run as admin)"
Write-Host "  Uninstall:  powershell -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
Write-Host ""
