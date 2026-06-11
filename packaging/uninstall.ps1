# uninstall.ps1 — remove the per-user Agent Warden install and its PATH entry.
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1
# Licensed under the Apache License 2.0.
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:LOCALAPPDATA "AgentWarden"))
$ErrorActionPreference = "Stop"

$DstBin = Join-Path $InstallDir "bin"
Write-Host "`n==> Uninstalling Agent Warden from $InstallDir" -ForegroundColor Cyan

# Remove from user PATH.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath) {
  $parts = $userPath.Split(";") | Where-Object { $_ -ne "" -and $_ -ne $DstBin }
  [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
  Write-Host "  [OK] removed $DstBin from user PATH" -ForegroundColor Green
}

# Remove files.
if (Test-Path $InstallDir) {
  Remove-Item -Recurse -Force $InstallDir
  Write-Host "  [OK] removed $InstallDir" -ForegroundColor Green
} else {
  Write-Host "  [i] $InstallDir not found (already removed)" -ForegroundColor Yellow
}
Write-Host "`nAgent Warden uninstalled. Open a new terminal to refresh PATH.`n"
