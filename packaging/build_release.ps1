# build_release.ps1 — produce Agent Warden Windows release artifacts.
#
# Outputs (under packaging\dist\):
#   AgentWarden\                         staged payload (bin\ + docs + install.ps1)
#   AgentWarden-v<ver>-windows-x64.zip   portable zip (extract + run install.ps1)
#   AgentWarden-Setup-v<ver>.exe         Inno Setup installer (only if ISCC is found)
#
# Run on the founder's Windows machine (Go required). No real name appears in any
# artifact — publisher is pinned to "AIEGIS".
#
#   powershell -ExecutionPolicy Bypass -File packaging\build_release.ps1
#   ...or double-click packaging\BUILD_RELEASE.bat
#
# Licensed under the Apache License 2.0.
[CmdletBinding()]
param(
  [string]$Version = "",                # default: read from aw-openclaw-bridge -version
  [switch]$SkipInstaller                # skip Inno Setup even if ISCC is present
)
$ErrorActionPreference = "Stop"

# --- locate repo --------------------------------------------------------------
$PackDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo      = Split-Path -Parent $PackDir
$Reference = Join-Path $Repo "reference"
$Dist      = Join-Path $PackDir "dist"
$Stage     = Join-Path $Dist "AgentWarden"
$BinOut    = Join-Path $Stage "bin"

function Say($m)  { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Die($m)  { Write-Host "`n[FAIL] $m" -ForegroundColor Red; exit 1 }

if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Die "go not found. Install Go (https://go.dev/dl/)." }

# --- clean stage --------------------------------------------------------------
Say "Staging into $Stage"
if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
New-Item -ItemType Directory -Force -Path $BinOut | Out-Null

# --- build every command in reference\cmd ------------------------------------
Say "Building binaries"
Push-Location $Reference
try {
  $cmds = Get-ChildItem -Directory (Join-Path $Reference "cmd")
  foreach ($c in $cmds) {
    $exe = Join-Path $BinOut ($c.Name + ".exe")
    & go build -o $exe ("./cmd/" + $c.Name)
    if ($LASTEXITCODE -ne 0) { Die "go build failed for cmd/$($c.Name)" }
    Ok $c.Name
  }
} finally { Pop-Location }

# --- smoke test the bridge ----------------------------------------------------
Say "Smoke-testing the OpenClaw bridge"
$bridge = Join-Path $BinOut "aw-openclaw-bridge.exe"
if (Test-Path $bridge) {
  & $bridge -selftest
  if ($LASTEXITCODE -ne 0) { Die "aw-openclaw-bridge -selftest FAILED — not shipping a broken binary." }
  Ok "bridge self-test PASS"
  if (-not $Version) { $Version = (& $bridge -version).Split(" ")[-1] }
}
if (-not $Version) { $Version = "0.2.0" }
Ok "version = $Version"

# --- stage docs + installer payload ------------------------------------------
Say "Staging docs"
foreach ($f in @("README.md","LICENSE","NOTICE","CHANGELOG.md")) {
  $src = Join-Path $Repo $f
  if (Test-Path $src) { Copy-Item $src (Join-Path $Stage $f) }
}
# Tier-1 adapter (so users can `plugins install --link` it after install).
Copy-Item -Recurse (Join-Path $Repo "adapters\openclaw") (Join-Path $Stage "openclaw-adapter")
Copy-Item (Join-Path $PackDir "install.ps1")   (Join-Path $Stage "install.ps1")
Copy-Item (Join-Path $PackDir "uninstall.ps1") (Join-Path $Stage "uninstall.ps1")
Ok "docs + install.ps1 + openclaw-adapter staged"

# --- portable zip -------------------------------------------------------------
Say "Creating portable zip"
$zip = Join-Path $Dist "AgentWarden-v$Version-windows-x64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $Stage -DestinationPath $zip
Ok "zip: $zip"

# --- Inno Setup installer (optional) -----------------------------------------
if (-not $SkipInstaller) {
  $iscc = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
  if (-not $iscc) {
    foreach ($p in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe","$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
      if (Test-Path $p) { $iscc = $p; break }
    }
  }
  if ($iscc) {
    Say "Building Inno Setup installer"
    $iss = Join-Path $PackDir "agent-warden.iss"
    & $iscc "/DMyAppVersion=$Version" "/O$Dist" $iss
    if ($LASTEXITCODE -ne 0) { Die "ISCC failed" }
    Ok "installer: $Dist\AgentWarden-Setup-v$Version.exe"
  } else {
    Write-Host "  [skip] Inno Setup (ISCC.exe) not found — portable zip only." -ForegroundColor Yellow
    Write-Host "         Install it from https://jrsoftware.org/isdl.php to also build the .exe installer." -ForegroundColor Yellow
  }
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " RELEASE BUILT — v$Version" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Artifacts in: $Dist"
Write-Host ""
