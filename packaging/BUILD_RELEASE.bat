@echo off
REM Double-click to build Agent Warden Windows release artifacts (zip + installer).
REM Requires Go. Inno Setup is optional (adds the .exe installer).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_release.ps1" %*
echo.
pause
