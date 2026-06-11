# Packaging — Agent Warden (Windows)

Build a download-and-run release. Two artifacts, one command.

## Build (founder-local, Windows; Go required)

```
:: double-click, or:
powershell -ExecutionPolicy Bypass -File packaging\build_release.ps1
```

This builds every binary in `reference\cmd\`, self-tests the OpenClaw bridge, and
produces under `packaging\dist\`:

| Artifact | What it is | Who it's for |
|---|---|---|
| `AgentWarden-v<ver>-windows-x64.zip` | portable payload + `install.ps1` | anyone; no installer needed |
| `AgentWarden-Setup-v<ver>.exe` | Inno Setup installer | non-technical users (only built if Inno Setup is installed) |

The `.exe` installer is produced **only if** Inno Setup's `ISCC.exe` is found
(install it from <https://jrsoftware.org/isdl.php>). Without it you still get the
portable zip. Pass `-SkipInstaller` to force zip-only.

## Install (end user)

**Portable zip:** extract, then
```
powershell -ExecutionPolicy Bypass -File install.ps1
```
Installs per-user to `%LOCALAPPDATA%\AgentWarden\bin` and adds it to PATH. No admin.

**Installer:** double-click `AgentWarden-Setup-v<ver>.exe`. Per-user, no admin
prompt. Uninstall via Settings ▸ Apps or the Start-menu shortcut.

Both expose on PATH: `awarden`, `aw-verify`, `aw-openclaw-bridge`,
`aw-confined-run`, and the demo/agent binaries. Open a **new** terminal after
install for PATH to take effect.

## Privacy

Every artifact pins the publisher to **AIEGIS** — no real name appears in the zip,
the installer metadata, or the PATH entries (see `[[feedback_no_real_name]]`).

## Notes

- Binaries are **not** committed; `packaging\dist\` is git-ignored. Releases are
  built on demand and (optionally) attached to a GitHub Release.
- Tier-2 confinement (`aw-confined-run`) needs an **elevated** shell to apply the
  firewall egress lockdown; the rest run unprivileged.
