; agent-warden.iss — Inno Setup script for the Agent Warden Windows installer.
;
; Produces AgentWarden-Setup-v<ver>.exe: a per-user (no-admin) install that drops
; the binaries under {localappdata}\AgentWarden\bin and adds that to the user PATH.
; Built by packaging\build_release.ps1, which passes /DMyAppVersion=<ver>.
;
; PRIVACY: publisher is pinned to "AIEGIS" — no real name in any installer field.
; Licensed under the Apache License 2.0.

#ifndef MyAppVersion
  #define MyAppVersion "0.2.0"
#endif

#define MyAppName "Agent Warden"
#define MyAppPublisher "AIEGIS"
#define MyAppURL "https://github.com/aiegisafety/agent-warden"

[Setup]
AppId={{A1E61543-0000-4A11-9C0D-AGENTWARDEN01}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={localappdata}\AgentWarden
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Per-user install → no admin prompt.
PrivilegesRequired=lowest
OutputDir=dist
OutputBaseFilename=AgentWarden-Setup-v{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Staged by build_release.ps1 under packaging\dist\AgentWarden\.
Source: "dist\AgentWarden\bin\*.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "dist\AgentWarden\README.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "dist\AgentWarden\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "dist\AgentWarden\NOTICE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "dist\AgentWarden\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "dist\AgentWarden\openclaw-adapter\*"; DestDir: "{app}\openclaw-adapter"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\Verify a ledger (aw-verify)"; Filename: "{app}\bin\aw-verify.exe"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\bin\aw-openclaw-bridge.exe"; Parameters: "-selftest"; Description: "Run a quick self-test"; Flags: postinstall nowait skipifsilent unchecked

; ---------------------------------------------------------------------------
; Add {app}\bin to the user's PATH on install; remove it on uninstall.
; ---------------------------------------------------------------------------
[Code]
const EnvKey = 'Environment';

function BinDir(): string;
begin
  Result := ExpandConstant('{app}\bin');
end;

procedure AddToPath();
var
  Path: string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Path) then
    Path := '';
  // Skip if already present (case-insensitive, delimiter-safe).
  if Pos(';' + Lowercase(BinDir()) + ';', ';' + Lowercase(Path) + ';') > 0 then
    exit;
  if (Path <> '') and (Path[Length(Path)] <> ';') then
    Path := Path + ';';
  Path := Path + BinDir();
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Path);
end;

procedure RemoveFromPath();
var
  Path: string;
  P: Integer;
  Target: string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Path) then
    exit;
  Target := ';' + Lowercase(Path) + ';';
  P := Pos(';' + Lowercase(BinDir()) + ';', Target);
  if P = 0 then
    exit;
  // Rebuild without our entry.
  Delete(Path, P, Length(BinDir()) + 1);
  // Tidy a possible leading/trailing ';'
  while (Length(Path) > 0) and (Path[1] = ';') do Delete(Path, 1, 1);
  while (Length(Path) > 0) and (Path[Length(Path)] = ';') do Delete(Path, Length(Path), 1);
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Path);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    AddToPath();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveFromPath();
end;
