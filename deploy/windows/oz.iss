; Inno Setup script for OZ (Windows)
; Build from repo root: iscc /DMyAppVersion=0.1.55 /DSourceExe=target\release\oz.exe deploy\windows\oz.iss

#ifndef MyAppVersion
#define MyAppVersion "0.1.55"
#endif

#ifndef SourceExe
#define SourceExe "..\..\target\release\oz.exe"
#endif

#define MyAppName "OZ"
#define MyAppPublisher "OZ"
#define MyAppExeName "oz.exe"

[Setup]
AppId={{E3F5D8D9-7F4B-4D7A-9D9E-0B8A5D1C2F10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Allow install without admin when possible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\..\dist\installer
OutputBaseFilename=oz-setup-v{#MyAppVersion}-windows-x86_64
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\config.example.toml"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\gui-settings.example.toml"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\sql\*"; DestDir: "{app}\sql"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\deploy\windows\README.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\..\docs\TZ_CLOSED_CONTOUR_PROXY_CENTOS_TO_DEBIAN.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
