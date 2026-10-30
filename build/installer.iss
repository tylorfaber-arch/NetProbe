; NetProbe installer (Inno Setup 6). Built by build\build.ps1 - don't run directly unless the publish folder exists.
#ifndef AppVersion
  #define AppVersion "2.0.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\..\..\..\AppData\Local\NetProbeBuild\publish"
#endif
#ifndef OutDir
  #define OutDir "..\..\release"
#endif

[Setup]
AppId={{6B0E8C2A-4E31-4C3B-9A57-5C1D2F0B7E21}
AppName=NetProbe
AppVersion={#AppVersion}
AppVerName=NetProbe {#AppVersion}
AppPublisher=Tylor Faber
AppPublisherURL=https://github.com/tylorfaber-arch/NetProbe
AppSupportURL=https://github.com/tylorfaber-arch/NetProbe/issues
AppUpdatesURL=https://github.com/tylorfaber-arch/NetProbe/releases
DefaultDirName={autopf}\NetProbe
DefaultGroupName=NetProbe
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
OutputDir={#OutDir}
; fixed name so the README's "latest/download" link never changes
OutputBaseFilename=NetProbe-Setup
SetupIconFile=..\Assets\netprobe.ico
UninstallDisplayIcon={app}\NetProbe.exe
UninstallDisplayName=NetProbe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#PublishDir}\NetProbe.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\NetProbe"; Filename: "{app}\NetProbe.exe"; Comment: "Network tester - switch port, link, IP, connectivity"
Name: "{autodesktop}\NetProbe"; Filename: "{app}\NetProbe.exe"; Tasks: desktopicon

[Run]
; also runs after a silent in-app update so NetProbe comes back up
Filename: "{app}\NetProbe.exe"; Description: "Launch NetProbe"; Flags: nowait postinstall

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\Temp\NetProbe"
