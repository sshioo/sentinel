; Instalador de Sentinel (Inno Setup 6). Se compila desde packaging/build.py.
; Instalación por usuario: no pide permisos de administrador.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F3C2B1A-5E4D-4C8B-9A7F-2D1E0C9B8A76}
AppName=Sentinel
AppVersion={#AppVersion}
AppVerName=Sentinel {#AppVersion}
AppPublisher=Sentinel
DefaultDirName={localappdata}\Programs\Sentinel
DefaultGroupName=Sentinel
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=Sentinel-Setup-{#AppVersion}
SetupIconFile=..\assets\sentinel.ico
UninstallDisplayIcon={app}\Sentinel.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; GroupDescription: "Accesos directos:"

[Files]
Source: "..\dist\Sentinel\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
; Plantilla de claves opcionales. No se sobrescribe ni se borra al desinstalar.
Source: "..\.env.example"; DestDir: "{localappdata}\Sentinel"; DestName: ".env"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{group}\Sentinel"; Filename: "{app}\Sentinel.exe"
Name: "{group}\Sentinel (demo)"; Filename: "{app}\Sentinel.exe"; Parameters: "--demo"; Comment: "Analiza seis muestras inocuas"
Name: "{group}\Desinstalar Sentinel"; Filename: "{uninstallexe}"
Name: "{userdesktop}\Sentinel"; Filename: "{app}\Sentinel.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Sentinel.exe"; Description: "Abrir Sentinel en modo demo"; Parameters: "--demo"; Flags: nowait postinstall skipifsilent
