import os
import sys
from pathlib import Path

VERSION = "1.2.0-beta.1"

# Empaquetado con PyInstaller, el código y las reglas viven en una carpeta de
# solo lectura (Program Files). Informes, caché y .env van a la carpeta del
# usuario. Desde el código fuente, ambas son la carpeta del proyecto.
FROZEN = getattr(sys, "frozen", False)
PROJECT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
USER_DIR = (Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Sentinel") if FROZEN else PROJECT_DIR
ENV_FILE = USER_DIR / ".env"
WATCH_DIR = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Downloads"

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".c", ".cpp", ".h", ".java", ".rb", ".php",
    ".sh", ".ps1", ".go", ".rs", ".lua", ".pl",
}

IGNORE_EXTENSIONS = {".crdownload", ".part", ".tmp", ".download"}

STABLE_WINDOW_S = 1.0
POLL_INTERVAL_S = 0.2
GUI_POLL_MS = 200

RULES = [
    ("eval(", "eval() dinámico", "alto"),
    ("os.system", "ejecución de comandos del sistema", "alto"),
    ("base64.b64decode", "decodificación base64", "medio"),
    ("-EncodedCommand", "PowerShell con comando codificado", "alto"),
    ("-enc ", "PowerShell con comando codificado", "alto"),
    ("Invoke-Expression", "PowerShell Invoke-Expression (IEX)", "alto"),
    ("IEX(", "PowerShell IEX abreviado", "alto"),
    ("DownloadString", "descarga de contenido remoto", "alto"),
    ("DownloadFile", "descarga de archivo remoto", "alto"),
    ("New-Object Net.WebClient", "WebClient para descarga", "alto"),
    ("FromBase64String", "decodificación base64 (PowerShell)", "medio"),
    ("eval(atob(", "eval sobre base64 (JS)", "alto"),
    ("child_process", "Node child_process (ejecución)", "alto"),
    ("require('child_process')", "Node child_process (ejecución)", "alto"),
    ('require("child_process")', "Node child_process (ejecución)", "alto"),
    ("curl | bash", "descarga y ejecución por tubería (bash)", "alto"),
    ("curl|bash", "descarga y ejecución por tubería (bash)", "alto"),
    ("wget -O- | sh", "descarga y ejecución por tubería (bash)", "alto"),
    ("/dev/tcp/", "conexión de red vía bash", "alto"),
    ("nc -e", "netcat con shell inversa", "alto"),
    ("bash -i >& /dev/tcp", "shell inversa (bash)", "alto"),
    ("chmod +x", "marcado de ejecutable", "bajo"),
    ("crontab", "persistencia vía cron", "medio"),
    ("/etc/passwd", "acceso a credenciales de sistema", "medio"),
]

SEVERITY_SCORE = {"bajo": 6, "medio": 14, "alto": 30, "crítico": 45}

SCORE_SATURATION = 45

# Una señal de confianza baja es algo que el software legítimo también hace
# (getattr, borrar un archivo, entropía alta). Pesan poco y, juntas, nunca
# superan BAJA_CAP: muchas señales débiles no equivalen a una fuerte.
CONFIDENCE_FACTOR = {"alta": 1.0, "media": 0.6, "baja": 0.2}
BAJA_CAP = 12
VERDICT_ALERT_SCORE = 60
VERDICT_REVIEW_SCORE = 25

AST_RULES = {
    "eval_exec": {
        "titulo": "Uso de eval()/exec()",
        "severidad": "alto",
        "mitre": ("T1059.006", "Command and Scripting Interpreter: Python"),
    },
    "dynamic_import": {
        "titulo": "Importación dinámica",
        "severidad": "medio",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "getattr_dynamic": {
        "titulo": "Acceso dinámico a atributos",
        "severidad": "medio",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "b64_decode": {
        "titulo": "Decodificación base64",
        "severidad": "medio",
        "mitre": ("T1140", "Deobfuscate/Decode Files or Information"),
    },
    "subprocess_shell": {
        "titulo": "Ejecución de shell vía subprocess",
        "severidad": "alto",
        "mitre": ("T1059", "Command and Scripting Interpreter"),
    },
    "os_system": {
        "titulo": "Ejecución de comandos (os.system/popen)",
        "severidad": "alto",
        "mitre": ("T1059", "Command and Scripting Interpreter"),
    },
    "network": {
        "titulo": "Llamada de red saliente",
        "severidad": "alto",
        "mitre": ("T1071", "Application Layer Protocol"),
    },
    "socket": {
        "titulo": "Uso de socket de bajo nivel",
        "severidad": "alto",
        "mitre": ("T1095", "Non-Application Layer Protocol"),
    },
    "file_destroy": {
        "titulo": "Borrado de archivos",
        "severidad": "crítico",
        "mitre": ("T1485", "Data Destruction"),
    },
    "permission_change": {
        "titulo": "Cambio de permisos",
        "severidad": "medio",
        "mitre": ("T1222", "File and Directory Permissions Modification"),
    },
    "persistence_env": {
        "titulo": "Modificación de entorno/registro",
        "severidad": "alto",
        "mitre": ("T1547", "Boot or Logon Autostart Execution"),
    },
    "encoded_string": {
        "titulo": "Cadena larga codificada (posible payload)",
        "severidad": "medio",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "string_format": {
        "titulo": "Formato de cadena dinámico",
        "severidad": "bajo",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "dynamic_attribute": {
        "titulo": "Atributo construido de forma dinámica",
        "severidad": "medio",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "tainted_exec": {
        "titulo": "Ejecuta datos decodificados, descargados o tecleados",
        "severidad": "crítico",
        "mitre": ("T1059.006", "Command and Scripting Interpreter: Python"),
    },
    "reverse_shell": {
        "titulo": "Socket conectado a un intérprete de comandos (shell inversa)",
        "severidad": "crítico",
        "mitre": ("T1059", "Command and Scripting Interpreter"),
    },
    "download_exec": {
        "titulo": "Descarga y ejecución en el mismo script",
        "severidad": "crítico",
        "mitre": ("T1105", "Ingress Tool Transfer"),
    },
    "obfuscated_exec": {
        "titulo": "Decodificación y ejecución dinámica en el mismo script",
        "severidad": "crítico",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "hardcoded_c2": {
        "titulo": "Destino de red fijo: IP literal o puerto típico de backdoor",
        "severidad": "alto",
        "mitre": ("T1071", "Application Layer Protocol"),
    },
    "keylogger_lib": {
        "titulo": "Librería de captura de teclado",
        "severidad": "alto",
        "mitre": ("T1056.001", "Input Capture: Keylogging"),
    },
    "ctypes_injection": {
        "titulo": "Inyección en otro proceso vía ctypes",
        "severidad": "crítico",
        "mitre": ("T1055", "Process Injection"),
    },
}

# Fuentes y sumideros del análisis de flujo de datos en Python. Un sumidero que
# recibe un valor de una fuente es una cadena causal, no una coincidencia.
TAINT_SOURCES = {
    "base64.b64decode": "base64", "base64.b32decode": "base64", "base64.b85decode": "base64",
    "base64.a85decode": "base64", "base64.urlsafe_b64decode": "base64",
    "binascii.unhexlify": "hex", "binascii.a2b_base64": "base64", "bytes.fromhex": "hex",
    "codecs.decode": "codecs", "zlib.decompress": "zlib", "gzip.decompress": "gzip",
    "bz2.decompress": "bz2", "lzma.decompress": "lzma", "marshal.loads": "marshal",
    "urllib.request.urlopen": "red", "urlopen": "red", "requests.get": "red",
    "requests.post": "red", "httpx.get": "red", "input": "teclado",
}
TAINT_SOURCE_METHODS = {"recv": "socket", "recvfrom": "socket"}
TAINT_SINKS = {"eval", "exec", "compile", "os.system", "os.popen", "subprocess.run",
               "subprocess.Popen", "subprocess.call", "subprocess.check_output",
               "subprocess.check_call", "pty.spawn"}
SHELL_BINARIES = ("cmd", "cmd.exe", "/bin/sh", "/bin/bash", "sh", "bash", "powershell",
                  "powershell.exe", "pwsh")
BACKDOOR_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 6697, 9001, 12345, 54321, 5555}
KEYLOGGER_MODULES = {"pynput", "keyboard", "pyHook", "pyxhook", "pynput.keyboard"}
INJECTION_API_NAMES = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                       "NtCreateThreadEx", "QueueUserAPC", "OpenProcess"}

DANGEROUS_CALLS = {
    "eval": "eval_exec",
    "exec": "eval_exec",
    "__import__": "dynamic_import",
    "getattr": "getattr_dynamic",
    "compile": "dynamic_import",
    "system": "os_system",
    "popen": "os_system",
    "remove": "file_destroy",
    "unlink": "file_destroy",
    "rmtree": "file_destroy",
    "chmod": "permission_change",
    "urlopen": "network",
    "urlretrieve": "network",
}

DANGEROUS_MODULE_CALLS = {
    ("subprocess", "run"): "subprocess_shell",
    ("subprocess", "Popen"): "subprocess_shell",
    ("subprocess", "call"): "subprocess_shell",
    ("subprocess", "check_output"): "subprocess_shell",
    ("subprocess", "check_call"): "subprocess_shell",
    ("os", "system"): "os_system",
    ("os", "popen"): "os_system",
    ("socket", "socket"): "socket",
    ("socket", "create_connection"): "socket",
    ("base64", "b64decode"): "b64_decode",
    ("urllib", "urlopen"): "network",
    ("requests", "get"): "network",
    ("requests", "post"): "network",
    ("os", "environ"): "persistence_env",
    ("os", "putenv"): "persistence_env",
    ("os", "remove"): "file_destroy",
    ("os", "unlink"): "file_destroy",
    ("shutil", "rmtree"): "file_destroy",
    ("os", "chmod"): "permission_change",
    ("winreg", "SetValue"): "persistence_env",
    ("winreg", "SetValueEx"): "persistence_env",
}

ENCODED_STR_MIN_LEN = 40
MAX_SNIPPET_LEN = 120

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".bat", ".cmd", ".vbs",
    ".js", ".jse", ".wsf", ".jar", ".zip", ".rar", ".7z", ".gz", ".tar",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".iso", ".img", ".bin", ".apk", ".lnk", ".ps1", ".hta", ".cpl",
}

MAGIC_SIGNATURES = {
    "exe": [(0, b"MZ")],
    "elf": [(0, b"\x7fELF")],
    "pdf": [(0, b"%PDF")],
    "zip": [(0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08")],
    "ole": [(0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")],
    "jpeg": [(0, b"\xff\xd8\xff")],
    "png": [(0, b"\x89PNG\r\n\x1a\n")],
    "gif": [(0, b"GIF87a"), (0, b"GIF89a")],
    "rtf": [(0, b"{\\rtf")],
    "rar": [(0, b"Rar!\x1a\x07")],
    "7z": [(0, b"7z\xbc\xaf\x27\x1c")],
    "bmp": [(0, b"BM")],
    "ico": [(0, b"\x00\x00\x01\x00")],
    "gz": [(0, b"\x1f\x8b")],
    "tar": [(257, b"ustar")],
    "xz": [(0, b"\xfd7zXZ\x00")],
    "cab": [(0, b"MSCF")],
    "webp": [(8, b"WEBP")],
    "mp4": [(4, b"ftyp")],
    "mp3": [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2")],
    "flac": [(0, b"fLaC")],
    "ogg": [(0, b"OggS")],
    "mkv": [(0, b"\x1aE\xdf\xa3")],
    "woff": [(0, b"wOFF"), (0, b"wOF2")],
}

EXTENSION_FAMILY = {
    ".exe": "exe", ".dll": "exe", ".sys": "exe", ".scr": "exe", ".com": "exe",
    ".msi": "ole", ".lnk": "ole",
    ".pdf": "pdf",
    ".zip": "zip", ".jar": "zip", ".docx": "zip", ".xlsx": "zip", ".pptx": "zip",
    ".apk": "zip",
    ".doc": "ole", ".xls": "ole", ".ppt": "ole", ".rtf": "rtf",
    ".jpg": "jpeg", ".jpeg": "jpeg",
    ".png": "png", ".gif": "gif", ".bmp": "bmp", ".ico": "ico", ".webp": "webp",
    ".rar": "rar", ".7z": "7z", ".gz": "gz", ".tar": "tar", ".xz": "xz",
    ".cab": "cab",
    ".mp4": "mp4", ".m4a": "mp4", ".mov": "mp4",
    ".mp3": "mp3", ".flac": "flac", ".ogg": "ogg",
    ".mkv": "mkv",
    ".woff": "woff", ".woff2": "woff",
}

# Formatos comprimidos o codificados por diseño: su entropía alta es normal.
# La exención solo aplica si la firma mágica confirma el formato, así que un
# ejecutable empaquetado con extensión .png sigue disparando extension_mismatch.
ENTROPY_EXEMPT_FAMILIES = {
    "png", "jpeg", "gif", "webp", "bmp", "ico",
    "zip", "rar", "7z", "gz", "tar", "xz", "cab",
    "pdf", "ole",
    "mp3", "flac", "ogg", "mp4", "mkv",
    "woff",
}

BINARY_RULES = {
    "extension_mismatch": {
        "titulo": "Extensión no coincide con el contenido",
        "severidad": "crítico",
        "mitre": ("T1036.008", "Masquerading: Masquerade File Type"),
    },
    "high_entropy": {
        "titulo": "Alta entropía (posible cifrado/empaquetado)",
        "severidad": "alto",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "executable_content": {
        "titulo": "Contenido ejecutable en archivo descargado",
        "severidad": "alto",
        "mitre": ("T1204.002", "User Execution: Malicious File"),
    },
    "embedded_script": {
        "titulo": "Script embebido en binario",
        "severidad": "medio",
        "mitre": ("T1059", "Command and Scripting Interpreter"),
    },
    "double_extension": {
        "titulo": "Doble extensión: ejecutable disfrazado de documento",
        "severidad": "alto",
        "mitre": ("T1036.007", "Masquerading: Double File Extension"),
    },
    "rtl_override": {
        "titulo": "Carácter de sobreescritura de sentido (RLO) en el nombre",
        "severidad": "crítico",
        "mitre": ("T1036.002", "Masquerading: Right-to-Left Override"),
    },
    "archive_executable": {
        "titulo": "Ejecutable o script dentro de un contenedor comprimido",
        "severidad": "alto",
        "mitre": ("T1204.002", "User Execution: Malicious File"),
    },
    "pdf_auto_js": {
        "titulo": "JavaScript con ejecución automática en PDF",
        "severidad": "crítico",
        "mitre": ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    },
    "disguised_pe": {
        "titulo": "Ejecutable disfrazado de imagen o documento (combinación)",
        "severidad": "crítico",
        "mitre": ("T1036.008", "Masquerading: Masquerade File Type"),
    },
    "vba_dropper": {
        "titulo": "Macro que se ejecuta al abrir y lanza o descarga código",
        "severidad": "crítico",
        "mitre": ("T1204.002", "User Execution: Malicious File"),
    },
    "packed_script": {
        "titulo": "Script ofuscado y empaquetado en binario",
        "severidad": "alto",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "pe_suspicious_section": {
        "titulo": "Sección de empaquetador conocido (UPX, Themida, VMProtect…)",
        "severidad": "medio",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "pe_high_entropy_section": {
        "titulo": "Sección PE con alta entropía",
        "severidad": "medio",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "pe_injection": {
        "titulo": "Imports de inyección en otro proceso (reservar, escribir, lanzar hilo)",
        "severidad": "crítico",
        "mitre": ("T1055", "Process Injection"),
    },
    "pe_hollowing": {
        "titulo": "Imports de process hollowing (vaciar y suplantar un proceso)",
        "severidad": "crítico",
        "mitre": ("T1055.012", "Process Injection: Process Hollowing"),
    },
    "pe_keylogger": {
        "titulo": "Lectura global del teclado (GetAsyncKeyState)",
        "severidad": "alto",
        "mitre": ("T1056.001", "Input Capture: Keylogging"),
    },
    "pe_downloader": {
        "titulo": "Descarga a disco y ejecución (URLDownloadToFile + ejecución)",
        "severidad": "alto",
        "mitre": ("T1105", "Ingress Tool Transfer"),
    },
    "pe_dynamic_resolution": {
        "titulo": "Imports mínimos con resolución dinámica de API",
        "severidad": "medio",
        "mitre": ("T1027.007", "Obfuscated Files or Information: Dynamic API Resolution"),
    },
    "pe_no_imports": {
        "titulo": "PE sin tabla de imports (posible packer)",
        "severidad": "medio",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "pe_wx_section": {
        "titulo": "Sección escribible y ejecutable a la vez",
        "severidad": "medio",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "pe_entry_anomaly": {
        "titulo": "Punto de entrada fuera de la sección de código",
        "severidad": "alto",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "pe_entry_stub": {
        "titulo": "Arranque típico de empaquetador o shellcode (desensamblado)",
        "severidad": "medio",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "pe_packed": {
        "titulo": "Ejecutable empaquetado: código cifrado y API ocultas",
        "severidad": "alto",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "pe_bad_signature": {
        "titulo": "Firma digital presente pero inválida o manipulada",
        "severidad": "alto",
        "mitre": ("T1553.002", "Subvert Trust Controls: Code Signing"),
    },
    "capa_malware_family": {
        "titulo": "capa: código de una familia de malware conocida",
        "severidad": "crítico",
        "mitre": ("T1587.001", "Develop Capabilities: Malware"),
    },
    "capa_credential_theft": {
        "titulo": "capa: robo de credenciales (navegador, gestor de contraseñas, tarjetas)",
        "severidad": "crítico",
        "mitre": ("T1555", "Credentials from Password Stores"),
    },
    "capa_keylog": {
        "titulo": "capa: registro de pulsaciones de teclado",
        "severidad": "crítico",
        "mitre": ("T1056.001", "Input Capture: Keylogging"),
    },
    "capa_spy": {
        "titulo": "capa: captura de pantalla, cámara o micrófono",
        "severidad": "alto",
        "mitre": ("T1113", "Screen Capture"),
    },
    "capa_injection": {
        "titulo": "capa: inyección de código en otro proceso",
        "severidad": "crítico",
        "mitre": ("T1055", "Process Injection"),
    },
    "capa_shellcode": {
        "titulo": "capa: carga o ejecución de shellcode",
        "severidad": "alto",
        "mitre": ("T1620", "Reflective Code Loading"),
    },
    "capa_c2": {
        "titulo": "capa: canal de mando y control (C2)",
        "severidad": "crítico",
        "mitre": ("T1071", "Application Layer Protocol"),
    },
    "capa_anti_analysis": {
        "titulo": "capa: evasión de análisis (detección de VM, antivirus o emulador)",
        "severidad": "alto",
        "mitre": ("T1497", "Virtualization/Sandbox Evasion"),
    },
    "capa_packer": {
        "titulo": "capa: empaquetador u ofuscador identificado",
        "severidad": "medio",
        "mitre": ("T1027.002", "Software Packing"),
    },
    "capa_persistence": {
        "titulo": "capa: persistencia en el sistema",
        "severidad": "alto",
        "mitre": ("T1547", "Boot or Logon Autostart Execution"),
    },
    "capa_impact": {
        "titulo": "capa: destrucción de datos o de copias de seguridad",
        "severidad": "crítico",
        "mitre": ("T1490", "Inhibit System Recovery"),
    },
    "capa_privilege": {
        "titulo": "capa: elevación de privilegios o desactivación de defensas",
        "severidad": "alto",
        "mitre": ("T1548.002", "Abuse Elevation Control Mechanism: Bypass UAC"),
    },
    "capa_exploitation": {
        "titulo": "capa: técnicas de explotación",
        "severidad": "alto",
        "mitre": ("T1203", "Exploitation for Client Execution"),
    },
    "capa_bootkit": {
        "titulo": "capa: escritura en el sector de arranque",
        "severidad": "crítico",
        "mitre": ("T1542.003", "Pre-OS Boot: Bootkit"),
    },
    "vba_macro": {
        "titulo": "Macro VBA presente",
        "severidad": "alto",
        "mitre": ("T1204.002", "User Execution: Malicious File"),
    },
    "vba_autoexec": {
        "titulo": "Macro de auto-ejecución (Auto_Open/AutoExec)",
        "severidad": "crítico",
        "mitre": ("T1137.004", "Office Application Startup: Outlook Home Page"),
    },
    "vba_shell": {
        "titulo": "Macro ejecuta comandos (Shell/WScript)",
        "severidad": "crítico",
        "mitre": ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    },
    "vba_download": {
        "titulo": "Macro descarga contenido remoto",
        "severidad": "crítico",
        "mitre": ("T1105", "Ingress Tool Transfer"),
    },
    "vba_obfuscation": {
        "titulo": "Macro ofuscada (Chr/StrReverse/base64)",
        "severidad": "alto",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "pdf_javascript": {
        "titulo": "JavaScript embebido en PDF",
        "severidad": "alto",
        "mitre": ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    },
    "pdf_openaction": {
        "titulo": "Acción automática al abrir PDF (/OpenAction)",
        "severidad": "alto",
        "mitre": ("T1204.002", "User Execution: Malicious File"),
    },
    "pdf_launch": {
        "titulo": "Acción de lanzamiento externo (/Launch)",
        "severidad": "crítico",
        "mitre": ("T1204.002", "User Execution: Malicious File"),
    },
    "pdf_embedded_file": {
        "titulo": "Archivo embebido en PDF (/EmbeddedFile)",
        "severidad": "alto",
        "mitre": ("T1027.009", "Embedded Payloads"),
    },
    "pdf_obfuscation": {
        "titulo": "PDF sospechoso (múltiples streams / filtros)",
        "severidad": "medio",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "yara_match": {
        "titulo": "Coincidencia con regla YARA",
        "severidad": "alto",
        "mitre": ("T1027", "Obfuscated Files or Information"),
    },
    "vt_detection": {
        "titulo": "Detección en VirusTotal",
        "severidad": "crítico",
        "mitre": ("T1204.002", "User Execution: Malicious File"),
    },
}

# Un import aislado no dice nada: VirtualAlloc o GetProcAddress están en casi
# cualquier ejecutable. Lo que delata es la combinación completa de una técnica.
# Los nombres van sin el sufijo A/W; pe_analyzer lo normaliza.
PE_INJECTION_STEPS = (
    {"VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"},
    {"WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"},
    {"CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
     "QueueUserAPC", "NtQueueApcThread"},
)
PE_HOLLOWING_STEPS = (
    {"NtUnmapViewOfSection", "ZwUnmapViewOfSection"},
    {"SetThreadContext", "Wow64SetThreadContext", "NtSetContextThread"},
    {"WriteProcessMemory", "NtWriteVirtualMemory"},
    {"ResumeThread", "NtResumeThread"},
)
PE_KEYLOG_APIS = {"GetAsyncKeyState", "GetKeyboardState"}
PE_HOOK_APIS = {"SetWindowsHookEx"}
PE_NETWORK_APIS = {"InternetOpen", "InternetOpenUrl", "InternetConnect", "WinHttpOpen",
                   "WinHttpConnect", "HttpSendRequest", "WSAStartup", "connect", "send",
                   "URLDownloadToFile"}
PE_DOWNLOAD_APIS = {"URLDownloadToFile", "URLDownloadToCacheFile"}
PE_EXEC_APIS = {"WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcess"}
PE_RESOLVER_APIS = {"GetProcAddress", "LoadLibrary", "LoadLibraryEx", "LdrGetProcedureAddress",
                    "LdrLoadDll"}
PE_FEW_IMPORTS = 15

# Rutas de capa que separan malware de software normal. El resto de
# capacidades (leer el registro, crear un mutex, usar XOR) también aparecen en
# notepad.exe; se muestran como comportamiento observado pero no puntúan.
CAPA_CATEGORIES = [
    ("malware-family/", "capa_malware_family"),
    ("collection/browser", "capa_credential_theft"),
    ("collection/password-manager", "capa_credential_theft"),
    ("collection/credit-card", "capa_credential_theft"),
    ("collection/keylog", "capa_keylog"),
    ("collection/screenshot", "capa_spy"),
    ("collection/webcam", "capa_spy"),
    ("collection/microphone", "capa_spy"),
    ("host-interaction/process/inject", "capa_injection"),
    ("load-code/shellcode", "capa_shellcode"),
    ("communication/c2", "capa_c2"),
    ("anti-analysis/anti-vm", "capa_anti_analysis"),
    ("anti-analysis/anti-av", "capa_anti_analysis"),
    ("anti-analysis/anti-emulation", "capa_anti_analysis"),
    ("anti-analysis/anti-forensic", "capa_anti_analysis"),
    ("anti-analysis/anti-llm", "capa_anti_analysis"),
    ("anti-analysis/packer", "capa_packer"),
    ("persistence", "capa_persistence"),
    ("impact/", "capa_impact"),
    ("host-interaction/uac", "capa_privilege"),
    ("host-interaction/firewall", "capa_privilege"),
    ("exploitation/", "capa_exploitation"),
    ("host-interaction/bootloader", "capa_bootkit"),
    ("targeting/automated-teller-machine", "capa_malware_family"),
]
CAPA_RULES_DIR = PROJECT_DIR / "rules" / "capa"
CAPA_SIGS_DIR = PROJECT_DIR / "rules" / "capa-sigs"
CAPA_MAX_BYTES = 16 * 1024 * 1024
CAPA_TIMEOUT_S = 120
ANALYSIS_CACHE_DIR = USER_DIR / "reports" / "cache"
SIGNATURE_TIMEOUT_S = 25

PE_SUSPICIOUS_SECTIONS = {
    "upx0", "upx1", "upx2", ".upx", ".aspack", ".adata", ".packed",
    ".themida", ".vmp0", "vmp0", "vmp1", ".enigma", ".petite", ".mpress",
}

VBA_AUTOEXEC = {"Auto_Open", "AutoOpen", "AutoExec", "Auto_Close", "AutoClose",
                "Document_Open", "Document_Close", "Workbook_Open", "Workbook_Close"}
VBA_SHELL = {"shell", "wscript.shell", "wscript", "CreateObject", "Win32_Process"}
VBA_DOWNLOAD = {"urlmon", "urldownloadtofile", "xmlhttp", "msxml2", "internetopen"}
VBA_OBFUSCATION = {"chr(", "strreverse", "base64", "frombase64string", "vbechunk"}

PDF_DANGER_KEYS = {
    "javascript": ("pdf_javascript", "/JavaScript"),
    "js": ("pdf_javascript", "/JS"),
    "openaction": ("pdf_openaction", "/OpenAction"),
    "aa": ("pdf_openaction", "/AA"),
    "launch": ("pdf_launch", "/Launch"),
    "embeddedfile": ("pdf_embedded_file", "/EmbeddedFile"),
    "embeddedfiles": ("pdf_embedded_file", "/EmbeddedFiles"),
}

# alta: casi nunca aparece en software legítimo. media: sospechoso, pero con
# usos legítimos conocidos. baja: habitual en software normal; solo cuenta como
# contexto. Las reglas sin entrada son "media".
RULE_CONFIDENCE = {
    "extension_mismatch": "alta",
    "executable_content": "alta",
    "double_extension": "alta",
    "rtl_override": "alta",
    "disguised_pe": "alta",
    "pdf_auto_js": "alta",
    "pdf_launch": "alta",
    "vba_dropper": "alta",
    "vt_detection": "alta",
    "pe_injection": "alta",
    "pe_hollowing": "alta",
    "pe_bad_signature": "alta",
    "capa_malware_family": "alta",
    "capa_credential_theft": "alta",
    "capa_injection": "alta",
    "capa_c2": "alta",
    "capa_impact": "alta",
    "capa_bootkit": "alta",
    "tainted_exec": "alta",
    "obfuscated_exec": "alta",
    "ctypes_injection": "alta",
    "high_entropy": "baja",
    "embedded_script": "baja",
    "pe_high_entropy_section": "baja",
    "pe_no_imports": "baja",
    "vba_macro": "media",
    "pdf_obfuscation": "baja",
    "eval_exec": "media",
    "dynamic_import": "baja",
    "getattr_dynamic": "baja",
    "b64_decode": "baja",
    "subprocess_shell": "baja",
    "os_system": "baja",
    "network": "baja",
    "socket": "baja",
    "file_destroy": "baja",
    "permission_change": "baja",
    "encoded_string": "baja",
    "string_format": "baja",
    "dynamic_attribute": "baja",
    "text_rule": "media",
    "trace_exec_command": "alta",
    "trace_exec_process": "media",
    "trace_network": "media",
    "trace_http_request": "media",
    "trace_file_write": "baja",
    "trace_credential_input": "baja",
    "trace_dynamic_exec": "media",
    "trace_file_delete": "alta",
}

# Hallazgos que una firma digital válida no atenúa: un instalador firmado que
# se llama factura.pdf.exe sigue siendo un engaño.
TRUST_OVERRIDE = {"extension_mismatch", "executable_content", "double_extension",
                  "rtl_override", "disguised_pe", "vt_detection", "capa_malware_family"}

COMPOUND_RULES = [
    (frozenset({"pdf_javascript", "pdf_openaction"}), "pdf_auto_js",
     "JavaScript y acción automática en el mismo PDF: se ejecuta al abrirlo"),
    (frozenset({"extension_mismatch", "executable_content"}), "disguised_pe",
     "Un PE ejecutable oculto tras una extensión de imagen o documento"),
    (frozenset({"high_entropy", "embedded_script"}), "packed_script",
     "Contenido empaquetado (alta entropía) que además contiene marcadores de script"),
    (frozenset({"vba_autoexec", "vba_shell"}), "vba_dropper",
     "La macro se ejecuta sola al abrir el documento y lanza comandos"),
    (frozenset({"vba_autoexec", "vba_download"}), "vba_dropper",
     "La macro se ejecuta sola al abrir el documento y descarga contenido"),
    (frozenset({"pe_suspicious_section", "pe_dynamic_resolution"}), "pe_packed",
     "Sección de empaquetador y tabla de imports reducida a resolver API en tiempo de ejecución"),
    (frozenset({"pe_high_entropy_section", "pe_dynamic_resolution"}), "pe_packed",
     "Código cifrado y tabla de imports reducida a resolver API en tiempo de ejecución"),
    (frozenset({"pe_high_entropy_section", "pe_entry_anomaly"}), "pe_packed",
     "Código cifrado y punto de entrada fuera de la sección de código"),
    (frozenset({"network", "eval_exec"}), "download_exec",
     "El script usa la red y ejecuta código dinámico (en partes distintas del archivo)"),
    (frozenset({"network", "os_system"}), "download_exec",
     "El script usa la red y lanza comandos del sistema (en partes distintas del archivo)"),
    (frozenset({"network", "subprocess_shell"}), "download_exec",
     "El script usa la red y lanza procesos (en partes distintas del archivo)"),
    (frozenset({"socket", "os_system"}), "reverse_shell",
     "Socket de bajo nivel y ejecución de comandos en el mismo script"),
    (frozenset({"socket", "subprocess_shell"}), "reverse_shell",
     "Socket de bajo nivel y creación de procesos en el mismo script"),
    (frozenset({"b64_decode", "eval_exec"}), "obfuscated_exec",
     "Decodifica base64 y ejecuta código dinámico en el mismo script"),
    (frozenset({"encoded_string", "eval_exec"}), "obfuscated_exec",
     "Cadena codificada larga y ejecución dinámica en el mismo script"),
]

ENTROPY_BLOCK_SIZE = 4096
ENTROPY_HIGH = 7.2
ENTROPY_SECTION_HIGH = 7.0
ENTROPY_SCAN_LIMIT = 64 * 1024 * 1024

YARA_RULES_DIR = PROJECT_DIR / "rules"

VT_API_URL = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT_PER_MIN = 4
VT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024
VT_TIMEOUT_S = 30

REPORTS_DIR = USER_DIR / "reports" / "out"

STABLE_MAX_RETRIES = 3

IOC_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "169.254.", "0.",
)

IOC_HASH_MIN_LEN = 32
IOC_MAX_PER_TYPE = 200

TRACER_RULES = {
    "exec_command": {
        "titulo": "Ejecución de comando observada",
        "severidad": "alto",
        "mitre": ("T1059", "Command and Scripting Interpreter"),
    },
    "exec_process": {
        "titulo": "Creación de proceso observada",
        "severidad": "alto",
        "mitre": ("T1059", "Command and Scripting Interpreter"),
    },
    "network": {
        "titulo": "Conexión de red observada",
        "severidad": "alto",
        "mitre": ("T1071", "Application Layer Protocol"),
    },
    "http_request": {
        "titulo": "Petición HTTP observada",
        "severidad": "alto",
        "mitre": ("T1071", "Application Layer Protocol"),
    },
    "file_write": {
        "titulo": "Escritura de archivo observada",
        "severidad": "medio",
        "mitre": ("T1105", "Ingress Tool Transfer"),
    },
    "credential_input": {
        "titulo": "Captura de entrada (posible credencial)",
        "severidad": "crítico",
        "mitre": ("T1056.001", "Input Capture: Keylogging"),
    },
    "dynamic_exec": {
        "titulo": "Ejecución dinámica observada",
        "severidad": "alto",
        "mitre": ("T1059.006", "Command and Scripting Interpreter: Python"),
    },
    "file_delete": {
        "titulo": "Borrado de archivo observado",
        "severidad": "crítico",
        "mitre": ("T1485", "Data Destruction"),
    },
}

TRACER_MAX_EVENTS = 500
TRACER_TIMEOUT_S = 2.0
