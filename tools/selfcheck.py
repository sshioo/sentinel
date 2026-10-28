"""Comprueba que el entorno puede ejecutar Sentinel y qué capas están activas.

Uso:
    python tools/selfcheck.py

Devuelve código 0 si todo lo imprescindible está listo, 1 si falta algo crítico.
No instala nada ni modifica el sistema.
"""

import importlib
import sys
import tkinter
import tkinter.font
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OK = "[ok]"
FAIL = "[--]"
WARN = "[!!]"

results = []


def check(name, fn, critical=True):
    try:
        detail = fn()
        results.append((OK, name, detail or "", critical))
    except Exception as exc:  # noqa: BLE001 - el chequeo debe sobrevivir a cualquier fallo
        marker = FAIL if critical else WARN
        results.append((marker, name, str(exc)[:120], critical))


def python_version():
    v = sys.version_info
    if v < (3, 10):
        raise RuntimeError(f"se requiere Python >= 3.10, hay {v.major}.{v.minor}")
    return f"{v.major}.{v.minor}.{v.micro}"


def dependencies():
    mods = ["watchdog", "customtkinter", "PIL", "yara", "pefile", "pypdf",
            "oletools", "capstone", "requests", "dotenv"]
    missing = []
    for m in mods:
        try:
            importlib.import_module(m)
        except ImportError:
            missing.append(m)
    if missing:
        raise RuntimeError("faltan: " + ", ".join(missing))
    return f"{len(mods)} paquetes"


def yara_rules():
    from core import yara_scanner
    from config import YARA_RULES_DIR
    yara_scanner._compile()
    if yara_scanner._LOAD_ERROR:
        raise RuntimeError(yara_scanner._LOAD_ERROR)
    total = 0
    for f in YARA_RULES_DIR.rglob("*.yar"):
        total += sum(1 for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines()
                     if ln.strip().startswith("rule "))
    if not total:
        raise RuntimeError("no se declaró ninguna regla")
    return f"{total} regla(s) en {YARA_RULES_DIR.name}/"


def capa_engine():
    from config import CAPA_RULES_DIR, CAPA_SIGS_DIR
    importlib.import_module("capa")
    rules = sum(1 for _ in CAPA_RULES_DIR.rglob("*.yml")) if CAPA_RULES_DIR.is_dir() else 0
    sigs = len(list(CAPA_SIGS_DIR.glob("*.sig"))) if CAPA_SIGS_DIR.is_dir() else 0
    if not rules or sigs < 3:
        raise RuntimeError("faltan reglas o firmas: ejecuta python tools/setup_rules.py")
    return f"{rules} reglas · {sigs} firmas FLIRT"


def signatures():
    from core import signature
    sig = signature.check(r"C:\Windows\System32\notepad.exe")
    if sig.get("status") != "Valid":
        raise RuntimeError(f"no se pudo verificar notepad.exe ({sig.get('error') or sig.get('status')})")
    return f"Authenticode operativo ({sig.get('signer')})"


def fonts():
    root = tkinter.Tk()
    root.withdraw()
    try:
        fams = set(tkinter.font.families(root))
    finally:
        root.destroy()
    have_ui = "Inter" in fams
    have_mono = "JetBrains Mono" in fams
    if not (have_ui and have_mono):
        raise RuntimeError("fallback activo (Inter/JetBrains Mono no instaladas)")
    return "Inter + JetBrains Mono"


def vt_key():
    from engines import virustotal
    if not virustotal.has_api_key():
        raise RuntimeError("VT_API_KEY vacía: capa online desactivada")
    return "clave presente"


def ai_analyst():
    from engines import ai_analyst as ai
    state = ai.status()
    if not state["configured"]:
        raise RuntimeError("sin proveedor: capa de explicación desactivada")
    return f"{state['provider']} · {state['model']}"


def watch_dir():
    from config import WATCH_DIR
    if not WATCH_DIR.is_dir():
        raise RuntimeError(f"no existe {WATCH_DIR}")
    return str(WATCH_DIR)


def reports_dir():
    from config import REPORTS_DIR
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    probe = REPORTS_DIR / ".write_test"
    probe.write_text("x", encoding="utf-8")
    probe.unlink()
    return str(REPORTS_DIR)


check("Python", python_version)
check("Dependencias", dependencies)
check("Reglas YARA", yara_rules)
check("Ingeniería inversa (capa)", capa_engine, critical=False)
check("Firmas digitales", signatures, critical=False)
check("Fuentes", fonts, critical=False)
check("VirusTotal (opcional)", vt_key, critical=False)
check("Analista IA (opcional)", ai_analyst, critical=False)
check("Carpeta vigilada", watch_dir)
check("Carpeta de informes", reports_dir)

from config import VERSION  # noqa: E402

print(f"\nSentinel {VERSION} · chequeo de entorno\n" + "-" * 66)
for marker, name, detail, _critical in results:
    print(f"{marker}  {name:<27} {detail}")
print("-" * 66)

hard_fail = any(m == FAIL and c for m, _n, _d, c in results)
if hard_fail:
    print("Resultado: faltan piezas críticas. Revisa README.md (Instalación).")
    sys.exit(1)

warn = any(m == WARN for m, _n, _d, _c in results)
print("Resultado: listo para ejecutar." + (" Avisos menores arriba." if warn else ""))
