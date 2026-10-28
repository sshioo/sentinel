"""Construye Sentinel.exe y, si Inno Setup está instalado, el instalador.

Uso:
    python packaging/build.py

Resultado:
    dist/Sentinel/Sentinel.exe                 aplicación (carpeta)
    dist/Sentinel-Setup-<versión>.exe          instalador para compartir
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import CAPA_RULES_DIR, CAPA_SIGS_DIR, VERSION  # noqa: E402

ISCC = [Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
        Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
        Path.home() / "AppData/Local/Programs/Inno Setup 6/ISCC.exe"]


def _numeric_version():
    nums = [int(n) for n in re.findall(r"\d+", VERSION)[:4]]
    return tuple((nums + [0, 0, 0, 0])[:4])


def write_version_info():
    v = _numeric_version()
    text = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('0C0A04B0', [
      StringStruct('CompanyName', 'Sentinel'),
      StringStruct('FileDescription', 'Sentinel: analizador de archivos'),
      StringStruct('FileVersion', '{VERSION}'),
      StringStruct('ProductName', 'Sentinel'),
      StringStruct('ProductVersion', '{VERSION}'),
      StringStruct('OriginalFilename', 'Sentinel.exe')])]),
    VarFileInfo([VarStruct('Translation', [0x0C0A, 1200])])])
"""
    (ROOT / "packaging" / "version_info.txt").write_text(text, encoding="utf-8")


def main():
    if not any(CAPA_RULES_DIR.rglob("*.yml")) or len(list(CAPA_SIGS_DIR.glob("*.sig"))) < 3:
        print("Faltan las reglas de capa: ejecuta antes python tools/setup_rules.py")
        return 1
    write_version_info()
    shutil.rmtree(ROOT / "dist" / "Sentinel", ignore_errors=True)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build"),
                    str(ROOT / "packaging" / "sentinel.spec")], check=True, cwd=ROOT)
    print(f"Aplicación: {ROOT / 'dist' / 'Sentinel' / 'Sentinel.exe'}")

    iscc = next((p for p in ISCC if p.exists()), None)
    if iscc is None:
        print("Inno Setup no está instalado: no se genera el instalador.")
        return 0
    subprocess.run([str(iscc), f"/DAppVersion={VERSION}", str(ROOT / "packaging" / "installer.iss")],
                   check=True, cwd=ROOT)
    print(f"Instalador: {ROOT / 'dist' / f'Sentinel-Setup-{VERSION}.exe'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
