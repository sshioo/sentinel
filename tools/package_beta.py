"""Empaqueta el código fuente de la beta en dist/sentinel-<versión>.zip.

Incluye lo necesario para que otra persona instale y ejecute Sentinel con
install.bat. Excluye secretos (.env), entornos, cachés, informes, muestras y
las reglas de capa, que install.bat descarga.

Uso:
    python tools/package_beta.py
"""

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import VERSION  # noqa: E402

EXCLUDE_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", "dist", "samples",
                "out", "cache", "capa", "capa-sigs", ".git"}
EXCLUDE_FILES = {".env"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".log"}


def _included(path):
    rel = path.relative_to(ROOT)
    if any(part in EXCLUDE_DIRS for part in rel.parts[:-1]):
        return False
    return path.name not in EXCLUDE_FILES and path.suffix not in EXCLUDE_SUFFIXES


def main():
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    target = dist / f"sentinel-{VERSION}.zip"
    files = sorted(p for p in ROOT.rglob("*") if p.is_file() and _included(p))
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, Path("sentinel") / path.relative_to(ROOT))

    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
    leaked = [n for n in names if n.endswith("/.env") or n.endswith("\\.env")]
    if leaked:
        target.unlink()
        print(f"Abortado: el paquete incluía {leaked}.")
        return 1
    print(f"{target}  ({target.stat().st_size / 1024:.0f} KB, {len(names)} archivos, sin .env)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
