"""Descarga las reglas y firmas de capa que usa el motor de ingeniería inversa.

No se versionan (pesan ~15 MB). Se fijan a la misma versión que flare-capa en
requirements.txt para que reglas y motor sean compatibles.

Uso:
    python tools/setup_rules.py            descarga lo que falte
    python tools/setup_rules.py --force    vuelve a descargarlo todo
"""

import argparse
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import CAPA_RULES_DIR, CAPA_SIGS_DIR  # noqa: E402

CAPA_TAG = "v10.0.0"
RULES_ZIP = f"https://github.com/mandiant/capa-rules/archive/refs/tags/{CAPA_TAG}.zip"
SIGS_URL = f"https://raw.githubusercontent.com/mandiant/capa/{CAPA_TAG}/sigs/"
SIGS = ["1_flare_msvc_rtf_32_64.sig", "2_flare_msvc_atlmfc_32_64.sig", "3_flare_common_libs.sig"]


def _download(url, dest):
    with urllib.request.urlopen(url, timeout=120) as resp, open(dest, "wb") as fh:
        shutil.copyfileobj(resp, fh)


def rules(force):
    if CAPA_RULES_DIR.is_dir() and any(CAPA_RULES_DIR.rglob("*.yml")) and not force:
        return "ya estaban"
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "rules.zip"
        _download(RULES_ZIP, archive)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp)
        extracted = next(p for p in Path(tmp).iterdir() if p.is_dir())
        # .github contiene YAML de flujos de trabajo que capa intentaría leer como reglas.
        shutil.rmtree(extracted / ".github", ignore_errors=True)
        if CAPA_RULES_DIR.exists():
            shutil.rmtree(CAPA_RULES_DIR)
        shutil.move(str(extracted), str(CAPA_RULES_DIR))
    return f"{sum(1 for _ in CAPA_RULES_DIR.rglob('*.yml'))} reglas"


def sigs(force):
    CAPA_SIGS_DIR.mkdir(parents=True, exist_ok=True)
    fetched = 0
    for name in SIGS:
        target = CAPA_SIGS_DIR / name
        if target.exists() and target.stat().st_size > 0 and not force:
            continue
        _download(SIGS_URL + name, target)
        fetched += 1
    return f"{fetched} descargadas, {len(SIGS)} en total"


def main():
    ap = argparse.ArgumentParser(description="Descarga reglas y firmas de capa")
    ap.add_argument("--force", action="store_true", help="volver a descargar aunque existan")
    args = ap.parse_args()
    try:
        print(f"Reglas capa {CAPA_TAG}: {rules(args.force)}")
        print(f"Firmas FLIRT: {sigs(args.force)}")
    except OSError as exc:
        print(f"No se pudo descargar ({exc}). Sin estos archivos Sentinel funciona,"
              " pero sin el motor de ingeniería inversa.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
