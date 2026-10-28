import argparse
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import VERSION

DEMO_DIR = Path(tempfile.gettempdir()) / "sentinel-demo"


def _demo(app):
    """Genera las muestras sintéticas fuera del proyecto y las analiza una a una.

    Van a %TEMP%\\sentinel-demo porque el dispatcher ignora a propósito los
    archivos dentro de la carpeta de Sentinel.
    """
    from core.analyzer import analyze
    from core.dispatcher import classify
    from tools.make_samples import generate

    files = generate(DEMO_DIR)
    time.sleep(2.4)
    for path, _engine, _expected in files:
        tipo = classify(path)
        result = analyze(path, online=False)
        app.queue.put({
            "hora": time.strftime("%H:%M:%S"),
            "archivo": path.name,
            "ruta": str(path),
            "tipo": tipo,
            "estado": result["estado"],
            "score": result.get("score", 0),
            "findings": result["findings"],
            "engine": result.get("engine", ""),
            "online": False,
        })
        time.sleep(1.6)


def main():
    ap = argparse.ArgumentParser(prog="sentinel", description="Sentinel: ¿es seguro abrir este archivo?")
    ap.add_argument("--demo", action="store_true",
                    help="analiza seis muestras inocuas al arrancar, sin tocar Descargas")
    ap.add_argument("--version", action="version", version=f"Sentinel {VERSION}")
    args = ap.parse_args()

    from ui.app import SentinelApp

    app = SentinelApp()
    if args.demo:
        threading.Thread(target=_demo, args=(app,), daemon=True).start()
    app.mainloop()


if __name__ == "__main__":
    main()
