import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import VERSION


def _capa_worker(out_file, capa_args):
    """Ejecuta capa dentro de Sentinel.exe empaquetado y escribe el JSON en out_file."""
    import os

    devnull = open(os.devnull, "w", encoding="utf-8")
    with open(out_file, "w", encoding="utf-8") as fh:
        sys.stdout = fh
        if sys.stderr is None:
            sys.stderr = devnull
        from capa.main import main as capa_main
        code = capa_main(capa_args)
    return code or 0


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--capa-worker":
        sys.exit(_capa_worker(sys.argv[2], sys.argv[3:]))
    # El .exe de ventana no tiene consola: sin esto, cualquier print fallaría.
    if sys.stdout is None or sys.stderr is None:
        import os
        sink = open(os.devnull, "w", encoding="utf-8")
        sys.stdout = sys.stdout or sink
        sys.stderr = sys.stderr or sink

    ap = argparse.ArgumentParser(prog="sentinel", description="Sentinel: ¿es seguro abrir este archivo?")
    ap.add_argument("--version", action="version", version=f"Sentinel {VERSION}")
    ap.parse_args()

    from ui.app import SentinelApp

    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    main()
