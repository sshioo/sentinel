"""Ejecuta todas las suites de tests/ y resume el resultado.

Uso:
    python tools/run_tests.py

Devuelve 0 si todas pasan. Cada suite sigue pudiendo ejecutarse sola.
"""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    suites = sorted((ROOT / "tests").glob("test_*.py"))
    failed = []
    print(f"\n{len(suites)} suites\n" + "-" * 50)
    for suite in suites:
        t = time.perf_counter()
        proc = subprocess.run([sys.executable, str(suite)], cwd=ROOT, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              env={**__import__("os").environ, "PYTHONUTF8": "1"})
        ok = proc.returncode == 0
        print(f"{'[ok]' if ok else '[--]'}  {suite.stem:<28} {time.perf_counter() - t:5.1f} s")
        if not ok:
            failed.append((suite.stem, (proc.stdout + proc.stderr).strip().splitlines()[-4:]))
    print("-" * 50)
    for name, tail in failed:
        print(f"\n{name}:")
        for line in tail:
            print(f"  {line}")
    print(f"\n{'Todas pasan.' if not failed else f'{len(failed)} suite(s) fallan.'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
