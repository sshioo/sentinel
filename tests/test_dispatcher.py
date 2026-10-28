import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from core.dispatcher import classify


def check(path, expected):
    got = classify(path)
    assert got == expected, f"{path}: esperado {expected}, obtenido {got}"
    print(f"OK  {path} -> {got}")


check("test.py", "CÓDIGO")
check("app.js", "CÓDIGO")
check("lib.rs", "CÓDIGO")
check("install.ps1", "CÓDIGO")
check("setup.sh", "CÓDIGO")
check("image.png", "BINARIO")
check("setup.exe", "BINARIO")
check("archive.zip", "BINARIO")
check("movie.mkv", "BINARIO")
check("doc.pdf", "BINARIO")
check("report.crdownload", "IGNORAR")
check("data.part", "IGNORAR")
check("cache.tmp", "IGNORAR")
check("payload.download", "IGNORAR")
check(".hidden", "IGNORAR")
check("alternate:stream", "IGNORAR")
check(str(Path(__file__).resolve().parent / "sneaky.py"), "IGNORAR")
check("sneaky_noext", "BINARIO")

print("\nTodos los casos del dispatcher pasaron.")
