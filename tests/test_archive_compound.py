import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from core import archive_analyzer, pipeline
from core.scoring import finalize


def _zip(members):
    path = Path(tempfile.mkdtemp()) / "paquete.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return path


def _rules(findings):
    return sorted(f["rule_id"] for f in findings)


def check(label, got, expected):
    assert got == expected, f"{label}: esperado {expected}, obtenido {got}"
    print(f"OK  {label} -> {got}")


# 1) inspección de contenedores
z = _zip([("leeme.txt", b"hola"), ("payload.exe", b"MZ" + b"\0" * 60)])
check("zip detectado", archive_analyzer.is_zip(z), True)
check("txt no es zip", archive_analyzer.is_zip(Path(__file__)), False)
r = archive_analyzer.analyze_archive(z)
check("ejecutable dentro", _rules(r["findings"]), ["archive_executable"])
check("detalle nombra el miembro", "payload.exe" in r["findings"][0]["detalle"], True)

z2 = _zip([("factura.pdf.exe", b"MZ")])
check("doble extension dentro del zip",
      _rules(archive_analyzer.analyze_archive(z2)["findings"]),
      ["archive_executable", "double_extension"])

z3 = _zip([("fotos/vacaciones.jpg", b"jpg"), ("notas.txt", b"x")])
check("zip limpio sin hallazgos", archive_analyzer.analyze_archive(z3)["findings"], [])

bad = Path(tempfile.mkdtemp()) / "roto.zip"
bad.write_bytes(b"PK\x03\x04 no es un zip real")
check("zip roto no revienta", archive_analyzer.analyze_archive(bad)["error"] is not None, True)

# 2) escalado por combinación
check("pdf js + openaction escala",
      _rules(finalize([{"rule_id": "pdf_javascript"}, {"rule_id": "pdf_openaction"}])),
      ["pdf_auto_js", "pdf_javascript", "pdf_openaction"])
check("sin combinación no escala",
      _rules(finalize([{"rule_id": "pdf_javascript"}])), ["pdf_javascript"])
check("combinación no se duplica",
      _rules(finalize(finalize([{"rule_id": "pdf_javascript"}, {"rule_id": "pdf_openaction"}]))),
      ["pdf_auto_js", "pdf_javascript", "pdf_openaction"])

# 3) confianza
check("alta entropía es baja confianza",
      finalize([{"rule_id": "high_entropy"}])[0]["confianza"], "baja")
check("mismatch es alta confianza",
      finalize([{"rule_id": "extension_mismatch"}])[0]["confianza"], "alta")
check("regla desconocida es media",
      finalize([{"rule_id": "regla_inventada"}])[0]["confianza"], "media")

# 4) extremo a extremo por el pipeline
rp = pipeline.analyze_binary(z2, online=False)
check("pipeline marca el zip", rp["estado"], "alerta")
check("pipeline expone la regla", "archive_executable" in _rules(rp["findings"]), True)
check("pipeline asigna confianza", all("confianza" in f for f in rp["findings"]), True)

print("\nTodos los casos de archivo y combinación pasaron.")
