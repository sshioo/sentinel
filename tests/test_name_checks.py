import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from core import name_checks


def _rules(name):
    return sorted(f["rule_id"] for f in name_checks.check(Path(name)))


def check(label, got, expected):
    assert got == expected, f"{label}: esperado {expected}, obtenido {got}"
    print(f"OK  {label} -> {got}")


check("rtl usa U+202E", name_checks.RTL_OVERRIDE, "\u202e")
check("doble extension exe", _rules("factura.pdf.exe"), ["double_extension"])
check("doble extension js", _rules("informe.docx.js"), ["double_extension"])
check("doble extension ruta", _rules(r"C:\Users\x\Downloads\foto.jpg.scr"), ["double_extension"])
check("pdf normal", _rules("factura.pdf"), [])
check("exe normal", _rules("setup.exe"), [])
check("ejecutable con señuelo al final", _rules("setup.exe.pdf"), [])
check("rlo", _rules("invoice_\u202efdp.exe"), ["rtl_override"])
check("hallazgo con peso", name_checks.check(Path("a.pdf.exe"))[0]["peso"], 30)

print("\nTodos los casos de nombre pasaron.")
