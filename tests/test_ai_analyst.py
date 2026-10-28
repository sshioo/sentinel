"""Pruebas del analista IA: prompt, proveedores, caché y degradación.

No hace red: el transporte se sustituye por una función falsa.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engines import ai_analyst as ai

_fails = []


def check(label, got, expected):
    ok = got == expected
    print(f"{'OK ' if ok else 'X  '} {label} -> {got}")
    if not ok:
        _fails.append(f"{label}: esperado {expected!r}, obtenido {got!r}")


def _isolate_env():
    keys = ["AI_PROVIDER", "OPENAI_API_KEY", "OPENAI_MODEL", "GEMINI_API_KEY",
            "GEMINI_MODEL", "OLLAMA_MODEL"]
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    return saved


def _restore_env(saved):
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


saved = _isolate_env()
tmpdir = Path(tempfile.mkdtemp(prefix="sentinel_ai_"))
ai.CACHE_PATH = tmpdir / ".ai_cache.json"

# 1) sin claves no hay proveedor
check("sin claves: configured", ai.status()["configured"], False)
check("sin claves: explain ok", ai.explain({"archivo": "x"})["ok"], False)
check("sin claves: motivo menciona .env", ".env" in ai.status()["reason"], True)

# 2) detección de proveedor
os.environ["OPENAI_API_KEY"] = "dummy"
check("detecta openai", ai.provider(), "openai")
check("modelo por defecto", ai.model_name(), "gpt-4o-mini")
os.environ["AI_PROVIDER"] = "gemini"
check("AI_PROVIDER manda", ai.provider(), "")  # gemini sin clave
os.environ.pop("AI_PROVIDER")
os.environ["OLLAMA_MODEL"] = "llama3.1:8b"
os.environ["AI_PROVIDER"] = "auto"
check("auto prefiere openai", ai.provider(), "openai")
os.environ["AI_PROVIDER"] = "ollama"
check("ollama explícito", ai.provider(), "ollama")

# 3) prompt: incluye datos y no se pasa del límite
sample = tmpdir / "muestra.py"
sample.write_text("import os\nos.system('echo hola')\n" + "# relleno\n" * 4000,
                  encoding="utf-8")
entry = {
    "archivo": "muestra.py", "ruta": str(sample), "tipo": "CÓDIGO",
    "estado": "alerta", "score": 62, "engine": "stub+ast",
    "findings": [{"regla": "eval_exec", "severidad": "alto", "line": 2,
                  "mitre_id": "T1059.006", "detalle": "llamada a os.system"}],
    "iocs": [{"tipo": "domain", "valor": "c2.example", "line": 1}],
}
msgs = ai.build_messages(entry)
user = msgs[1]["content"]
check("prompt: nombre", "muestra.py" in user, True)
check("prompt: hallazgo", "eval_exec" in user, True)
check("prompt: mitre", "T1059.006" in user, True)
check("prompt: ioc", "c2.example" in user, True)
check("prompt: fragmento acotado", len(user) < ai.MAX_SNIPPET_CHARS + 4000, True)
check("prompt: recorta líneas", user.count("# relleno") <= 120, True)
check("prompt: bloque fragmento", "--- fragmento ---" in user, True)

# 4) respuesta + caché
calls = {"n": 0}


def fake_ok(messages):
    calls["n"] += 1
    return "RESUMEN: prueba\nRIESGO: alto"


ai._CALLERS["openai"] = fake_ok
os.environ["OPENAI_API_KEY"] = "dummy"
os.environ["AI_PROVIDER"] = "openai"
os.environ["OPENAI_MODEL"] = "modelo-test"
r1 = ai.explain(entry)
check("explica: ok", r1["ok"], True)
check("explica: proveedor", r1["provider"], "openai")
check("explica: no cacheado", r1["cached"], False)
check("explica: texto", "RESUMEN: prueba" in r1["text"], True)


def fake_boom(messages):
    calls["n"] += 1
    raise RuntimeError("fallo de red simulado")


ai._CALLERS["openai"] = fake_boom
r2 = ai.explain(entry)
check("segunda llamada: cacheada", r2["cached"], True)
check("segunda llamada: no repite red", calls["n"], 1)
check("cache: texto íntegro", r2["text"], r1["text"])

# 5) force ignora la caché y propaga el error sin romper
r3 = ai.explain(entry, force=True)
check("force: error controlado", r3["ok"], False)
check("force: mensaje", "fallo de red simulado" in r3["error"], True)

# 6) binario: solo cadenas imprimibles
blob = tmpdir / "muestra.bin"
blob.write_bytes(bytes(range(256)) * 4 + b"CADENA_SOSPECHOSA_12345")
entry_bin = dict(entry, archivo="muestra.bin", ruta=str(blob), tipo="BINARIO",
                 findings=[], iocs=[])
snip = ai._snippet(entry_bin["ruta"])
check("binario: extrae cadena", "CADENA_SOSPECHOSA_12345" in snip, True)
check("binario: sin bytes de control", "\x00" in snip, False)

# 7) archivo inexistente no rompe
entry_missing = dict(entry, ruta=str(tmpdir / "no_existe.py"))
r4 = ai.explain(entry_missing)
check("archivo ausente: no rompe", isinstance(r4["ok"], bool), True)

_restore_env(saved)
if _fails:
    print("\nFallos:")
    for f in _fails:
        print(" -", f)
    sys.exit(1)
print("\nTodos los casos del analista IA pasaron.")
