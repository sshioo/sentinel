"""Traza estática de un script Python.

No ejecuta el archivo. Recorre su árbol sintáctico y lista, en orden de línea,
las llamadas que importan (comandos, procesos, red, entrada de credenciales,
ejecución dinámica, escritura y borrado de archivos) con los argumentos tal
como aparecen en el código.

Una versión anterior ejecutaba el script dentro de Sentinel con funciones
sustituidas. Era evadible con __import__ o getattr: un script malicioso corría
con los permisos del usuario. Python no se puede aislar dentro del mismo proceso.
"""
import ast
from pathlib import Path

from config import (
    MAX_SNIPPET_LEN,
    SEVERITY_SCORE,
    TRACER_MAX_EVENTS,
    TRACER_RULES,
)

_TRACKED = {
    "system": "exec_command",
    "popen": "exec_process",
    "run": "exec_process",
    "call": "exec_process",
    "Popen": "exec_process",
    "check_output": "exec_process",
    "socket": "network",
    "create_connection": "network",
    "get": "http_request",
    "post": "http_request",
    "urlopen": "network",
    "urlretrieve": "network",
    "input": "credential_input",
    "eval": "dynamic_exec",
    "exec": "dynamic_exec",
    "compile": "dynamic_exec",
    "remove": "file_delete",
    "unlink": "file_delete",
    "rmtree": "file_delete",
}

# get/post existen en cualquier diccionario: solo cuentan si el objeto parece un cliente HTTP.
_HTTP_OBJECTS = {"requests", "session", "httpx", "client", "http", "urllib3"}


def _safe_repr(value):
    try:
        text = repr(value)
    except Exception:
        return "<no representable>"
    return text[:MAX_SNIPPET_LEN]


def _arg_text(node):
    try:
        return ast.unparse(node)
    except (RecursionError, ValueError):
        return "<expresión compleja>"


def _write_mode(node):
    """True si open(...) escribe, o si el modo no se puede saber de antemano."""
    mode = None
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode = node.args[1].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    if mode is None:
        return len(node.args) >= 2 or any(kw.arg == "mode" for kw in node.keywords)
    return isinstance(mode, str) and any(ch in mode for ch in "wxa+")


def _match(node):
    func = node.func
    if isinstance(func, ast.Name):
        if func.id == "open":
            return "file_write" if _write_mode(node) else None
        return _TRACKED.get(func.id)
    if isinstance(func, ast.Attribute) and func.attr in _TRACKED:
        evento = _TRACKED[func.attr]
        if evento == "http_request":
            base = func.value
            name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
            return evento if str(name).lower() in _HTTP_OBJECTS else None
        return evento
    return None


def _collect(tree):
    events = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        evento = _match(node)
        if evento:
            events.append({
                "evento": evento,
                "args": _safe_repr(tuple(_arg_text(a) for a in node.args)),
                "line": getattr(node, "lineno", 0),
            })
    events.sort(key=lambda e: e["line"])
    return events[:TRACER_MAX_EVENTS]


def trace(path):
    try:
        source = Path(path).resolve().read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"events": [], "findings": [], "error": str(exc), "score": 0, "estado": "pendiente"}

    try:
        tree = ast.parse(source)
        events = _collect(tree)
    except SyntaxError as exc:
        return {"events": [], "findings": [], "score": 0, "estado": "pendiente",
                "error": f"SyntaxError en línea {exc.lineno}: {exc.msg}"}
    except (RecursionError, MemoryError, ValueError) as exc:
        return {"events": [], "findings": [], "score": 0, "estado": "pendiente",
                "error": f"el archivo no se pudo recorrer: {type(exc).__name__}"}

    findings = _findings_from_events(events)
    score = _score(findings)
    return {
        "events": events,
        "findings": findings,
        "score": score,
        "estado": _estado(score, findings),
        "error": None,
        "engine": "tracer",
        "static": True,
    }


def _findings_from_events(events):
    seen = set()
    findings = []
    for ev in events:
        evento = ev["evento"]
        if evento not in TRACER_RULES:
            continue
        key = (evento, ev["line"])
        if key in seen:
            continue
        seen.add(key)
        rule = TRACER_RULES[evento]
        findings.append({
            "line": ev["line"],
            "rule_id": f"trace_{evento}",
            "regla": rule["titulo"],
            "severidad": rule["severidad"],
            "peso": SEVERITY_SCORE[rule["severidad"]],
            "mitre_id": rule["mitre"][0],
            "mitre_name": rule["mitre"][1],
            "detalle": f"{evento}: {ev['args']}"[:MAX_SNIPPET_LEN],
        })
    return findings


def _score(findings):
    if not findings:
        return 0
    from core.scoring import weighted_score
    return weighted_score(findings)


def _estado(score, findings):
    if not findings:
        return "limpio"
    from core.scoring import estado_from_score
    return estado_from_score(score, findings)
