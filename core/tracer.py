import ast
import builtins
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

_WRITE_MODES = {"w", "wb", "a", "ab", "x", "xb", "r+", "w+", "a+"}

_WRAPPER_NAMES = {
    "exec_command": "__trace_exec_command",
    "exec_process": "__trace_exec_process",
    "network": "__trace_network",
    "http_request": "__trace_http",
    "credential_input": "__trace_input",
    "dynamic_exec": "__trace_dynamic",
    "file_write": "__trace_file_write",
    "file_delete": "__trace_file_delete",
}


class _Recorder:
    def __init__(self):
        self.events = []

    def record(self, evento, args, line):
        if len(self.events) >= TRACER_MAX_EVENTS:
            return
        self.events.append({
            "evento": evento,
            "args": _safe_repr(args),
            "line": line,
        })


def _safe_repr(value):
    try:
        text = repr(value)
    except Exception:
        return "<no representable>"
    return text[:MAX_SNIPPET_LEN]


class _Instrument(ast.NodeTransformer):
    def __init__(self, recorder):
        self.recorder = recorder

    def visit_Call(self, node):
        self.generic_visit(node)
        evento = self._match(node)
        if evento and evento in _WRAPPER_NAMES:
            wrapper = _WRAPPER_NAMES[evento]
            args = [ast.Constant(evento), ast.Constant(node.lineno)] + list(node.args)
            new_call = ast.Call(
                func=ast.Name(id=wrapper, ctx=ast.Load()),
                args=args,
                keywords=node.keywords,
            )
            return ast.copy_location(new_call, node)
        return node

    def _match(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _TRACKED:
            return _TRACKED[func.id]
        if isinstance(func, ast.Attribute):
            if func.attr in _TRACKED:
                return _TRACKED[func.attr]
        return None


class _OpenInstrument(ast.NodeTransformer):
    def __init__(self, recorder):
        self.recorder = recorder

    def visit_Call(self, node):
        self.generic_visit(node)
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            mode = _extract_mode(node)
            if mode is None or any(ch in mode for ch in "wxa+"):
                args = [ast.Constant("file_write"), ast.Constant(node.lineno)] + list(node.args)
                new_call = ast.Call(
                    func=ast.Name(id=_WRAPPER_NAMES["file_write"], ctx=ast.Load()),
                    args=args,
                    keywords=node.keywords,
                )
                return ast.copy_location(new_call, node)
        return node


def _extract_mode(node):
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        if isinstance(node.args[1].value, str):
            return node.args[1].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, str):
                return kw.value.value
    return None


def _build_globals(recorder, findings_sink):
    def make_wrapper(evento):
        def wrapper(*args, **kwargs):
            line = args[1] if len(args) > 1 and isinstance(args[1], int) else 0
            payload = args[2:] if len(args) > 2 else ()
            recorder.record(evento, payload, line)
            findings_sink.append((evento, line, payload))
            if evento == "credential_input":
                return "salida_suprimida"
            return _NullResult()
        return wrapper

    safe_builtins = {
        "len": len, "range": range, "print": lambda *a, **k: None,
        "str": str, "int": int, "float": float, "list": list, "dict": dict,
        "tuple": tuple, "set": set, "bool": bool, "bytes": bytes,
        "enumerate": enumerate, "zip": zip, "min": min, "max": max,
        "abs": abs, "sum": sum, "sorted": sorted, "isinstance": isinstance,
        "True": True, "False": False, "None": None, "type": type,
        "getattr": getattr, "hasattr": hasattr, "repr": repr,
        "__import__": builtins.__import__,
    }

    glb = {"__builtins__": safe_builtins}
    for evento, name in _WRAPPER_NAMES.items():
        glb[name] = make_wrapper(evento)
    return glb


class _NullResult:
    def __call__(self, *a, **k):
        return self

    def __getattr__(self, name):
        return self

    def __iter__(self):
        return iter(())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __getitem__(self, key):
        return self

    def __repr__(self):
        return "<trazado>"


def trace(path):
    try:
        source = Path(path).resolve().read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"events": [], "findings": [], "error": str(exc), "score": 0, "estado": "pendiente"}

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"events": [], "findings": [], "score": 0, "estado": "pendiente",
                "error": f"SyntaxError en línea {exc.lineno}: {exc.msg}"}

    recorder = _Recorder()
    raw_events = []

    tree = _Instrument(recorder).visit(tree)
    tree = _OpenInstrument(recorder).visit(tree)
    ast.fix_missing_locations(tree)

    code = compile(tree, filename="<tracer>", mode="exec")
    glb = _build_globals(recorder, raw_events)

    error = None
    try:
        exec(code, glb)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    findings = _findings_from_events(recorder.events)
    score = _score(recorder.events)
    estado = _estado(score, recorder.events)

    return {
        "events": recorder.events,
        "findings": findings,
        "score": score,
        "estado": estado,
        "error": error,
        "engine": "tracer",
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


def _score(events):
    if not events:
        return 0
    from core.scoring import weighted_score
    return weighted_score(_findings_from_events(events))


def _estado(score, events):
    if not events:
        return "limpio"
    from core.scoring import estado_from_score
    return estado_from_score(score, _findings_from_events(events))
