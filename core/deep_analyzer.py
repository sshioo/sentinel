import ast
import re
from pathlib import Path

from config import (
    AST_RULES,
    DANGEROUS_CALLS,
    DANGEROUS_MODULE_CALLS,
    ENCODED_STR_MIN_LEN,
    MAX_SNIPPET_LEN,
    SEVERITY_SCORE,
)
from core.scoring import estado_from_score, finalize, weighted_score

_ENCODED_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


class DeepAnalyzer(ast.NodeVisitor):
    def __init__(self, source):
        self.source_lines = source.splitlines()
        self.findings = []
        self.import_aliases = {}
        self.session_vars = set()

    def _emit(self, rule_id, node, snippet=None):
        rule = AST_RULES[rule_id]
        line = getattr(node, "lineno", 1)
        self.findings.append({
            "line": line,
            "rule_id": rule_id,
            "regla": rule["titulo"],
            "severidad": rule["severidad"],
            "peso": SEVERITY_SCORE[rule["severidad"]],
            "mitre_id": rule["mitre"][0],
            "mitre_name": rule["mitre"][1],
            "detalle": snippet if snippet is not None else self._snippet(line),
        })

    def _snippet(self, line):
        if 1 <= line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()[:MAX_SNIPPET_LEN]
        return ""

    def _module_name(self, node):
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._module_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            inner = self._module_name(node.func)
            return inner
        return ""

    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname:
                self.import_aliases[alias.asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            name = f"{module}.{alias.name}" if module else alias.name
            self.import_aliases[alias.asname or alias.name] = name
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, (ast.Name, ast.Attribute)):
            called = self._module_name(node.value.func)
            if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "Session":
                caller = self._module_name(node.value.func.value)
                if caller.endswith("requests"):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            self.session_vars.add(tgt.id)
            if called.rsplit(".", 1)[-1] == "Session":
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        self.session_vars.add(tgt.id)

        if any(self._is_environ_subscript(t) for t in node.targets):
            self._emit("persistence_env", node, "asignación a os.environ[...]")

        self.generic_visit(node)

    def _is_environ_subscript(self, target):
        if not isinstance(target, ast.Subscript):
            return False
        base = self._module_name(target.value)
        return base.endswith("os.environ") or base == "environ"

    def visit_Call(self, node):
        func = node.func

        if isinstance(func, ast.Name):
            rule_id = DANGEROUS_CALLS.get(func.id)
            if rule_id:
                self._emit(rule_id, node)
        elif isinstance(func, ast.Attribute):
            dotted = self._module_name(func)
            parts = dotted.rsplit(".", 1) if dotted else []
            if len(parts) == 2:
                module, method = parts
                root = module.split(".")[-1]
                rule_id = DANGEROUS_MODULE_CALLS.get((root, method))
                if rule_id:
                    self._emit(rule_id, node, self._call_snippet(node, module, method))
                elif method in ("get", "post", "put", "delete", "request"):
                    obj = func.value
                    if isinstance(obj, ast.Name) and obj.id in self.session_vars:
                        self._emit("network", node, f"session.{method}(...)")
                elif root == "session" and method in ("get", "post", "put", "delete", "request"):
                    self._emit("network", node, f"session.{method}(...)")

        self.generic_visit(node)

    def _call_snippet(self, node, module, method):
        return f"{module}.{method}(...)"

    def visit_Attribute(self, node):
        if node.attr.startswith("__") and node.attr.endswith("__"):
            self._emit("dynamic_attribute", node)
        self.generic_visit(node)

    def visit_BinOp(self, node):
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
            value = node.left.value
            if isinstance(value, str) and len(value) >= ENCODED_STR_MIN_LEN:
                self._emit("string_format", node, "formato de cadena dinámico")
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, (str, bytes)):
            raw = node.value
            if isinstance(raw, bytes):
                self.generic_visit(node)
                return
            stripped = raw.strip()
            if (
                len(stripped) >= ENCODED_STR_MIN_LEN
                and _ENCODED_RE.match(stripped)
                and not stripped.isalpha()
                and not stripped.isspace()
            ):
                self._emit("encoded_string", node, stripped[:MAX_SNIPPET_LEN])
        self.generic_visit(node)


def deep_analyze(path):
    try:
        source = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"score": 0, "estado": "alerta", "findings": [], "error": str(exc)}

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {
            "score": 0,
            "estado": "pendiente",
            "findings": [],
            "error": f"SyntaxError en línea {exc.lineno}: {exc.msg}",
        }

    analyzer = DeepAnalyzer(source)
    analyzer.visit(tree)

    findings = finalize(analyzer.findings)
    score = weighted_score(findings)
    return {
        "score": score,
        "estado": estado_from_score(score, findings),
        "findings": findings,
        "error": None,
    }
