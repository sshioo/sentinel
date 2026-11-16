import re
from pathlib import Path

from config import RULES, SEVERITY_SCORE
from core import name_checks, static_re, yara_scanner
from core.scoring import estado_from_score, finalize, reasons, weighted_score
from core.deep_analyzer import deep_analyze
from core.pipeline import analyze_binary

# Una regla de texto que empieza por letra no debe saltar dentro de otra
# palabra: «eval(» no es «retrieval(».
_RULE_PATTERNS = [
    (re.compile(("(?<![A-Za-z0-9_])" if needle[0].isalnum() else "") + re.escape(needle)),
     label, severity)
    for needle, label, severity in RULES
]


def analyze(path, online=True, force=False):
    """Analiza un archivo. force=True lo analiza aunque el vigilante lo ignoraría
    (temporal, oculto...): quien elige un archivo a mano espera un veredicto real."""
    try:
        return _analyze_by_type(path, online, force)
    except Exception as exc:  # noqa: BLE001 - un archivo hostil no puede tumbar el análisis
        return _failed(exc)


def _failed(exc):
    return {
        "score": 0,
        "estado": "pendiente",
        "findings": [],
        "engine": "error",
        "errors": [f"análisis interrumpido ({type(exc).__name__}): {str(exc)[:120]}"],
        "incomplete": True,
    }


def _disguised_exe_findings(path):
    """Un ejecutable (MZ) con extensión de código: no es el script que dice ser."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
    except OSError:
        return []
    if head != b"MZ":
        return []
    ext = Path(path).suffix
    return [
        name_checks.make_finding("extension_mismatch", f"extensión {ext} pero contenido exe"),
        name_checks.make_finding("executable_content", "contenido PE (MZ) en archivo de código"),
    ]


def analyze_code(path, online=False):
    try:
        text = _read_text(path)
    except OSError as exc:
        return {"score": 0, "estado": "pendiente", "findings": [], "engine": "stub",
                "errors": [f"no se pudo leer el archivo: {exc}"], "incomplete": True}

    findings = _text_findings(text)

    deep = deep_analyze(path)
    deep_findings = _deep_findings(deep["findings"])
    if not deep["error"]:
        # Con el árbol sintáctico disponible, la búsqueda por texto solo aporta
        # contexto: el AST ya sabe si «eval» es una llamada o un comentario.
        for f in findings:
            f["confianza"] = "baja"
    findings = _merge(findings, deep_findings)

    yara = yara_scanner.scan(path)
    findings = _merge(findings, _yara_findings(yara["findings"]))
    findings = _merge(findings, _disguised_exe_findings(path))
    # Ingeniería inversa del script: decodifica base64/hex/-EncodedCommand y
    # busca ejecutables o código escondidos dentro de las cadenas.
    re_result = static_re.analyze(path, (), False, deep=False)
    for f in re_result["findings"]:
        f.setdefault("motor", "ingenieria_inversa")
    findings = _merge(findings, re_result["findings"])
    findings = finalize(_merge(findings, name_checks.check(path)))

    score = weighted_score(findings)
    estado = estado_from_score(score, findings)

    errors = []
    incomplete = False
    if yara.get("error"):
        errors.append(f"yara: {yara['error']}")
        incomplete = True
    if deep["error"]:
        # Solo los .py se pueden leer con el árbol de Python. Un .ps1, .c o .php
        # que no compila como Python es lo normal, no una anomalía.
        if Path(path).suffix.lower() == ".py" or not deep["error"].startswith("SyntaxError"):
            errors.append(f"ast: {deep['error']}")
            incomplete = True
    if incomplete and estado == "limpio":
        estado = "pendiente"

    engine = "stub+ast"
    if yara["findings"]:
        engine += "+yara"
    engine += "+ingenieria_inversa"
    if re_result.get("error"):
        errors.append(f"ingenieria_inversa: {re_result['error']}")
    return {"score": score, "estado": estado, "findings": findings, "engine": engine,
            "errors": errors, "incomplete": incomplete, "razones": reasons(findings),
            "meta": {"ingenieria_inversa": re_result.get("meta") or {}}}


def _yara_findings(yara_findings):
    return [
        {
            "line": f.get("line", 0),
            "regla": f["regla"],
            "detalle": f.get("detalle", ""),
            "severidad": f["severidad"],
            "mitre_id": f.get("mitre_id"),
            "mitre_name": f.get("mitre_name"),
            "rule_id": f.get("rule_id"),
            "peso": f.get("peso"),
            "confianza": f.get("confianza"),
        }
        for f in yara_findings
    ]


def _analyze_by_type(path, online, force=False):
    from config import CODE_EXTENSIONS
    from core.dispatcher import classify
    tipo = classify(path)
    if tipo == "IGNORAR" and force:
        tipo = "CÓDIGO" if Path(path).suffix.lower() in CODE_EXTENSIONS else "BINARIO"
    if tipo == "CÓDIGO":
        return analyze_code(path)
    if tipo == "BINARIO":
        return analyze_binary(path, online=online)
    return {"score": 0, "estado": "limpio", "findings": [], "engine": "skip"}


analyze_text = analyze_code


def _text_findings(text):
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern, label, severity in _RULE_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "line": lineno,
                    "rule_id": f"text:{label}",
                    "regla": label,
                    "detalle": line.strip(),
                    "severidad": severity,
                    "peso": SEVERITY_SCORE[severity],
                    "confianza": "media",
                })
    return findings


def _merge(text_findings, deep_findings):
    covered = {(f["line"], f["severidad"]) for f in deep_findings}
    merged = list(deep_findings)
    for f in text_findings:
        key = (f["line"], f["severidad"])
        if key in covered and f["line"] != 0:
            continue
        if any(f["line"] == g["line"] and f["regla"] == g["regla"] for g in merged):
            continue
        merged.append(f)
    merged.sort(key=lambda f: (f["line"], f["regla"]))
    return merged


def _deep_findings(deep_findings):
    return [
        {
            "line": f["line"],
            "rule_id": f.get("rule_id"),
            "regla": f["regla"],
            "detalle": f["detalle"],
            "severidad": f["severidad"],
            "peso": f.get("peso"),
            "mitre_id": f.get("mitre_id"),
            "mitre_name": f.get("mitre_name"),
            "confianza": f.get("confianza"),
        }
        for f in deep_findings
    ]


def _read_text(path, limit=2_000_000):
    with open(path, "rb") as fh:
        raw = fh.read(limit)
    return raw.decode("utf-8", errors="replace")


def entry_extras(result):
    """Lo que la interfaz y los informes guardan de un análisis, además de los hallazgos:
    los motivos del veredicto, la identidad del archivo y la ingeniería inversa."""
    meta = result.get("meta") or {}
    binary = meta.get("binary") or {}
    re_meta = meta.get("ingenieria_inversa") or {}
    capa = meta.get("capa") or {}
    pe = meta.get("pe") or {}
    extras = {
        "razones": result.get("razones") or [],
        "info": {k: binary[k] for k in ("sha256", "md5", "size", "entropy", "magic") if k in binary},
        "re": {
            "pasos": list(re_meta.get("pasos") or []),
            "capacidades": list(re_meta.get("capacidades") or []),
            "tallados": list(re_meta.get("tallados") or []),
            "capa": [c.get("nombre") for c in capa.get("capacidades") or []][:60],
            "capa_omitido": capa.get("omitido"),
        },
    }
    if pe:
        ep = pe.get("entry_point") or {}
        sig = pe.get("firma") or {}
        extras["re"]["pe"] = {
            "arquitectura": pe.get("arquitectura"),
            "tipo": pe.get("tipo"),
            "dotnet": pe.get("dotnet"),
            "imports": pe.get("count"),
            "secciones": [f"{s.get('name')} · entropía {s.get('entropy')}" for s in pe.get("sections") or []][:12],
            "entrada": (ep.get("disasm") or [])[:12],
            "entrada_nota": pe.get("entry_note"),
            "firma": sig.get("signer") or sig.get("status"),
        }
    return extras
