from config import RULES, SEVERITY_SCORE
from core import name_checks, yara_scanner
from core.scoring import estado_from_score, finalize, weighted_score
from core.deep_analyzer import deep_analyze
from core.pipeline import analyze_binary


def analyze(path, online=True):
    return _analyze_by_type(path, online)


def analyze_code(path, online=False):
    try:
        text = _read_text(path)
    except OSError as exc:
        return {
            "score": 0,
            "estado": "alerta",
            "findings": [{"line": 0, "regla": str(exc), "severidad": "alto"}],
            "engine": "stub",
        }

    findings = _text_findings(text)

    deep = deep_analyze(path)
    deep_findings = _deep_findings(deep["findings"])
    findings = _merge(findings, deep_findings)

    yara = yara_scanner.scan(path)
    findings = _merge(findings, _yara_findings(yara["findings"]))
    findings = finalize(_merge(findings, name_checks.check(path)))

    score = weighted_score(findings)
    estado = estado_from_score(score, findings)
    if deep["error"] and not findings:
        estado = "pendiente"

    engine = "stub+ast"
    if yara["findings"]:
        engine += "+yara"
    return {"score": score, "estado": estado, "findings": findings, "engine": engine}


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


def _analyze_by_type(path, online):
    from core.dispatcher import classify
    tipo = classify(path)
    if tipo == "CÓDIGO":
        return analyze_code(path)
    if tipo == "BINARIO":
        return analyze_binary(path, online=online)
    return {"score": 0, "estado": "limpio", "findings": [], "engine": "skip"}


analyze_text = analyze_code


def _text_findings(text):
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for needle, label, severity in RULES:
            if needle in line:
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
