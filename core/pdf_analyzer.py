import re
from pathlib import Path

from config import BINARY_RULES, MAX_SNIPPET_LEN, PDF_DANGER_KEYS, SEVERITY_SCORE
from core.scoring import estado_from_score, weighted_score

try:
    from pypdf import PdfReader
    _HAVE_PYPDF = True
except ImportError:
    _HAVE_PYPDF = False


def _finding(rule_id, detalle, line=0):
    rule = BINARY_RULES[rule_id]
    return {
        "line": line,
        "rule_id": rule_id,
        "regla": rule["titulo"],
        "severidad": rule["severidad"],
        "peso": SEVERITY_SCORE[rule["severidad"]],
        "mitre_id": rule["mitre"][0],
        "mitre_name": rule["mitre"][1],
        "detalle": detalle[:MAX_SNIPPET_LEN],
    }


def is_pdf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(5).startswith(b"%PDF")
    except OSError:
        return False


def analyze_pdf(path):
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return {"score": 0, "estado": "alerta", "findings": [], "error": str(exc),
                "engine": "pdf"}

    findings = []
    seen = set()

    for token, (rule_id, label) in PDF_DANGER_KEYS.items():
        if rule_id in seen:
            continue
        if re.search(rb"/" + re.escape(token.encode()) + rb"\b", raw, re.IGNORECASE):
            findings.append(_finding(rule_id, f"clave {label}"))
            seen.add(rule_id)

    streams, filters = _stream_stats(raw)
    if filters and (len(filters) >= 3 or streams > 5):
        findings.append(_finding(
            "pdf_obfuscation", f"{streams} streams, filtros {', '.join(filters)}"))

    meta = _metadata(path)
    score = weighted_score(findings)
    return {
        "score": score,
        "estado": estado_from_score(score, findings),
        "findings": findings,
        "error": None,
        "engine": "pdf",
        "meta": {"streams": streams, "filters": filters, **meta},
    }


def _stream_stats(raw):
    streams = len(re.findall(rb"\bstream\b", raw))
    filters = sorted({m.decode("latin-1", errors="replace")
                      for m in re.findall(rb"/Filter\s*/([A-Za-z0-9]+)", raw)})
    return streams, filters


def _metadata(path):
    if not _HAVE_PYPDF:
        return {}
    try:
        reader = PdfReader(str(path))
        info = reader.metadata or {}
        return {
            "pages": len(reader.pages),
            "producer": str(info.get("/Producer", ""))[:80],
        }
    except Exception:
        return {}
