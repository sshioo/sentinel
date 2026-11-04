import re
import zlib
from pathlib import Path

from config import BINARY_RULES, MAX_READ_BYTES, MAX_SNIPPET_LEN, PDF_DANGER_KEYS, SEVERITY_SCORE
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
        with open(path, "rb") as fh:
            raw = fh.read(MAX_READ_BYTES)
    except OSError as exc:
        return {"score": 0, "estado": "pendiente", "findings": [], "error": str(exc),
                "engine": "pdf"}

    findings = []
    seen = set()
    haystack = _haystack(raw)

    for token, (rule_id, label) in PDF_DANGER_KEYS.items():
        if rule_id in seen:
            continue
        if re.search(rb"/" + re.escape(token.encode()) + rb"\b", haystack, re.IGNORECASE):
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


_HEX_NAME = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)
_MAX_INFLATED = 8 * 1024 * 1024
_MAX_STREAMS = 400


def _haystack(raw):
    """Texto donde buscar claves: el PDF con los nombres #xx decodificados más el
    contenido de los flujos comprimidos (/ObjStm guarda diccionarios ahí dentro)."""
    parts = [_HEX_NAME.sub(lambda m: bytes([int(m.group(1), 16)]), raw)]
    budget = _MAX_INFLATED
    for i, m in enumerate(_STREAM.finditer(raw)):
        if i >= _MAX_STREAMS or budget <= 0:
            break
        try:
            inflater = zlib.decompressobj()
            data = inflater.decompress(m.group(1), min(budget, 1024 * 1024))
        except zlib.error:
            continue
        budget -= len(data)
        parts.append(_HEX_NAME.sub(lambda mm: bytes([int(mm.group(1), 16)]), data))
    return b"\n".join(parts)


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
