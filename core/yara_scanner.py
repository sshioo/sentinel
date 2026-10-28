from pathlib import Path

from config import BINARY_RULES, MAX_SNIPPET_LEN, SEVERITY_SCORE, YARA_RULES_DIR
from core.scoring import estado_from_score, weighted_score

_RULES = None
_LOAD_ERROR = None
_HAVE_YARA = False

try:
    import yara
    _HAVE_YARA = True
except ImportError:
    _HAVE_YARA = False


def _rule_severity(meta):
    sev = str(meta.get("severity", "alto")).lower()
    return sev if sev in SEVERITY_SCORE else "alto"


def _rule_confidence(meta):
    conf = str(meta.get("confidence", "media")).lower()
    return conf if conf in ("alta", "media", "baja") else "media"


def _compile():
    global _RULES, _LOAD_ERROR
    if _RULES is not None or _LOAD_ERROR is not None:
        return
    if not _HAVE_YARA:
        _LOAD_ERROR = "yara-python no instalado"
        return
    if not YARA_RULES_DIR.exists():
        _LOAD_ERROR = f"directorio de reglas ausente: {YARA_RULES_DIR}"
        return
    _yar_files = {p.stem: str(p) for p in YARA_RULES_DIR.rglob("*.yar")}
    try:
        _RULES = yara.compile(filepaths=_yar_files)
    except yara.SyntaxError as exc:
        _LOAD_ERROR = f"error de sintaxis YARA: {exc}"


def scan(path):
    _compile()
    if _RULES is None:
        return {"score": 0, "estado": "pendiente", "findings": [],
                "error": _LOAD_ERROR or "reglas YARA no compiladas", "engine": "yara"}

    try:
        data = Path(path).resolve().read_bytes()
        matches = _RULES.match(data=data)
    except yara.Error as exc:
        return {"score": 0, "estado": "pendiente", "findings": [], "error": str(exc),
                "engine": "yara"}
    except OSError as exc:
        return {"score": 0, "estado": "pendiente", "findings": [], "error": str(exc),
                "engine": "yara"}

    findings = []
    for match in matches:
        sev = _rule_severity(match.meta)
        rule = BINARY_RULES["yara_match"]
        ident = match.meta.get("mitre", rule["mitre"][0])
        findings.append({
            "line": 0,
            "rule_id": "yara_match",
            "regla": f"YARA: {match.rule}",
            "severidad": sev,
            "peso": SEVERITY_SCORE[sev],
            "mitre_id": ident,
            "mitre_name": match.meta.get("description", rule["mitre"][1])[:MAX_SNIPPET_LEN],
            "detalle": match.meta.get("description", match.rule)[:MAX_SNIPPET_LEN],
            "confianza": _rule_confidence(match.meta),
        })

    score = weighted_score(findings)
    return {
        "score": score,
        "estado": estado_from_score(score, findings),
        "findings": findings,
        "error": None,
        "engine": "yara",
        "meta": {"matches": [m.rule for m in matches]},
    }
