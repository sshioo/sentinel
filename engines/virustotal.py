import os
import time
from pathlib import Path

from config import (
    BINARY_RULES,
    MAX_SNIPPET_LEN,
    SEVERITY_SCORE,
    VT_API_URL,
    VT_MAX_UPLOAD_BYTES,
    VT_RATE_LIMIT_PER_MIN,
    VT_TIMEOUT_S,
)

try:
    import requests
    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from core.scoring import estado_from_score, weighted_score

_last_call = 0.0
_MIN_INTERVAL = 60.0 / VT_RATE_LIMIT_PER_MIN


def _api_key():
    return os.environ.get("VT_API_KEY", "").strip()


def has_api_key():
    return bool(_api_key())


def _sha256(path):
    from core.binary_analyzer import hashes
    return hashes(path)["sha256"]


def _throttle():
    global _last_call
    elapsed = time.monotonic() - _last_call
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_call = time.monotonic()


def scan(sha256=None, path=None):
    if not _HAVE_REQUESTS:
        return _skip("requests no instalado")
    key = _api_key()
    if not key:
        return _skip("VT_API_KEY ausente en .env")

    headers = {"x-apikey": key}
    if sha256 is None and path is not None:
        sha256 = _sha256(path)
    try:
        report = _get_report(sha256, headers) if sha256 else None
        if report is None and path is not None:
            report = _lookup_by_path(path, headers)
    except _RateLimited:
        return _skip("rate limit de VirusTotal (429)")
    except Exception as exc:
        return _skip(f"error consultando VirusTotal: {exc}")

    if report is None:
        return _skip("sin resultados en VirusTotal")

    return _build_findings(report)


class _RateLimited(Exception):
    pass


def _get_report(sha256, headers):
    _throttle()
    resp = requests.get(f"{VT_API_URL}/files/{sha256}", headers=headers, timeout=VT_TIMEOUT_S)
    if resp.status_code == 404:
        return None
    if resp.status_code == 429:
        raise _RateLimited()
    resp.raise_for_status()
    return resp.json()


def _lookup_by_path(path, headers):
    path = Path(path)
    if path.stat().st_size > VT_MAX_UPLOAD_BYTES:
        return None

    _throttle()
    upload_url = f"{VT_API_URL}/files"
    with open(path, "rb") as fh:
        resp = requests.post(upload_url, headers=headers, files={"file": fh}, timeout=120)
    if resp.status_code == 429:
        raise _RateLimited()
    if resp.status_code not in (200, 201):
        return None

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        return None

    for _ in range(10):
        time.sleep(15)
        _throttle()
        poll = requests.get(f"{VT_API_URL}/analyses/{analysis_id}", headers=headers,
                            timeout=VT_TIMEOUT_S)
        if poll.status_code == 429:
            raise _RateLimited()
        if poll.status_code != 200:
            return None
        data = poll.json().get("data", {})
        if data.get("attributes", {}).get("status") == "completed":
            return data
    return None


def _skip(motivo):
    return {"score": 0, "estado": "pendiente", "findings": [],
            "error": motivo, "engine": "virustotal", "meta": {}}


def _build_findings(report):
    attrs = report.get("attributes", {})
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(v for k, v in stats.items() if isinstance(v, int))

    findings = []
    if malicious or suspicious:
        rule = BINARY_RULES["vt_detection"]
        sev = "crítico" if malicious else "alto"
        findings.append({
            "line": 0,
            "rule_id": "vt_detection",
            "regla": rule["titulo"],
            "severidad": sev,
            "peso": SEVERITY_SCORE[sev],
            "mitre_id": rule["mitre"][0],
            "mitre_name": rule["mitre"][1],
            "detalle": f"{malicious} maliciosos, {suspicious} sospechosos de {total} motores",
        })

    engines = _top_engines(attrs)
    score = weighted_score(findings)
    return {
        "score": score,
        "estado": estado_from_score(score, findings),
        "findings": findings,
        "error": None,
        "engine": "virustotal",
        "meta": {"malicious": malicious, "suspicious": suspicious,
                 "total": total, "engines": engines},
    }


def _top_engines(attrs):
    results = attrs.get("last_analysis_results") or {}
    flagged = [f"{name}: {r.get('result')}" for name, r in results.items()
               if r.get("category") == "malicious"]
    return flagged[:10]
