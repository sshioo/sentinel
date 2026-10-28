"""Ingeniería inversa de ejecutables con capa (Mandiant).

capa desensambla el binario, reconstruye funciones y bloques básicos, y busca
en ellos patrones de más de mil reglas: "inyecta código en otro proceso",
"registra pulsaciones", "detecta máquinas virtuales". Sentinel solo puntúa las
capacidades de CAPA_CATEGORIES; el resto se guarda como comportamiento observado.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from config import (
    ANALYSIS_CACHE_DIR,
    BINARY_RULES,
    CAPA_CATEGORIES,
    CAPA_MAX_BYTES,
    CAPA_RULES_DIR,
    CAPA_SIGS_DIR,
    CAPA_TIMEOUT_S,
    MAX_SNIPPET_LEN,
    SEVERITY_SCORE,
)

CACHE_VERSION = 1


def available():
    return (importlib.util.find_spec("capa") is not None
            and CAPA_RULES_DIR.is_dir() and CAPA_SIGS_DIR.is_dir())


def analyze(path, sha256, skip_reason=None):
    path = Path(path)
    base = {"engine": "capa", "score": 0, "estado": "limpio", "findings": [], "error": None}
    if skip_reason:
        return {**base, "meta": {"omitido": skip_reason}}
    if not available():
        return {**base, "error": "capa no disponible (pip install flare-capa y reglas en rules/capa)"}
    if path.stat().st_size > CAPA_MAX_BYTES:
        return {**base, "meta": {"omitido": f"mayor de {CAPA_MAX_BYTES // (1024 * 1024)} MB"}}

    cached = _cache_path(sha256)
    capabilities = _load_cache(cached)
    if capabilities is None:
        capabilities, error = _run_capa(path)
        if error:
            return {**base, "error": error}
        _save_cache(cached, capabilities)

    findings = _findings(capabilities)
    return {**base, "findings": findings,
            "meta": {"capacidades": capabilities, "total": len(capabilities)}}


def _run_capa(path):
    cmd = [sys.executable, "-m", "capa.main", "-j", "-q",
           "-r", str(CAPA_RULES_DIR), "-s", str(CAPA_SIGS_DIR), str(path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=CAPA_TIMEOUT_S,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return None, f"capa superó {CAPA_TIMEOUT_S} s"
    except OSError as exc:
        return None, str(exc)
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["sin detalle"]
        return None, f"capa terminó con código {proc.returncode}: {tail[0][:160]}"
    try:
        doc = json.loads(proc.stdout)
    except ValueError as exc:
        return None, f"salida de capa ilegible: {exc}"

    capabilities = []
    for name, rule in doc.get("rules", {}).items():
        meta = rule.get("meta", {})
        namespace = meta.get("namespace") or ""
        if meta.get("lib") or namespace.startswith("internal"):
            continue
        capabilities.append({
            "nombre": name,
            "namespace": namespace,
            "attack": [a.get("id") for a in meta.get("attack", []) if a.get("id")],
            "coincidencias": len(rule.get("matches", [])),
        })
    capabilities.sort(key=lambda c: (c["namespace"], c["nombre"]))
    return capabilities, None


def _category(namespace):
    for prefix, rule_id in CAPA_CATEGORIES:
        if namespace == prefix.rstrip("/") or namespace.startswith(prefix):
            return rule_id
    return None


def _findings(capabilities):
    grouped = {}
    for cap in capabilities:
        rule_id = _category(cap["namespace"])
        if rule_id:
            grouped.setdefault(rule_id, []).append(cap)

    findings = []
    for rule_id, caps in grouped.items():
        rule = BINARY_RULES[rule_id]
        attack = sorted({a for c in caps for a in c["attack"]})
        detalle = "; ".join(c["nombre"] for c in caps)
        if attack:
            detalle += f" [ATT&CK {', '.join(attack[:4])}]"
        findings.append({
            "line": 0,
            "rule_id": rule_id,
            "regla": rule["titulo"],
            "severidad": rule["severidad"],
            "peso": SEVERITY_SCORE[rule["severidad"]],
            "mitre_id": rule["mitre"][0],
            "mitre_name": rule["mitre"][1],
            "detalle": detalle[:MAX_SNIPPET_LEN * 2],
        })
    return findings


def _cache_path(sha256):
    return ANALYSIS_CACHE_DIR / f"capa_{sha256}.json"


def _load_cache(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("version") != CACHE_VERSION:
        return None
    return data.get("capacidades")


def _save_cache(path, capabilities):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": CACHE_VERSION, "capacidades": capabilities},
                                   ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
