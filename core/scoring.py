from config import (
    AST_RULES,
    BAJA_CAP,
    BINARY_RULES,
    COMPOUND_RULES,
    CONFIDENCE_FACTOR,
    RULE_CONFIDENCE,
    SCORE_SATURATION,
    SEVERITY_SCORE,
    TRUST_OVERRIDE,
    VERDICT_ALERT_SCORE,
    VERDICT_REVIEW_SCORE,
)

_ALL_RULES = {**AST_RULES, **BINARY_RULES}
_DOWNGRADE = {"alta": "media", "media": "baja", "baja": "baja"}
_STRONG_SEVERITY = {"alto", "crítico"}


def confidence(finding):
    return finding.get("confianza") or RULE_CONFIDENCE.get(finding.get("rule_id"), "media")


def finalize(findings):
    """Añade las reglas compuestas y fija la confianza de cada hallazgo."""
    present = {f.get("rule_id") for f in findings}
    compounds = []
    for needed, rule_id, detalle in COMPOUND_RULES:
        if needed <= present and rule_id not in present:
            rule = _ALL_RULES[rule_id]
            compounds.append({
                "line": 0,
                "rule_id": rule_id,
                "regla": rule["titulo"],
                "severidad": rule["severidad"],
                "peso": SEVERITY_SCORE[rule["severidad"]],
                "mitre_id": rule["mitre"][0],
                "mitre_name": rule["mitre"][1],
                "detalle": detalle,
            })
            present.add(rule_id)
    out = findings + compounds
    for f in out:
        f["confianza"] = confidence(f)
    return out


def attenuate_trusted(findings, signer, os_binary=False):
    """Una firma Authenticode válida baja un escalón la confianza de cada hallazgo.

    Un binario del propio Windows (firmado por catálogo) baja hasta "baja":
    kernel32.dll importa las API de inyección porque es quien las implementa.
    """
    for f in findings:
        if f.get("rule_id") in TRUST_OVERRIDE or f.get("atenuado"):
            continue
        f["confianza"] = "baja" if os_binary else _DOWNGRADE[confidence(f)]
        f["atenuado"] = f"firma válida: {signer}"
    return findings


def _weight(f):
    return (f.get("peso") or SEVERITY_SCORE.get(f.get("severidad"), 6)) * CONFIDENCE_FACTOR[confidence(f)]


def weighted_score(findings):
    if not findings:
        return 0
    findings = finalize(list(findings))
    # Cada regla cuenta una vez: cien getattr no son cien indicios distintos.
    best = {}
    for f in findings:
        key = f.get("rule_id") or f.get("regla")
        best[key] = max(best.get(key, 0.0), _weight(f))
    low = sum(w for k, w in best.items() if _conf_of(findings, k) == "baja")
    weights = sorted((w for k, w in best.items() if _conf_of(findings, k) != "baja"), reverse=True)
    if low:
        weights = sorted(weights + [min(low, BAJA_CAP)], reverse=True)
    total = weights[0] + sum(w * 0.6 for w in weights[1:])
    return max(0, min(100, int(round(total / (total + SCORE_SATURATION) * 100))))


def _conf_of(findings, key):
    levels = [confidence(f) for f in findings if (f.get("rule_id") or f.get("regla")) == key]
    for level in ("alta", "media", "baja"):
        if level in levels:
            return level
    return "media"


def estado_from_score(score, findings):
    """Veredicto por evidencia.

    alerta: una prueba fuerte (confianza alta y severidad alta o crítica), o un
    score alto apoyado en al menos dos indicios distintos que no sean débiles.
    pendiente: algún indicio de confianza media o un score intermedio.
    limpio: no hay hallazgos o solo hay señales débiles.
    """
    if not findings:
        return "limpio"
    findings = finalize(list(findings))
    if any(confidence(f) == "alta" and f.get("severidad") in _STRONG_SEVERITY for f in findings):
        return "alerta"
    solid = {f.get("rule_id") or f.get("regla") for f in findings if confidence(f) != "baja"}
    if score >= VERDICT_ALERT_SCORE and len(solid) >= 2:
        return "alerta"
    if solid or score >= VERDICT_REVIEW_SCORE:
        return "pendiente"
    return "limpio"


def verdict(findings):
    findings = finalize(findings)
    score = weighted_score(findings)
    return findings, score, estado_from_score(score, findings)
