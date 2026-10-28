from pathlib import Path

from core import (
    archive_analyzer,
    binary_analyzer,
    name_checks,
    office_analyzer,
    pdf_analyzer,
    pe_analyzer,
    reverse_engineer,
    signature,
    yara_scanner,
)
from core.scoring import attenuate_trusted, estado_from_score, finalize, weighted_score

ZIP_OFFICE_EXT = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
OLE_OFFICE_EXT = {".doc", ".xls", ".ppt", ".msi"}


def analyze_binary(path, online=True, deep=True):
    """Ejecuta todos los motores aplicables y fusiona resultados.

    deep=False omite capa, que tarda de segundos a minutos por ejecutable.
    """
    path = Path(path)
    results = []

    base = binary_analyzer.analyze_binary(path)
    results.append(base)
    results.append(yara_scanner.scan(path))
    results.append({"engine": "nombre", "score": 0, "estado": "limpio",
                    "findings": name_checks.check(path), "error": None})

    if archive_analyzer.is_zip(path):
        results.append(archive_analyzer.analyze_archive(path))

    ext = path.suffix.lower()
    sig = None
    if pe_analyzer.is_pe(path):
        pe = pe_analyzer.analyze_pe(path)
        results.append(pe)
        sig = (pe.get("meta") or {}).get("firma")
        if deep and not pe.get("error"):
            results.append(reverse_engineer.analyze(
                path, (base.get("meta") or {}).get("sha256", ""), _capa_skip(sig)))

    if ext in (ZIP_OFFICE_EXT | OLE_OFFICE_EXT):
        results.append(office_analyzer.analyze_office(path))

    if pdf_analyzer.is_pdf(path):
        results.append(pdf_analyzer.analyze_pdf(path))

    if online:
        results.append(_virustotal(path))

    return _merge(results, sig)


def _capa_skip(sig):
    # Los binarios del propio Windows firmados por Microsoft no necesitan
    # desensamblarse: su firma ya prueba el origen y capa tardaría medio minuto.
    if sig and signature.is_trusted(sig) and sig.get("os"):
        return f"binario del sistema firmado por {sig.get('signer') or 'Microsoft'}"
    return None


def _virustotal(path):
    try:
        from engines import virustotal
    except ImportError as exc:
        return {"score": 0, "estado": "pendiente", "findings": [],
                "error": f"engine online no disponible: {exc}", "engine": "virustotal"}

    return virustotal.scan(sha256=_sha256(path), path=path)


def _sha256(path):
    from core.binary_analyzer import hashes
    return hashes(path)["sha256"]


def _merge(results, sig=None):
    findings = []
    engines = []
    errors = []
    meta = {}
    for r in results:
        engine = r.get("engine", "?")
        engines.append(engine)
        findings.extend(r.get("findings", []))
        if r.get("error"):
            errors.append(f"{engine}: {r['error']}")
        if r.get("meta"):
            meta[engine] = r["meta"]

    findings = finalize(findings)
    if sig and signature.is_trusted(sig):
        attenuate_trusted(findings, sig.get("signer") or "firmante desconocido", sig.get("os", False))
    score = weighted_score(findings)
    estado = estado_from_score(score, findings)
    return {
        "score": score,
        "estado": estado,
        "findings": findings,
        "engine": "multi:" + "+".join(engines),
        "errors": errors,
        "meta": meta,
    }
