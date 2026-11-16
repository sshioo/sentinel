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
    static_re,
    yara_scanner,
)
from core.scoring import attenuate_trusted, estado_from_score, finalize, reasons, weighted_score

# Motores cuyo fallo deja el veredicto a medias. VirusTotal y capa son
# opcionales: sin clave o sin reglas no se considera un análisis incompleto.
CORE_ENGINES = {"binary", "ingenieria_inversa", "yara", "pe", "pdf", "office", "archivo", "nombre"}


def _safe(engine, fn, *args, **kwargs):
    """Un motor que falla no puede tumbar a los demás ni dejar el archivo como «seguro»."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - RecursionError, MemoryError, errores de librerías
        return {"engine": engine, "score": 0, "estado": "pendiente", "findings": [],
                "error": f"fallo interno ({type(exc).__name__}): {str(exc)[:120]}"}


def analyze_binary(path, online=True, deep=True):
    """Ejecuta todos los motores aplicables y fusiona resultados.

    deep=False omite capa, que tarda de segundos a minutos por ejecutable.
    """
    path = Path(path)
    results = []

    base = _safe("binary", binary_analyzer.analyze_binary, path)
    results.append(base)
    magic = tuple((base.get("meta") or {}).get("magic") or ())
    is_pe = pe_analyzer.is_pe(path)
    # Ingeniería inversa primero: estructura, ejecutables ocultos, cargas
    # codificadas, shellcode y cadenas. Es el núcleo del veredicto.
    results.append(_safe("ingenieria_inversa", static_re.analyze, path, magic, is_pe, deep))
    results.append(_safe("yara", yara_scanner.scan, path))
    results.append(_safe("nombre", lambda: {"engine": "nombre", "score": 0, "estado": "limpio",
                                            "findings": name_checks.check(path), "error": None}))

    if _safe("archivo", archive_analyzer.is_zip, path) is True:
        results.append(_safe("archivo", archive_analyzer.analyze_archive, path))

    sig = None
    if is_pe:
        pe = _safe("pe", pe_analyzer.analyze_pe, path)
        results.append(pe)
        sig = (pe.get("meta") or {}).get("firma")
        if deep and not pe.get("error"):
            results.append(_safe("capa", reverse_engineer.analyze,
                                 path, (base.get("meta") or {}).get("sha256", ""), _capa_skip(sig)))

    if office_analyzer.is_office(path):
        results.append(_safe("office", office_analyzer.analyze_office, path))

    if pdf_analyzer.is_pdf(path):
        results.append(_safe("pdf", pdf_analyzer.analyze_pdf, path))

    if online:
        results.append(_safe("virustotal", _virustotal, path))

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
    incomplete = False
    meta = {}
    for r in results:
        engine = r.get("engine", "?")
        engines.append(engine)
        for f in r.get("findings", []):
            f.setdefault("motor", engine)
            findings.append(f)
        if r.get("error"):
            errors.append(f"{engine}: {r['error']}")
            incomplete = incomplete or engine in CORE_ENGINES
        if r.get("meta"):
            meta[engine] = r["meta"]

    findings = finalize(findings)
    if sig and signature.is_trusted(sig):
        attenuate_trusted(findings, sig.get("signer") or "firmante desconocido", sig.get("os", False))
    score = weighted_score(findings)
    estado = estado_from_score(score, findings)
    # Fallar abierto sería declarar «seguro» un archivo que no se pudo revisar.
    if incomplete and estado == "limpio":
        estado = "pendiente"
    return {
        "score": score,
        "estado": estado,
        "findings": findings,
        "razones": reasons(findings),
        "engine": "multi:" + "+".join(engines),
        "errors": errors,
        "incomplete": incomplete,
        "meta": meta,
    }
