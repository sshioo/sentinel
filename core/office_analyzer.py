import io
import zipfile
from pathlib import Path

from config import (
    BINARY_RULES,
    MAX_SNIPPET_LEN,
    SEVERITY_SCORE,
    VBA_AUTOEXEC,
    VBA_DOWNLOAD,
    VBA_OBFUSCATION,
    VBA_SHELL,
)
from core.scoring import estado_from_score, weighted_score

try:
    from oletools.olevba import VBA_Parser
    _HAVE_OLETOOLS = True
except ImportError:
    _HAVE_OLETOOLS = False


ZIP_OFFICE_EXT = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
OLE_OFFICE_EXT = {".doc", ".xls", ".ppt", ".msi"}


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


def is_office(path):
    return Path(path).suffix.lower() in (ZIP_OFFICE_EXT | OLE_OFFICE_EXT)


def analyze_office(path):
    path = Path(path)
    if not _HAVE_OLETOOLS:
        return {"score": 0, "estado": "pendiente", "findings": [],
                "error": "oletools no instalado", "engine": "office"}

    findings = []
    has_vba_project = False
    ext = path.suffix.lower()

    if ext in ZIP_OFFICE_EXT:
        has_vba_project = _zip_has_vbaproject(path)
        if has_vba_project:
            findings.append(_finding("vba_macro", "vbaProject.bin presente en el paquete OOXML"))

    macros = _extract_macros(path)
    if macros:
        if not has_vba_project:
            findings.append(_finding("vba_macro", f"{len(macros)} macro(s) VBA"))
        findings.extend(_scan_macro_source(macros))

    score = weighted_score(findings)
    return {
        "score": score,
        "estado": estado_from_score(score, findings),
        "findings": findings,
        "error": None,
        "engine": "office",
        "meta": {"has_vba_project": has_vba_project, "macros": len(macros)},
    }


def _zip_has_vbaproject(path):
    try:
        with zipfile.ZipFile(path) as zf:
            return any("vbaProject.bin" in name for name in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


def _extract_macros(path):
    sources = []
    try:
        parser = VBA_Parser(str(path))
        if parser.detect_vba_macros():
            for _fname, _stream, _vba_name, code in parser.extract_macros():
                if code:
                    sources.append(code)
        parser.close()
    except Exception:
        return sources
    return sources


def _scan_macro_source(sources):
    findings = []
    combined = "\n".join(sources)
    lowered = combined.lower()

    for name in VBA_AUTOEXEC:
        if name.lower() in lowered:
            findings.append(_finding("vba_autoexec", f"rutina {name}"))
            break

    for token in VBA_SHELL:
        if token.lower() in lowered:
            findings.append(_finding("vba_shell", f"llamada {token}"))
            break

    for token in VBA_DOWNLOAD:
        if token in lowered:
            findings.append(_finding("vba_download", f"descarga vía {token}"))
            break

    hits = [t for t in VBA_OBFUSCATION if t in lowered]
    if hits:
        findings.append(_finding("vba_obfuscation", ", ".join(hits)))

    return findings
