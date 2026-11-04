import zipfile
from pathlib import Path

from core import name_checks

MAX_MEMBERS = 2000
MAX_FINDINGS = 25


def is_zip(path):
    with open(path, "rb") as fh:
        return fh.read(4) in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _escapes_folder(member):
    name = member.replace("\\", "/")
    return name.startswith("/") or (len(name) > 1 and name[1] == ":") or ".." in name.split("/")


def analyze_archive(path):
    try:
        with zipfile.ZipFile(path) as zf:
            members = zf.infolist()[:MAX_MEMBERS]
    except (zipfile.BadZipFile, OSError) as exc:
        return {"engine": "archivo", "score": 0, "estado": "limpio",
                "findings": [], "error": str(exc)}

    findings = []
    if any(info.flag_bits & 0x1 for info in members):
        findings.append(name_checks.make_finding(
            "archive_encrypted", "el paquete pide contraseña: no se puede ver qué contiene"))
    for info in members:
        if len(findings) >= MAX_FINDINGS:
            break
        member = info.filename
        if _escapes_folder(member):
            findings.append(name_checks.make_finding(
                "archive_traversal", f"{member}: al extraerlo escribiría fuera de la carpeta"))
        base = member.replace("\\", "/").rsplit("/", 1)[-1]
        if Path(base).suffix.lower() in name_checks.EXEC_EXTS:
            findings.append(name_checks.make_finding(
                "archive_executable", f"{member} dentro del contenedor"))
        for f in name_checks.check(base):
            f["detalle"] = f"{member}: {f['detalle']}"
            findings.append(f)

    return {"engine": "archivo", "score": 0, "estado": "limpio",
            "findings": findings[:MAX_FINDINGS], "error": None,
            "meta": {"miembros": len(members)}}
