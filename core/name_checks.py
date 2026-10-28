from pathlib import Path

from config import BINARY_RULES, SEVERITY_SCORE

RTL_OVERRIDE = "\u202e"

EXEC_EXTS = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".js", ".jse", ".vbs", ".vbe",
             ".wsf", ".hta", ".lnk", ".msi", ".jar", ".cpl", ".pif"}
LURE_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt",
             ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4"}


def check(path):
    name = Path(path).name
    findings = []
    if RTL_OVERRIDE in name:
        findings.append(make_finding("rtl_override", f"carácter U+202E en el nombre: {name!r}"))
    parts = name.lower().split(".")
    if len(parts) >= 3 and "." + parts[-1] in EXEC_EXTS and "." + parts[-2] in LURE_EXTS:
        findings.append(make_finding("double_extension",
                                     f"«.{parts[-2]}.{parts[-1]}» oculta un ejecutable"))
    return findings


def make_finding(rule_id, detalle):
    rule = BINARY_RULES[rule_id]
    return {
        "line": 0,
        "rule_id": rule_id,
        "regla": rule["titulo"],
        "severidad": rule["severidad"],
        "peso": SEVERITY_SCORE[rule["severidad"]],
        "mitre_id": rule["mitre"][0],
        "mitre_name": rule["mitre"][1],
        "detalle": detalle,
    }
