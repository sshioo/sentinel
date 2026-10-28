from pathlib import Path

from config import (
    BINARY_RULES,
    ENTROPY_SECTION_HIGH,
    MAX_SNIPPET_LEN,
    PE_DOWNLOAD_APIS,
    PE_EXEC_APIS,
    PE_FEW_IMPORTS,
    PE_HOLLOWING_STEPS,
    PE_HOOK_APIS,
    PE_INJECTION_STEPS,
    PE_KEYLOG_APIS,
    PE_NETWORK_APIS,
    PE_RESOLVER_APIS,
    PE_SUSPICIOUS_SECTIONS,
    SEVERITY_SCORE,
)
from core import signature
from core.binary_analyzer import shannon_entropy
from core.scoring import estado_from_score, weighted_score

try:
    import pefile
    _HAVE_PEFILE = True
except ImportError:
    _HAVE_PEFILE = False

try:
    import capstone
    _HAVE_CAPSTONE = True
except ImportError:
    _HAVE_CAPSTONE = False

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
ENTRY_BYTES = 96
ENTRY_INSNS = 16
SKIP_ENTROPY_SECTIONS = {".rsrc", ".reloc"}


def _finding(rule_id, detalle):
    rule = BINARY_RULES[rule_id]
    return {
        "line": 0,
        "rule_id": rule_id,
        "regla": rule["titulo"],
        "severidad": rule["severidad"],
        "peso": SEVERITY_SCORE[rule["severidad"]],
        "mitre_id": rule["mitre"][0],
        "mitre_name": rule["mitre"][1],
        "detalle": detalle[:MAX_SNIPPET_LEN],
    }


def is_pe(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def analyze_pe(path, check_signature=True):
    path = Path(path)
    if not _HAVE_PEFILE:
        return {"score": 0, "estado": "pendiente", "findings": [], "error": "pefile no instalado",
                "engine": "pe"}

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError as exc:
        return {"score": 0, "estado": "pendiente", "findings": [], "error": str(exc),
                "engine": "pe"}

    findings = []
    try:
        names = _imports(pe)
        apis = _normalize(names)
        dotnet = _is_dotnet(pe)
        sections, ep_section = _sections(pe, findings)
        entry, entry_note = _entry(pe, ep_section, findings)
        machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    finally:
        pe.close()

    _import_behaviour(apis, names, dotnet, entry["rva"], findings)

    sig = signature.check(path) if check_signature else {"status": "NoComprobada"}
    if signature.is_tampered(sig):
        findings.append(_finding("pe_bad_signature",
                                 f"estado {sig['status']}: el archivo cambió después de firmarse"))

    score = weighted_score(findings)
    return {
        "score": score,
        "estado": estado_from_score(score, findings),
        "findings": findings,
        "error": None,
        "engine": "pe",
        "meta": {
            "arquitectura": machine.replace("IMAGE_FILE_MACHINE_", ""),
            "tipo": "DLL" if is_dll else "EXE",
            "dotnet": dotnet,
            "firma": sig,
            "imports": sorted(names)[:80],
            "count": len(names),
            "sections": sections,
            "entry_point": entry,
            "entry_note": entry_note,
        },
    }


def _imports(pe):
    names = set()
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                         pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
    except Exception:
        return names
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name:
                names.add(imp.name.decode("latin-1", errors="replace"))
    return names


def _normalize(names):
    out = set(names)
    out.update(n[:-1] for n in names if len(n) > 2 and n[-1] in "AW" and n[-2].islower())
    return out


def _is_dotnet(pe):
    try:
        com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
        return com.VirtualAddress != 0
    except (IndexError, AttributeError):
        return False


def _sections(pe, findings):
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = None
    meta = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
        flags = section.Characteristics
        executable = bool(flags & IMAGE_SCN_MEM_EXECUTE)
        writable = bool(flags & IMAGE_SCN_MEM_WRITE)
        ent = shannon_entropy(section.get_data())
        meta.append({"name": name, "entropy": round(ent, 3), "size": section.SizeOfRawData,
                     "perm": ("R" + ("W" if writable else "-") + ("X" if executable else "-"))})
        if ep and section.contains_rva(ep):
            ep_section = (section, name, executable, writable)
        if name.lower() in PE_SUSPICIOUS_SECTIONS:
            findings.append(_finding("pe_suspicious_section", f"sección {name}"))
        if (ent >= ENTROPY_SECTION_HIGH and section.SizeOfRawData > 512
                and name.lower() not in SKIP_ENTROPY_SECTIONS):
            findings.append(_finding("pe_high_entropy_section", f"{name} entropía {ent:.2f}"))
        if executable and writable and section.SizeOfRawData > 0:
            findings.append(_finding("pe_wx_section", f"{name} es RWX"))

    if ep:
        if ep_section is None:
            findings.append(_finding("pe_entry_anomaly",
                                     f"el punto de entrada 0x{ep:x} no cae en ninguna sección"))
        elif not ep_section[2]:
            findings.append(_finding("pe_entry_anomaly",
                                     f"el punto de entrada está en {ep_section[1]}, que no es ejecutable"))
        elif ep_section[3] and ep_section[0] is pe.sections[-1] and len(pe.sections) > 1:
            findings.append(_finding("pe_entry_anomaly",
                                     f"el punto de entrada está en la última sección ({ep_section[1]}), escribible"))
    return meta, ep_section


def _entry(pe, ep_section, findings):
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    info = {"rva": ep, "section": ep_section[1] if ep_section else None, "disasm": []}
    if not ep or not _HAVE_CAPSTONE:
        return info, None if ep else "sin punto de entrada (DLL de solo recursos)"

    try:
        code = pe.get_data(ep, ENTRY_BYTES)
    except Exception:
        return info, "no se pudo leer el punto de entrada"

    mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    base = pe.OPTIONAL_HEADER.ImageBase + ep
    insns = list(md.disasm(code, base))[:ENTRY_INSNS]
    info["disasm"] = [f"0x{i.address:x}  {i.mnemonic} {i.op_str}".rstrip() for i in insns]

    stub = _entry_stub(pe, insns, ep_section)
    if stub:
        findings.append(_finding("pe_entry_stub", stub))
    return info, stub


def _entry_stub(pe, insns, ep_section):
    if not insns:
        return None
    if insns[0].mnemonic in ("pushal", "pushad"):
        return "arranca con pushad: guarda los registros antes de descomprimir (UPX y similares)"
    for i, insn in enumerate(insns[:6]):
        if insn.mnemonic == "call" and insn.op_str == hex(insn.address + insn.size):
            nxt = insns[i + 1] if i + 1 < len(insns) else None
            if nxt is not None and nxt.mnemonic == "pop":
                return "call $+5 seguido de pop: el código calcula su propia dirección (shellcode)"
    if ep_section:
        section = ep_section[0]
        lo = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        hi = lo + max(section.Misc_VirtualSize, section.SizeOfRawData)
        for insn in insns[:3]:
            if insn.mnemonic == "jmp" and insn.op_str.startswith("0x"):
                target = int(insn.op_str, 16)
                if not lo <= target < hi:
                    return f"salta de inmediato a 0x{target:x}, fuera de la sección de entrada"
    return None


def _import_behaviour(apis, names, dotnet, ep, findings):
    for rule_id, steps in (("pe_injection", PE_INJECTION_STEPS), ("pe_hollowing", PE_HOLLOWING_STEPS)):
        if all(apis & step for step in steps):
            hit = sorted(set().union(*(apis & step for step in steps)))
            findings.append(_finding(rule_id, " → ".join(hit)))
    if apis & PE_KEYLOG_APIS and (apis & PE_HOOK_APIS or apis & PE_NETWORK_APIS):
        findings.append(_finding("pe_keylogger", ", ".join(sorted(
            apis & (PE_KEYLOG_APIS | PE_HOOK_APIS | PE_NETWORK_APIS)))))
    if apis & PE_DOWNLOAD_APIS and apis & PE_EXEC_APIS:
        findings.append(_finding("pe_downloader", ", ".join(sorted(apis & (PE_DOWNLOAD_APIS | PE_EXEC_APIS)))))
    if dotnet:
        return
    if not names and ep:
        findings.append(_finding("pe_no_imports", "sin imports resueltos"))
    elif names and len(names) <= PE_FEW_IMPORTS and apis & PE_RESOLVER_APIS:
        findings.append(_finding("pe_dynamic_resolution",
                                 f"{len(names)} imports, entre ellos {', '.join(sorted(apis & PE_RESOLVER_APIS))}"))
