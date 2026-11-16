"""Ingeniería inversa estática de cualquier archivo, sin ejecutarlo.

Es el paso central del escaneo. Desmonta el archivo como lo haría un analista:

1. Estructura: dónde termina de verdad el formato y qué hay pegado detrás
   (datos «overlay» tras el fin de un JPEG, PNG, PDF o ZIP).
2. Tallado (carving): ejecutables PE escondidos dentro del archivo, también
   cifrados con XOR de un byte, la ofuscación más común en droppers.
3. Decodificación: bloques base64 y hex largos, incluido el
   `powershell -EncodedCommand` (UTF-16LE). Lo decodificado se vuelve a
   inspeccionar: un PE en base64 dentro de un script es un dropper.
4. Shellcode: arranques conocidos (stub de Metasploit, acceso al PEB por
   fs:[0x30] / gs:[0x60]) fuera de un ejecutable.
5. Cadenas: API de inyección, espionaje y descarga, claves de persistencia,
   comprobaciones anti-VM y notas de rescate.

Los PE tallados pasan por el analizador de ejecutables y por capa, de modo que
un .exe oculto en una foto se desensambla igual que uno suelto.
"""
import base64
import binascii
import os
import re
import tempfile
from pathlib import Path

from config import BINARY_RULES, MAX_SNIPPET_LEN, SEVERITY_SCORE

RE_SCAN_LIMIT = 32 * 1024 * 1024
XOR_SCAN_LIMIT = 4 * 1024 * 1024
MAX_CARVED = 3
MIN_B64 = 160
MIN_HEX = 200
MAX_DECODE_BLOBS = 40

_DOS_STUB = b"This program cannot be run in DOS mode"
_B64_RE = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_B64)
_HEX_RE = re.compile(rb"(?:[0-9A-Fa-f]{2}){%d,}" % (MIN_HEX // 2))
_ENC_CMD_RE = re.compile(rb"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/]{40,}={0,2})", re.I)
_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

# Cadenas que delatan capacidades. Se buscan por grupos; cada grupo es una regla.
API_GROUPS = {
    "inyección en procesos": ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                              "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
                              "NtWriteVirtualMemory", "RtlCreateUserThread"),
    "espionaje de teclado/pantalla": ("GetAsyncKeyState", "SetWindowsHookEx", "GetKeyboardState",
                                      "BitBlt", "GetClipboardData"),
    "descarga y ejecución": ("URLDownloadToFile", "InternetOpenUrl", "WinHttpOpen", "ShellExecute",
                             "WinExec", "CreateProcess"),
    "robo de credenciales": ("CryptUnprotectData", "Login Data", "logins.json", "wallet.dat",
                             "LsaRetrievePrivateData", "sekurlsa"),
}
PERSISTENCE = (b"\\currentversion\\run", b"\\currentversion\\runonce", b"schtasks /create",
               b"\\start menu\\programs\\startup", b"winlogon\\shell", b"image file execution options")
ANTI_VM = (b"vboxservice", b"vboxtray", b"vmtoolsd", b"vmwaretray", b"sbiedll", b"wine_get_unix_file_name",
           b"isdebuggerpresent", b"checkremotedebuggerpresent", b"ollydbg", b"x64dbg", b"wireshark")
RANSOM = (b"your files have been encrypted", b"files are encrypted", b"bitcoin", b"decrypt your files",
          b"tor browser", b".onion", b"ransom", b"vssadmin delete shadows", b"wbadmin delete catalog",
          b"bcdedit /set {default} recoveryenabled no")
SCRIPT_MARKERS = (b"powershell", b"invoke-expression", b"iex(", b"wscript.shell", b"cmd.exe /c",
                  b"createobject(", b"frombase64string", b"downloadstring", b"<script", b"eval(",
                  b"exec(", b"/bin/sh", b"bash -i", b"subprocess", b"socket.socket(",
                  b"os.system(", b"start-process", b"net.webclient")

SHELLCODE = (
    (b"\xfc\xe8\x82\x00\x00\x00", "stub de Metasploit (x86)", True),
    (b"\xfc\x48\x83\xe4\xf0\xe8", "stub de Metasploit (x64)", True),
    (b"\x64\xa1\x30\x00\x00\x00", "lectura del PEB por fs:[0x30] (x86)", False),
    (b"\x64\x8b\x15\x30\x00\x00\x00", "lectura del PEB por fs:[0x30] (x86)", False),
    (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "lectura del PEB por gs:[0x60] (x64)", False),
)

# Dónde termina cada formato: lo que haya detrás es un «overlay».
_FORMAT_END = {
    "jpeg": (b"\xff\xd8\xff", b"\xff\xd9", 0),
    "png": (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 0),
    "gif": (b"GIF8", b"\x00;", 0),
    "pdf": (b"%PDF", b"%%EOF", 2),
}
OVERLAY_MIN = 1024


def _finding(rule_id, detalle, confianza=None, extra=None):
    rule = BINARY_RULES[rule_id]
    f = {
        "line": 0,
        "rule_id": rule_id,
        "regla": rule["titulo"],
        "severidad": rule["severidad"],
        "peso": SEVERITY_SCORE[rule["severidad"]],
        "mitre_id": rule["mitre"][0],
        "mitre_name": rule["mitre"][1],
        "detalle": detalle[:MAX_SNIPPET_LEN * 2],
    }
    if confianza:
        f["confianza"] = confianza
    if extra:
        f.update(extra)
    return f


def _valid_pe_at(data, off):
    """MZ seguido de una cabecera PE coherente: descarta los «MZ» casuales."""
    if data[off:off + 2] != b"MZ" or off + 0x40 > len(data):
        return False
    e_lfanew = int.from_bytes(data[off + 0x3C:off + 0x40], "little")
    if not 0x40 <= e_lfanew <= 0x400:
        return False
    return data[off + e_lfanew:off + e_lfanew + 4] == b"PE\x00\x00"


def _embedded_pes(data, start=1):
    found = []
    pos = data.find(b"MZ", start)
    while pos != -1 and len(found) < MAX_CARVED:
        if _valid_pe_at(data, pos):
            found.append(pos)
        pos = data.find(b"MZ", pos + 2)
    return found


def _xor_pes(data):
    """Busca el stub DOS cifrado con XOR de un byte y devuelve (clave, posición)."""
    window = data[:XOR_SCAN_LIMIT]
    for key in range(1, 256):
        needle = bytes(b ^ key for b in _DOS_STUB)
        pos = window.find(needle)
        if pos != -1:
            return key, pos
    return None


def _overlay(data, magic):
    for fam, (head, end, extra) in _FORMAT_END.items():
        if fam in magic and data.startswith(head):
            pos = data.rfind(end)
            if pos == -1:
                return None
            tail = pos + len(end) + extra
            rest = data[tail:].strip(b"\r\n\x00 ")
            if len(rest) >= OVERLAY_MIN:
                return fam, tail, len(rest)
    return None


def _strings(data):
    ascii_s = _ASCII_RE.findall(data)
    utf16_s = [s.replace(b"\x00", b"") for s in _UTF16_RE.findall(data)]
    return ascii_s + utf16_s


_CONCAT_RE = re.compile(rb"""['"]\s*[+&]\s*['"]""")
_CHR_RE = re.compile(rb"[Cc][Hh][Rr][Ww]?\s*\(\s*(?:&[Hh])?([0-9A-Fa-f]{1,3})\s*\)")
_DEOBF_MARKERS = ("downloadstring", "downloadfile", "downloaddata", "invoke-expression",
                  "iex", "invoke-webrequest", "wscript.shell", "shellexecute", "frombase64string",
                  "createobject", "powershell", "cmd.exe", "reverseshell", "start-process",
                  "regwrite", "vssadmin", "net.webclient", "scheduledtask", "schtasks")


def _deobfuscate(data):
    """Reconstruye lo que un script esconde a propósito, para poder buscarlo:
    - cadenas partidas por concatenación:  'Downl'+'oadStr'+'ing' -> DownloadString
    - caracteres por código:  Chr(87)&Chr(83) -> WS  (clásico en macros VBA/VBScript)
    Devuelve el texto reconstruido en minúsculas, o b'' si no había ofuscación."""
    out = []
    # Une los trozos entre comillas pegados por + o &.
    joined = _CONCAT_RE.sub(b"", data)
    if joined != data:
        out.append(joined)
    # Traduce las secuencias de Chr()/ChrW() a sus caracteres.
    chars = _CHR_RE.findall(data)
    if len(chars) >= 4:
        try:
            out.append(bytes(int(c, 16) if len(c) <= 2 and not c.isdigit()
                             else int(c) & 0xFF for c in chars))
        except ValueError:
            pass
    return b"\n".join(out).lower()


def _decode_blobs(data):
    """Decodifica bloques base64/hex largos. Devuelve [(tipo, offset, bytes)]."""
    out = []
    for m in _ENC_CMD_RE.finditer(data):
        try:
            raw = base64.b64decode(m.group(1) + b"=" * (-len(m.group(1)) % 4))
            out.append(("powershell -EncodedCommand", m.start(), raw.decode("utf-16-le", "ignore").encode()))
        except (binascii.Error, ValueError):
            pass
    for m in _B64_RE.finditer(data):
        if len(out) >= MAX_DECODE_BLOBS:
            break
        blob = m.group(0)
        if len(set(blob)) < 16:  # «AAAA…» no es un payload
            continue
        try:
            raw = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        out.append(("base64", m.start(), raw))
    for m in _HEX_RE.finditer(data):
        if len(out) >= MAX_DECODE_BLOBS:
            break
        try:
            out.append(("hex", m.start(), bytes.fromhex(m.group(0).decode())))
        except ValueError:
            continue
    return out


def _looks_textual(raw):
    if not raw:
        return False
    sample = raw[:2048]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.85


def analyze(path, magic=(), is_pe=False, deep=True):
    """Ingeniería inversa del archivo. Devuelve el formato de motor de pipeline."""
    path = Path(path)
    base = {"engine": "ingenieria_inversa", "score": 0, "estado": "limpio", "findings": [],
            "error": None}
    try:
        with open(path, "rb") as fh:
            data = fh.read(RE_SCAN_LIMIT)
    except OSError as exc:
        return {**base, "error": str(exc)}

    findings, steps, carved = [], [], []
    lower = data.lower()

    # 1. Estructura y overlay.
    ov = _overlay(data, magic)
    if ov:
        fam, off, size = ov
        steps.append(f"estructura {fam.upper()}: {size} bytes añadidos tras el fin del formato (0x{off:x})")
        findings.append(_finding("re_overlay", f"{size} bytes tras el fin del {fam.upper()} en 0x{off:x}"))
    else:
        steps.append("estructura: el contenido termina donde dice el formato")

    # 2. Tallado de PE embebidos (en claro y con XOR de un byte).
    # El PE que empieza en 0 ya lo analiza el motor de ejecutables.
    pes = _embedded_pes(data, start=1)
    for off in pes:
        carved.append(("en claro", off, data[off:]))
        findings.append(_finding(
            "re_dropper_pe" if is_pe else "re_embedded_pe",
            f"cabecera PE válida en el desplazamiento 0x{off:x}"))
    xor = None if pes else _xor_pes(data)
    if xor:
        key, pos = xor
        decoded = bytes(b ^ key for b in data)
        start = decoded.rfind(b"MZ", 0, pos)
        if start != -1:
            carved.append((f"XOR 0x{key:02x}", start, decoded[start:]))
        findings.append(_finding("re_xor_pe", f"ejecutable cifrado con XOR clave 0x{key:02x} "
                                              f"(stub DOS en 0x{pos:x})"))
    if not pes and not xor:
        steps.append("tallado: sin ejecutables ocultos (en claro ni con XOR de un byte)")
    else:
        steps.append(f"tallado: {len(carved)} ejecutable(s) oculto(s) extraído(s)")

    # 3. Decodificación de bloques codificados.
    blobs = _decode_blobs(data)
    decoded_hits = 0
    for kind, off, raw in blobs:
        if raw[:2] == b"MZ":
            decoded_hits += 1
            findings.append(_finding("re_encoded_pe", f"PE codificado en {kind} en 0x{off:x}"))
            if _valid_pe_at(raw, 0):
                carved.append((kind, off, raw))
        elif _looks_textual(raw):
            low = raw.lower()
            hits = sorted({m.decode() for m in SCRIPT_MARKERS if m in low})
            if hits:
                decoded_hits += 1
                snippet = raw[:90].decode("utf-8", "replace").replace("\n", " ")
                # Varias órdenes de ejecución escondidas a propósito: eso es un loader.
                findings.append(_finding(
                    "re_encoded_script",
                    f"{kind} en 0x{off:x} oculta código ({', '.join(hits[:4])}): «{snippet}»",
                    confianza="alta" if len(hits) >= 2 else None))
    steps.append(f"decodificación: {len(blobs)} bloque(s) codificado(s), {decoded_hits} con carga oculta"
                 if blobs else "decodificación: sin bloques base64/hex largos")

    # 4. Shellcode fuera de un ejecutable.
    if not is_pe:
        for pattern, label, strong in SHELLCODE:
            pos = data.find(pattern)
            if pos != -1:
                findings.append(_finding("re_shellcode", f"{label} en 0x{pos:x}",
                                         confianza="alta" if strong else "media"))
                steps.append(f"shellcode: {label}")
                break

    # 4b. Desofuscación de scripts: reconstruye cadenas partidas y Chr() y busca en ellas.
    #     Solo en archivos de texto: un PDF o una imagen traen "+" y "Chr(" por azar.
    deob = _deobfuscate(data) if _looks_textual(data) else b""
    # Solo cuenta lo que aparece TRAS reconstruir y no estaba ya entero: eso es
    # ocultación deliberada. El código normal escribe "cmd.exe" de una pieza.
    orig_l = data.lower()
    deob_hits = sorted({m for m in _DEOBF_MARKERS
                        if m.encode() in deob and m.encode() not in orig_l})
    if deob_hits:
        steps.append(f"desofuscación: cadenas ocultas reconstruidas ({', '.join(deob_hits[:5])})")
        dl = any(h.encode() in deob for h in ("downloadstring", "downloadfile", "downloaddata",
                                              "invoke-webrequest", "net.webclient"))
        ex = any(h.encode() in deob for h in ("invoke-expression", "iex", "shellexecute",
                                              "wscript.shell", "start-process", "cmd.exe", "powershell"))
        strong = dl and ex
        findings.append(_finding(
            "re_deobfuscated",
            "el script arma cadenas ocultas (concatenación o Chr()) que forman: "
            + ", ".join(deob_hits[:6]),
            confianza="alta" if strong else "media"))

    # 5. Cadenas.
    strings = _strings(data)
    blob = b"\n".join(strings)
    blob_l = blob.lower()
    caps = []
    for group, apis in API_GROUPS.items():
        hit = [a for a in apis if a.encode().lower() in blob_l]
        if len(hit) >= 2:
            caps.append(f"{group}: {', '.join(hit[:5])}")
            # En un PE ya las valoran pefile y capa; aquí cuentan fuera de un ejecutable.
            if not is_pe:
                findings.append(_finding("re_api_strings",
                                         f"nombres de API de {group} en un archivo que no es un programa: "
                                         f"{', '.join(hit[:5])}"))
    persist = [p.decode() for p in PERSISTENCE if p in blob_l]
    if persist:
        caps.append(f"persistencia: {', '.join(persist[:3])}")
        findings.append(_finding("re_persistence_strings", ", ".join(persist[:3])))
    antivm = [p.decode() for p in ANTI_VM if p in blob_l]
    if len(antivm) >= 2:
        caps.append(f"evasión de análisis: {', '.join(antivm[:4])}")
        findings.append(_finding("re_antianalysis_strings", ", ".join(antivm[:4])))
    ransom = [p.decode() for p in RANSOM if p in lower]
    if len(ransom) >= 2:
        caps.append(f"extorsión: {', '.join(ransom[:4])}")
        findings.append(_finding("re_ransom_strings", ", ".join(ransom[:4]),
                                 confianza="alta" if len(ransom) >= 3 else None))
    steps.append(f"cadenas: {len(strings)} extraídas, {len(caps)} grupo(s) de capacidades")

    # 6. Los PE tallados se analizan y desensamblan como si fueran sueltos.
    carved_meta = []
    for how, off, payload in carved[:MAX_CARVED]:
        info = {"origen": how, "offset": off, "bytes": len(payload)}
        sub = _analyze_carved(payload, deep)
        for f in sub["findings"]:
            f = dict(f)
            f["detalle"] = f"[PE oculto @0x{off:x}] {f.get('detalle', '')}"[:MAX_SNIPPET_LEN * 2]
            findings.append(f)
        info["capacidades"] = sub["capacidades"]
        info["errores"] = sub["errores"]
        carved_meta.append(info)
        steps.append(f"PE oculto @0x{off:x} ({how}): desensamblado, {len(sub['findings'])} hallazgo(s)")

    return {**base, "findings": findings,
            "meta": {"pasos": steps, "capacidades": caps, "tallados": carved_meta,
                     "cadenas": len(strings), "bloques": len(blobs)}}


def _analyze_carved(payload, deep):
    from core import pe_analyzer, reverse_engineer
    from core.binary_analyzer import hashes

    out = {"findings": [], "capacidades": [], "errores": []}
    fd, tmp = tempfile.mkstemp(prefix="sentinel-carved-", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        try:
            pe = pe_analyzer.analyze_pe(tmp, check_signature=False)
            out["findings"].extend(pe.get("findings", []))
            if pe.get("error"):
                out["errores"].append(f"pe: {pe['error']}")
        except Exception as exc:  # noqa: BLE001 - un PE tallado puede estar truncado
            out["errores"].append(f"pe: {type(exc).__name__}")
        if deep and reverse_engineer.available():
            capa = reverse_engineer.analyze(tmp, hashes(tmp)["sha256"])
            out["findings"].extend(capa.get("findings", []))
            out["capacidades"] = [c["nombre"] for c in (capa.get("meta") or {}).get("capacidades", [])][:40]
            if capa.get("error"):
                out["errores"].append(f"capa: {capa['error']}")
    finally:
        Path(tmp).unlink(missing_ok=True)
    return out
