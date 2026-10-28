import hashlib
import math
from collections import Counter
from pathlib import Path

from config import (
    BINARY_RULES,
    ENTROPY_BLOCK_SIZE,
    ENTROPY_EXEMPT_FAMILIES,
    ENTROPY_HIGH,
    ENTROPY_SCAN_LIMIT,
    EXTENSION_FAMILY,
    MAGIC_SIGNATURES,
    MAX_SNIPPET_LEN,
    SEVERITY_SCORE,
)
from core.scoring import estado_from_score, weighted_score


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def hashes(path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def detect_magic(head):
    matches = []
    for family, sigs in MAGIC_SIGNATURES.items():
        for offset, magic in sigs:
            if head[offset:offset + len(magic)] == magic:
                matches.append(family)
                break
    return matches


def expected_families(path):
    ext = Path(path).suffix.lower()
    fam = EXTENSION_FAMILY.get(ext)
    return [fam] if fam else []


class _Finding:
    def __init__(self, rule_id, line, detalle):
        rule = BINARY_RULES[rule_id]
        self.data = {
            "line": line,
            "rule_id": rule_id,
            "regla": rule["titulo"],
            "severidad": rule["severidad"],
            "peso": SEVERITY_SCORE[rule["severidad"]],
            "mitre_id": rule["mitre"][0],
            "mitre_name": rule["mitre"][1],
            "detalle": detalle[:MAX_SNIPPET_LEN],
        }


def analyze_binary(path):
    path = Path(path)
    findings = []
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            scan_data = fh.read(ENTROPY_SCAN_LIMIT)
        head = scan_data[:4096]
    except OSError as exc:
        return {"score": 0, "estado": "alerta", "findings": [], "error": str(exc),
                "engine": "binary"}

    digests = hashes(path)

    magic = detect_magic(head)
    expected = expected_families(path)

    if expected and magic:
        if not any(fam in magic for fam in expected):
            findings.append(_Finding(
                "extension_mismatch", 0,
                f"extensión {path.suffix} pero contenido {', '.join(magic)}",
            ).data)

    elif expected and not magic and expected[0] not in ("bmp", "ico", "gz", "tar"):
        findings.append(_Finding(
            "extension_mismatch", 0,
            f"extensión {path.suffix} sin firma reconocida",
        ).data)

    if "exe" in magic and expected and "exe" not in expected:
        findings.append(_Finding(
            "executable_content", 0,
            "contenido PE (MZ) en archivo no ejecutable",
        ).data)

    entropy, high_blocks = _scan_entropy(scan_data)
    # Imágenes, vídeo, audio y contenedores comprimidos son densos por diseño.
    # Solo se exime cuando la firma mágica confirma un formato exento y la
    # cabecera es coherente; un paquete cifrado sin formato reconocido sigue
    # disparando la regla.
    entropy_exempt = _entropy_exempt(head, magic)
    if entropy >= ENTROPY_HIGH and not entropy_exempt:
        findings.append(_Finding(
            "high_entropy", 0,
            f"entropía media {entropy:.2f} ({high_blocks} bloques altos)",
        ).data)

    script_count = _count_embedded_scripts(scan_data)
    if script_count:
        findings.append(_Finding(
            "embedded_script", 0,
            f"{script_count} marcadores de script embebidos",
        ).data)

    score = weighted_score(findings)
    return {
        "score": score,
        "estado": estado_from_score(score, findings),
        "findings": findings,
        "error": None,
        "engine": "binary",
        "meta": {
            "sha256": digests["sha256"],
            "md5": digests["md5"],
            "size": size,
            "scanned": min(size, ENTROPY_SCAN_LIMIT),
            "entropy": round(entropy, 3),
            "entropy_exempt": entropy_exempt,
            "magic": magic,
        },
    }


def _entropy_exempt(head, magic):
    if not any(fam in ENTROPY_EXEMPT_FAMILIES for fam in magic):
        return False
    if "png" in magic:
        # La firma PNG válida exige el chunk IHDR justo después de la cabecera.
        return head[12:16] == b"IHDR"
    if "jpeg" in magic:
        return head[6:10] in (b"JFIF", b"Exif") or head[2:4] in (b"\xff\xe0", b"\xff\xe1")
    return True


def _scan_entropy(data):
    if not data:
        return 0.0, 0
    pairs = [(b, shannon_entropy(b))
             for b in (data[i:i + ENTROPY_BLOCK_SIZE] for i in range(0, len(data), ENTROPY_BLOCK_SIZE))]
    high = sum(1 for _, e in pairs if e >= ENTROPY_HIGH)
    # Media ponderada por tamaño: un bloque final diminuto no debe hundir la
    # media de un archivo grande.
    total = sum(e * len(b) for b, e in pairs)
    weight = sum(len(b) for b, _ in pairs)
    avg = total / weight if weight else 0.0
    return avg, high


def _count_embedded_scripts(data):
    markers = [b"<script", b"powershell", b"WScript.Shell", b"cmd.exe /c",
               b"base64 -d", b"Invoke-Expression", b"IEX("]
    return sum(1 for m in markers if m.lower() in data.lower())
