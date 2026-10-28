import json
import os
import subprocess
import sys

from config import SIGNATURE_TIMEOUT_S

# Get-AuthenticodeSignature resuelve también los binarios firmados por catálogo
# (notepad.exe, cmd.exe), que no llevan la firma incrustada en el PE.
_SCRIPT = (
    "$s = Get-AuthenticodeSignature -LiteralPath $env:SENTINEL_TARGET;"
    "[pscustomobject]@{status=[string]$s.Status;"
    "signer=$(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' });"
    "os=[bool]$s.IsOSBinary;type=[string]$s.SignatureType} | ConvertTo-Json -Compress"
)


def check(path):
    """Devuelve {'status', 'signer', 'os', 'type'} o {'status': 'Unknown', 'error': ...}."""
    if sys.platform != "win32":
        return {"status": "Unknown", "error": "verificación Authenticode solo en Windows"}
    env = dict(os.environ, SENTINEL_TARGET=str(path))
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _SCRIPT],
            capture_output=True, timeout=SIGNATURE_TIMEOUT_S, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        data = json.loads(proc.stdout.decode("utf-8", errors="replace") or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {"status": "Unknown", "error": str(exc)}
    return {
        "status": data.get("status", "Unknown"),
        "signer": _common_name(data.get("signer", "")),
        "os": bool(data.get("os")),
        "type": data.get("type", ""),
    }


def _common_name(subject):
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:]
    return subject


def is_trusted(sig):
    return sig.get("status") == "Valid"


def is_tampered(sig):
    # HashMismatch: el archivo cambió después de firmarse. NotSigned o una
    # cadena no confiable (firma de desarrollo) no prueban nada por sí solas.
    return sig.get("status") == "HashMismatch"
