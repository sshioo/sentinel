import re

from config import IOC_HASH_MIN_LEN, IOC_MAX_PER_TYPE, IOC_PRIVATE_PREFIXES

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]},]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|onion|site|online|club|tk|ml|ga|cf|gq|pw|zip|mov)\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{%d,64}\b" % IOC_HASH_MIN_LEN)
_C2_PATH_RE = re.compile(
    r"(?:/gate\.php|/panel/|/bot|/c2/|/cmd/|/inject|/payload|/beacon|/update\.php)",
    re.IGNORECASE,
)


def _is_private(ip):
    return any(ip.startswith(p) for p in IOC_PRIVATE_PREFIXES)


def _is_all_numeric(domain):
    return all(ch.isdigit() or ch == "." for ch in domain)


def _valid_ip(ip):
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def _add(iocs, seen, tipo, valor, line):
    key = (tipo, valor.lower())
    if key in seen:
        return
    seen.add(key)
    iocs.append({"tipo": tipo, "valor": valor, "line": line})


def extract_text(text):
    iocs = []
    seen = set()
    counts = {}

    def bump(tipo):
        counts[tipo] = counts.get(tipo, 0) + 1
        return counts[tipo] <= IOC_MAX_PER_TYPE

    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in _URL_RE.finditer(line):
            if bump("url"):
                _add(iocs, seen, "url", m.group(0), lineno)
        for m in _EMAIL_RE.finditer(line):
            if bump("email"):
                _add(iocs, seen, "email", m.group(0), lineno)
        for m in _IP_RE.finditer(line):
            ip = m.group(0)
            if _valid_ip(ip) and not _is_private(ip) and bump("ip"):
                _add(iocs, seen, "ip", ip, lineno)
        for m in _DOMAIN_RE.finditer(line):
            dom = m.group(0)
            if _is_all_numeric(dom):
                continue
            if bump("domain"):
                _add(iocs, seen, "domain", dom, lineno)
        for m in _HASH_RE.finditer(line):
            if bump("hash"):
                _add(iocs, seen, "hash", m.group(0), lineno)
        for m in _C2_PATH_RE.finditer(line):
            if bump("c2_path"):
                _add(iocs, seen, "c2_path", m.group(0), lineno)

    return iocs


def extract_file(path, limit=4_000_000):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError:
        return []
    text = raw.decode("utf-8", errors="replace")
    return extract_text(text)


def summarize(iocs):
    counts = {}
    for ioc in iocs:
        counts[ioc["tipo"]] = counts.get(ioc["tipo"], 0) + 1
    return counts
