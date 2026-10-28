"""Analista IA opcional: explica los hallazgos ya detectados.

No detecta nada por sí solo ni sustituye al score. Toma el veredicto de reglas,
los IOCs y un fragmento acotado del archivo, y pide a un LLM una explicación en
español.

Proveedores, elegidos con AI_PROVIDER (auto detecta el primero configurado):
  - openai  : cualquier API compatible (OpenAI, Groq, OpenRouter...)
  - gemini  : Google AI Studio
  - ollama  : modelo local, sin nube

Privacidad: se envían hallazgos, metadatos y un fragmento de hasta ~6 KB.
Nunca el archivo completo. Sin proveedor configurado, la app sigue igual y este
módulo solo devuelve un aviso.

Privacidad de datos del demo: si usas un proveedor en la nube, no analices
muestras reales confidenciales con esta capa activa.
"""

import hashlib
import json
import os
from pathlib import Path

from config import ENV_FILE, REPORTS_DIR

try:
    from dotenv import load_dotenv
    load_dotenv(ENV_FILE)
except ImportError:
    pass

CACHE_PATH = REPORTS_DIR / ".ai_cache.json"
MAX_SNIPPET_CHARS = 6000
MAX_TEXT_CHARS = 8000
TIMEOUT_S = 60

_CODE_EXT = {".py", ".js", ".ts", ".ps1", ".sh", ".bat", ".cmd", ".rs", ".java",
             ".c", ".cpp", ".h", ".rb", ".php", ".pl", ".vbs", ".lua", ".go"}
_TEXT_EXT = {".txt", ".md", ".html", ".htm", ".xml", ".json", ".csv", ".log", ".yar"}

_SYSTEM = (
    "Eres analista de malware. Recibes el resultado de motores estáticos y un "
    "fragmento del archivo. Explica el riesgo en español claro para un estudiante "
    "de ingeniería. Estructura la respuesta exactamente en cuatro bloques:\n"
    "RESUMEN: qué es el archivo y qué hace, en 2-3 frases.\n"
    "RIESGO: por qué el veredicto es el que es; menciona los hallazgos concretos.\n"
    "TECNICAS: técnicas o familias probables solo si hay evidencia en los hallazgos.\n"
    "SIGUIENTES PASOS: qué haría un analista a continuación, sin ejecutar la muestra.\n"
    "Reglas: no inventes IOCs, hashes ni nombres de familia; si falta evidencia, "
    "escribe 'sin evidencia suficiente'. No propongas ejecutar el archivo. "
    "Máximo 220 palabras."
)


def _env(name, default=""):
    return os.environ.get(name, default).strip()


def provider():
    """Devuelve el proveedor activo o cadena vacía."""
    pref = _env("AI_PROVIDER", "auto").lower()
    have = {
        "openai": bool(_env("OPENAI_API_KEY")),
        "gemini": bool(_env("GEMINI_API_KEY")),
        "ollama": bool(_env("OLLAMA_MODEL")),
    }
    if pref in have:
        return pref if have[pref] else ""
    for name in ("openai", "gemini", "ollama"):
        if have[name]:
            return name
    return ""


def model_name(prov=None):
    prov = prov or provider()
    return {
        "openai": _env("OPENAI_MODEL", "gpt-4o-mini"),
        "gemini": _env("GEMINI_MODEL", "gemini-3.5-flash"),
        "ollama": _env("OLLAMA_MODEL", "llama3.1:8b"),
    }.get(prov, "")


def status():
    prov = provider()
    if prov:
        return {"configured": True, "provider": prov, "model": model_name(prov),
                "reason": ""}
    return {"configured": False, "provider": "", "model": "",
            "reason": "define OPENAI_API_KEY, GEMINI_API_KEY u OLLAMA_MODEL en .env"}


def _fingerprint(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            h.update(fh.read(65536))
        st = os.stat(path)
        h.update(f"{st.st_size}:{int(st.st_mtime)}".encode())
        return h.hexdigest()
    except OSError:
        return ""


def _snippet(path):
    p = Path(path)
    ext = p.suffix.lower()
    try:
        if ext in _CODE_EXT or ext in _TEXT_EXT:
            text = p.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()[:120]
            return "\n".join(lines)[:MAX_SNIPPET_CHARS]
        raw = p.read_bytes()[:2_000_000]
    except OSError:
        return ""
    out, cur = [], []
    for byte in raw:
        if 32 <= byte < 127:
            cur.append(chr(byte))
        else:
            if len(cur) >= 5:
                out.append("".join(cur))
            cur = []
            if len(out) >= 80:
                break
    if len(cur) >= 5:
        out.append("".join(cur))
    return "\n".join(s[:160] for s in out)[:MAX_SNIPPET_CHARS]


def build_messages(entry):
    findings = entry.get("findings", [])
    lines = []
    for f in findings[:30]:
        mitre = f.get("mitre_id", "")
        line = f.get("line", 0)
        bits = [f"[{f.get('severidad', '?')}]", f.get("regla", "?")]
        if line:
            bits.append(f"L{line}")
        if mitre:
            bits.append(mitre)
        if f.get("detalle"):
            bits.append(str(f["detalle"])[:200])
        lines.append(" · ".join(bits))
    iocs = entry.get("iocs") or []
    ioc_txt = ", ".join(f"{i.get('tipo')}={i.get('valor')}" for i in iocs[:20])
    meta = entry.get("meta")
    meta_txt = ""
    if meta:
        try:
            meta_txt = json.dumps(meta, ensure_ascii=False, default=str)[:1500]
        except (TypeError, ValueError):
            meta_txt = ""

    user = (
        f"Archivo: {entry.get('archivo', '?')}\n"
        f"Tipo: {entry.get('tipo', '?')}\n"
        f"Estado: {entry.get('estado', '?')} · Score: {entry.get('score', 0)}/100\n"
        f"Motor: {entry.get('engine', '?')}\n"
        f"Hallazgos ({len(findings)}):\n" + ("\n".join(lines) if lines else "ninguno") + "\n"
        f"IOCs: {ioc_txt or 'ninguno'}\n"
        f"Metadatos: {meta_txt or 'sin metadatos'}\n"
        f"--- fragmento ---\n{_snippet(entry.get('ruta', '')) or '(sin fragmento legible)'}"
    )[:MAX_SNIPPET_CHARS + 3000]
    return [{"role": "system", "content": _SYSTEM},
            {"role": "user", "content": user}]


def _post_json(url, headers, payload, timeout=TIMEOUT_S):
    import requests
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _call_openai(messages):
    base = _env("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    data = _post_json(
        f"{base}/chat/completions",
        {"Authorization": f"Bearer {_env('OPENAI_API_KEY')}",
         "Content-Type": "application/json"},
        {"model": model_name("openai"), "messages": messages,
         "temperature": 0.2, "max_tokens": 600},
    )
    return data["choices"][0]["message"]["content"]


_GEMINI_FALLBACK = ("gemini-3.5-flash", "gemini-2.5-flash", "gemini-flash-lite-latest")


def _gemini_request(model, messages, thinking=False):
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={_env('GEMINI_API_KEY')}")
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    user = "\n\n".join(m["content"] for m in messages if m["role"] != "system")
    gen = {"temperature": 0.2, "maxOutputTokens": 2048}
    if not thinking:
        # Razonamiento interno desactivado: tarea corta y de formato fijo.
        # Con thinking activo el presupuesto se consume y la respuesta se corta.
        gen["thinkingConfig"] = {"thinkingBudget": 0}
    data = _post_json(url, {"Content-Type": "application/json"},
                      {"system_instruction": {"parts": [{"text": system}]},
                       "contents": [{"parts": [{"text": user}]}],
                       "generationConfig": gen})
    cand = data["candidates"][0]
    parts = cand.get("content", {}).get("parts", [])
    text = "".join(p.get("text", "") for p in parts)
    if cand.get("finishReason") == "MAX_TOKENS" and len(text) > 100:
        text += "\n\n(Respuesta recortada por límite de tokens del modelo.)"
    return text


def _call_gemini(messages):
    """Prueba el modelo configurado y cae a alternativas si está saturado."""
    primary = model_name("gemini")
    candidates = [primary] + [m for m in _GEMINI_FALLBACK if m != primary]
    last = None
    for model in candidates:
        try:
            try:
                return _gemini_request(model, messages, thinking=False)
            except RuntimeError as exc:
                # Modelos que no aceptan thinkingConfig: reintento sin él.
                if "HTTP 400" in str(exc) and "thinking" in str(exc).lower():
                    return _gemini_request(model, messages, thinking=True)
                raise
        except RuntimeError as exc:
            last = exc
            msg = str(exc)
            if "HTTP 503" in msg or "HTTP 404" in msg or "UNAVAILABLE" in msg:
                continue
            raise
    raise last


def _call_ollama(messages):
    host = _env("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    data = _post_json(f"{host}/api/chat", {"Content-Type": "application/json"},
                      {"model": model_name("ollama"), "messages": messages,
                       "stream": False, "options": {"temperature": 0.2}})
    return data["message"]["content"]


_CALLERS = {"openai": _call_openai, "gemini": _call_gemini, "ollama": _call_ollama}


def _read_cache():
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_cache(data):
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(CACHE_PATH)
    except OSError:
        pass


def _cache_key(prov, entry):
    raw = json.dumps({
        "v": 2,  # invalida respuestas truncadas de versiones anteriores
        "p": prov,
        "m": model_name(prov),
        "f": entry.get("archivo", ""),
        "s": entry.get("score", 0),
        "e": entry.get("estado", ""),
        "r": _fingerprint(entry.get("ruta", "")),
        "n": len(entry.get("findings", [])),
    }, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def explain(entry, force=False):
    """Devuelve {'ok', 'text', 'provider', 'model', 'cached', 'error'}."""
    prov = provider()
    if not prov:
        return {"ok": False, "text": "", "provider": "", "model": "", "cached": False,
                "error": status()["reason"]}

    key = _cache_key(prov, entry)
    cache = _read_cache()
    if not force and key in cache:
        return {"ok": True, "text": cache[key], "provider": prov,
                "model": model_name(prov), "cached": True, "error": ""}

    try:
        text = _CALLERS[prov](build_messages(entry)).strip()[:MAX_TEXT_CHARS]
        if not text:
            raise RuntimeError("respuesta vacía del modelo")
    except Exception as exc:  # noqa: BLE001 - la capa IA nunca debe tumbar la app
        return {"ok": False, "text": "", "provider": prov, "model": model_name(prov),
                "cached": False, "error": str(exc)[:300]}

    cache[key] = text
    _write_cache(cache)
    return {"ok": True, "text": text, "provider": prov, "model": model_name(prov),
            "cached": False, "error": ""}
