"""Historial de los archivos que el usuario ha analizado, entre sesiones."""
import json
import os

from config import USER_DIR

PATH = USER_DIR / "history.json"
KEYS = ("archivo", "ruta", "tipo", "estado", "score", "findings", "engine", "hora", "ts",
        "online", "iocs", "errors", "razones", "info", "re", "cuarentena")


def load(limit=60):
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
        return [e for e in data if isinstance(e, dict) and e.get("archivo")][-limit:]
    except (OSError, ValueError):
        return []


def save(entries, limit=60):
    rows = [{k: e[k] for k in KEYS if k in e} for e in entries][-limit:]
    try:
        USER_DIR.mkdir(parents=True, exist_ok=True)
        tmp = PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(rows, ensure_ascii=False, default=str), encoding="utf-8")
        os.replace(tmp, PATH)
    except OSError:
        pass


def clear():
    save([])
