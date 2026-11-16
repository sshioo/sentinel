"""Preferencias del usuario, guardadas entre sesiones."""
import json
import os

from config import USER_DIR

PATH = USER_DIR / "settings.json"
DEFAULTS = {
    "auto_quarantine": False,   # mover solo los «Peligro» a la cuarentena
    "watch_on_start": False,    # empezar a vigilar Descargas al abrir
    "notify": True,             # aviso en la barra de estado al llegar un resultado
}


def load():
    try:
        data = json.loads(PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {**DEFAULTS, **{k: v for k, v in data.items() if k in DEFAULTS}}


def save(values):
    try:
        USER_DIR.mkdir(parents=True, exist_ok=True)
        tmp = PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(values, indent=1), encoding="utf-8")
        os.replace(tmp, PATH)
    except OSError:
        pass
