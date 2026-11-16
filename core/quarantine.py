"""Cuarentena: aparta un archivo peligroso sin borrarlo.

El archivo se mueve a USER_DIR/quarantine con un nombre neutro y la extensión
.quarantine, para que un doble clic no lo ejecute. Un índice JSON recuerda de
dónde vino, para poder restaurarlo o eliminarlo después.
"""
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from config import USER_DIR

DIR = USER_DIR / "quarantine"
INDEX = DIR / "index.json"


def _load():
    try:
        data = json.loads(INDEX.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save(items):
    DIR.mkdir(parents=True, exist_ok=True)
    tmp = INDEX.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, INDEX)


def items():
    return sorted(_load(), key=lambda i: i.get("ts", 0), reverse=True)


def isolate(path, estado="", score=0, motivo=""):
    """Mueve el archivo a la cuarentena. Devuelve la ficha o lanza OSError."""
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"ya no existe: {src}")
    DIR.mkdir(parents=True, exist_ok=True)
    qid = uuid.uuid4().hex[:12]
    dest = DIR / f"{qid}.quarantine"
    shutil.move(str(src), str(dest))
    item = {"id": qid, "archivo": src.name, "origen": str(src), "ts": time.time(),
            "estado": estado, "score": score, "motivo": motivo, "bytes": dest.stat().st_size}
    data = _load()
    data.append(item)
    _save(data)
    return item


def restore(qid):
    data = _load()
    item = next((i for i in data if i["id"] == qid), None)
    if item is None:
        raise KeyError(qid)
    target = Path(item["origen"])
    if target.exists():
        target = target.with_name(f"{target.stem} (restaurado){target.suffix}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(DIR / f"{qid}.quarantine"), str(target))
    _save([i for i in data if i["id"] != qid])
    return target


def delete(qid):
    data = _load()
    (DIR / f"{qid}.quarantine").unlink(missing_ok=True)
    _save([i for i in data if i["id"] != qid])
