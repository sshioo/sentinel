import os
from pathlib import Path

from config import CODE_EXTENSIONS, IGNORE_EXTENSIONS, PROJECT_DIR


def classify(path) -> str:
    p = Path(path)
    name = p.name

    if name.startswith("."):
        return "IGNORAR"
    if ":" in name:
        return "IGNORAR"

    ext = p.suffix.lower()
    if ext in IGNORE_EXTENSIONS:
        return "IGNORAR"

    if _is_inside(p, PROJECT_DIR):
        return "IGNORAR"

    if ext in CODE_EXTENSIONS:
        return "CÓDIGO"

    return "BINARIO"


def _is_inside(path: Path, folder: Path) -> bool:
    if not path.is_absolute():
        return False
    try:
        resolved = path.resolve()
    except OSError:
        return False
    try:
        return os.path.commonpath([str(resolved), str(folder.resolve())]) == str(folder.resolve())
    except ValueError:
        return False
