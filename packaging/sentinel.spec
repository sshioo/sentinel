# Receta de PyInstaller para Sentinel. Se usa desde packaging/build.py.
# Modo carpeta (onedir): arranca más rápido que un único .exe y los antivirus
# lo marcan mucho menos, porque no se descomprime en %TEMP% al abrirse.
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_dynamic_libs

ROOT = Path(SPECPATH).parent

datas = [
    (str(ROOT / "rules" / "sentinel.yar"), "rules"),
    (str(ROOT / "rules" / "capa"), "rules/capa"),
    (str(ROOT / "rules" / "capa-sigs"), "rules/capa-sigs"),
    (str(ROOT / "assets"), "assets"),
    (str(ROOT / ".env.example"), "."),
]
binaries = []
hiddenimports = ["tools.make_samples", "engines.virustotal", "engines.ai_analyst"]

datas += collect_data_files("customtkinter")
binaries += collect_dynamic_libs("capstone")
datas += collect_data_files("capstone")
for pkg in ("capa", "vivisect", "envi", "vstruct", "viv_utils", "dncil", "dnfile", "flirt", "oletools"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    # Integraciones opcionales de capa (IDA, Ghidra, Binary Ninja, nube) y
    # ciencia de datos que no usa Sentinel: unos 115 MB menos.
    excludes=["pytest", "IPython", "matplotlib", "notebook", "tests", "scipy", "numpy", "pandas",
              "botocore", "boto3", "s3transfer", "capa.ida", "capa.ghidra", "capa.features.extractors.ida",
              "capa.features.extractors.ghidra", "capa.features.extractors.binja", "binaryninja",
              "idaapi", "idc", "ghidra", "PyQt5", "PySide2", "PySide6"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Sentinel",
    icon=str(ROOT / "assets" / "sentinel.ico"),
    console=False,
    upx=False,
    version=str(ROOT / "packaging" / "version_info.txt"),
)
coll = COLLECT(exe, a.binaries, a.datas, name="Sentinel", upx=False)
