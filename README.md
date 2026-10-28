# Sentinel

Aplicación de escritorio para Windows que responde a una pregunta: ¿es seguro
abrir este archivo? Revisa cada archivo nuevo de Descargas, o el que elijas, con
varios motores locales y da un veredicto claro (**Seguro**, **Revisar** o
**Peligro**) con las pruebas que lo justifican.

Versión actual: **1.2.0-beta.1**. Los cambios están en `CHANGELOG.md`.

## Instalar (sin Python)

Descarga `Sentinel-Setup-<versión>.exe` de la página de *Releases* y ábrelo. No
pide permisos de administrador: se instala en tu usuario, crea un acceso
directo en el escritorio y otro en el menú Inicio, «Sentinel (demo)», que
analiza seis muestras inocuas.

El instalador no está firmado, así que Windows puede mostrar «Windows protegió
tu PC». Pulsa **Más información → Ejecutar de todas formas**.

Tus informes, la caché y el archivo `.env` con las claves opcionales quedan en
`%LOCALAPPDATA%\Sentinel`. Desinstalar Sentinel no los borra.

## Desde el código fuente

Requisitos: Windows 10/11 y Python 3.10 o superior (probado en 3.12.10).

```bat
install.bat
demo.bat
```

`install.bat` crea `.venv`, instala las dependencias, descarga las reglas de
capa (unos 15 MB) y comprueba el entorno. `demo.bat` abre Sentinel y analiza
seis muestras inocuas sin tocar tu carpeta Descargas.

Para el uso normal: `run.bat`.

Instalación manual, si prefieres:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python tools/setup_rules.py
python tools/selfcheck.py
python main.py
```

## Qué analiza

| Motor | Qué mira |
|---|---|
| Binario | Firma mágica frente a extensión, hashes, entropía |
| Nombre | Doble extensión (`factura.pdf.exe`), carácter RLO |
| ZIP | Ejecutables y disfraces dentro del paquete, sin extraerlo |
| Ejecutables (pefile) | Técnicas completas de imports, secciones, punto de entrada |
| Desensamblador (capstone) | Primeras instrucciones: arranques de empaquetador o shellcode |
| Ingeniería inversa (capa) | Qué sabe hacer el programa, según 1054 reglas de Mandiant |
| Firma digital | Authenticode, incluidos los binarios de Windows firmados por catálogo |
| Office (oletools) | Macros VBA, autoejecución, comandos y descargas |
| PDF (pypdf) | JavaScript, acciones automáticas, lanzamientos y adjuntos |
| Código Python | Árbol sintáctico: ejecución dinámica, red, sockets, ofuscación |
| YARA | Patrones conocidos, con confianza por regla |
| VirusTotal | Opcional: consulta del hash, nunca sube el archivo |

## Cómo decide

Cada hallazgo tiene una confianza:

- **alta**: casi nunca aparece en software legítimo. Por ejemplo, un ejecutable
  disfrazado de foto o la combinación completa de inyección en otro proceso.
- **media**: sospechoso, pero con usos legítimos conocidos.
- **baja**: habitual en software normal, como `getattr`, borrar un archivo o
  la entropía alta. Solo aporta contexto.

**Peligro** exige una prueba fuerte o un score alto apoyado en varios indicios
distintos. **Revisar** aparece con algún indicio de confianza media. Las señales
débiles cuentan una vez cada una y, juntas, nunca pasan de **Seguro**.

Una firma digital válida baja la confianza de los hallazgos; si es del propio
Windows, hasta «baja». Los disfraces de nombre o extensión no se atenúan nunca.

## Muestras de la demo

`python main.py --demo` o `python tools/make_samples.py`. Resultado de la
última ejecución:

| Muestra | Veredicto | Score | Por qué |
|---|---|---|---|
| `notas_reunion.txt` | Seguro | 0 | Texto normal |
| `paquete_demo.bin` | Seguro | 12 | Solo entropía alta: señal débil |
| `contrato_demo.docx` | Revisar | 29 | Macro VBA sin autoejecución |
| `demo_keylogger.py` | Peligro | 64 | Decodifica y ejecuta; socket y shell |
| `factura_demo.pdf` | Peligro | 60 | JavaScript que se ejecuta al abrir |
| `foto_demo.jpg` | Peligro | 67 | Ejecutable con extensión de imagen |

Las muestras son inocuas: no descargan nada ni tocan el sistema.

## Capas opcionales

Copia `.env.example` a `.env` (`install.bat` lo hace) y rellena solo lo que
uses. Sin nada configurado, todo el análisis local funciona igual.

**VirusTotal**: clave gratis en virustotal.com.

```
VT_API_KEY=tu_clave
```

**Analista IA**: explica los hallazgos en lenguaje claro. No detecta ni cambia
el score.

```
AI_PROVIDER=openai          # auto | openai | gemini | ollama
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4o-mini

GEMINI_API_KEY=...
GEMINI_MODEL=gemini-3.5-flash

OLLAMA_MODEL=llama3.1:8b
```

Se envían hallazgos, metadatos y un fragmento de hasta ~6 KB, nunca el archivo
completo. Las respuestas se guardan en `reports/out/.ai_cache.json`.

## Uso

- **Activar protección**: vigila Descargas y analiza cada archivo nuevo en
  cuanto termina de llegar.
- **Elige un archivo para revisarlo**: análisis manual de cualquier ruta.
- Pulsa un archivo de **Actividad reciente** para ver el veredicto, qué hacer y
  la pestaña **Por qué**.
- **Generar informe** crea un HTML autocontenido en `reports/out/`.
- **Trazar código** ejecuta un script Python en un intérprete instrumentado.
- **Preguntar a la IA** usa el analista, si está configurado.

## Desarrollo

```bat
.venv\Scripts\python tools\run_tests.py      siete suites
.venv\Scripts\python tools\selfcheck.py      estado del entorno
.venv\Scripts\python tools\package_beta.py   ZIP de la beta, sin .env
.venv\Scripts\python packaging\build.py      Sentinel.exe e instalador
```

`packaging/build.py` necesita PyInstaller (`pip install pyinstaller`) y, para el
instalador, Inno Setup 6 (`winget install JRSoftware.InnoSetup`). Deja la
aplicación en `dist/Sentinel/` y el instalador en `dist/`.

Guía para colaborar en `CONTRIBUTING.md`.

```
main.py                 arranque (--demo, --version)
config.py               versión, reglas, confianzas, umbrales
core/
  watcher.py            observador de Descargas
  dispatcher.py         código / binario / ignorar
  analyzer.py           entrada común y análisis de código
  pipeline.py           cadena de motores para binarios
  scoring.py            veredicto por evidencia
  binary_analyzer.py    firma mágica, hashes, entropía
  name_checks.py        doble extensión y RLO
  archive_analyzer.py   contenido de ZIP
  pe_analyzer.py        imports, secciones, punto de entrada, capstone
  reverse_engineer.py   capa, con caché por SHA-256
  signature.py          Authenticode
  office_analyzer.py    macros VBA
  pdf_analyzer.py       acciones y JavaScript en PDF
  deep_analyzer.py      árbol sintáctico de Python
  tracer.py             ejecución instrumentada
  yara_scanner.py       reglas YARA
  iocs.py               IP, dominios, URL, hashes
engines/                VirusTotal y analista IA
rules/sentinel.yar      reglas propias (capa se descarga en rules/capa*)
reports/report.py       informe HTML
ui/                     ventana, tema y gráficos animados
site/                   web del proyecto
tools/                  instalación, pruebas, muestras y empaquetado
tests/                  siete suites
```

## Límites conocidos

- capa tarda de 6 s a más de 2 minutos por ejecutable sin firmar y se corta a
  los 120 s. Mientras tanto, la vigilancia espera. Los binarios de Windows se
  saltan y los resultados quedan en caché.
- Algunos programas legítimos quedan en **Revisar**. Por ejemplo, 7-Zip: capa ve
  técnicas de evasión y sondeo de teclado en su interfaz.
- La detección se ha medido con muestras sintéticas y software legítimo, no con
  malware real.
- El trazador no es un sandbox: aísla builtins, no el proceso. Para muestras
  desconocidas, usa una máquina virtual.
- El analista IA puede equivocarse; el veredicto lo fijan las reglas.
- La aplicación no está firmada. SmartScreen puede avisar si se empaqueta como
  ejecutable.

## Documentos

- `CHANGELOG.md`: cambios por versión.
- `CONTRIBUTING.md`: cómo colaborar.
- `DEMO.md`: guion de la demo.
- `DESIGN.md` y `PRODUCT.md`: dirección visual y contexto de producto.
