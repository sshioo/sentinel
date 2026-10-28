# Demo de 90 segundos

## Antes de empezar

1. `install.bat` una vez. `selfcheck` debe salir en `[ok]`, salvo VirusTotal si
   no hay clave.
2. Elige el modo:
   - **Automático** (recomendado si hay poco tiempo): `demo.bat`. Sentinel
     analiza seis muestras al arrancar, sin tocar Descargas.
   - **En vivo**: `run.bat`, pulsa **Activar protección** y copia muestras de
     `python tools/make_samples.py` a Descargas.
3. Opcional: analista IA configurado en `.env` y probado una vez con conexión.

## Guion (modo automático)

**0:00 — Qué es.** «Sentinel responde a una pregunta: ¿es seguro abrir este
archivo? El análisis ocurre en el equipo; no sube nada a la nube.»

> Arranca `demo.bat`. Los archivos entran uno a uno en Actividad reciente y la
> señal de vigilancia lanza un pulso del color de cada veredicto.

**0:15 — Lo seguro sale seguro.** Pulsa `notas_reunion.txt` y
`paquete_demo.bin`.

«No todo lo raro es malware. Este paquete tiene entropía alta, como cualquier
archivo comprimido o cifrado. Sentinel lo anota como señal débil y lo deja en
Seguro.»

**0:30 — Disfraz.** Pulsa `foto_demo.jpg`.

«Dice ser una foto, pero por dentro es un ejecutable. Esa es una prueba fuerte:
Peligro, con la técnica MITRE que corresponde.»

> Señala la pestaña **Por qué** y la etiqueta «prueba fuerte».

**0:45 — Documento.** Pulsa `factura_demo.pdf` y después `contrato_demo.docx`.

«El PDF lleva JavaScript que se ejecuta al abrirlo: Peligro. El Word tiene una
macro, pero no se ejecuta sola ni lanza nada: Revisar. Sentinel distingue entre
tener una capacidad y usarla.»

**1:05 — Código.** Pulsa `demo_keylogger.py`.

«Decodifica base64 y ejecuta el resultado, y abre un socket junto a una shell.
Esa es la forma de una carga ofuscada.»

> Opcional: **Preguntar a la IA** para la explicación en lenguaje claro.

**1:20 — Cierre.** Pulsa **Generar informe** y ábrelo desde **Informes**.

«Todo queda en un informe HTML: veredicto, pruebas, MITRE e indicadores.»

## Si algo falla

| Síntoma | Plan B |
|---|---|
| No aparecen archivos en modo demo | Espera unos segundos tras el splash; si no, cierra y vuelve a abrir `demo.bat`. |
| En vivo no aparece un archivo | La copia puede tardar; espera a que termine o vuelve a copiarlo. |
| El antivirus borra una muestra | Usa el modo automático: las muestras van a `%TEMP%\sentinel-demo`. No añadas exclusiones. |
| Un ejecutable tarda | Es capa desensamblando. Para la demo, usa las seis muestras. |
| Sin internet | No menciones VirusTotal ni la IA; el resto es local. |
| La ventana no arranca | `.venv\Scripts\python tools\selfcheck.py` y revisa la primera línea `[--]`. |

## Qué no prometer

- No es un sandbox: el trazador aísla builtins, no el proceso.
- No sustituye a un antivirus.
- La IA no detecta: explica los hallazgos y puede equivocarse.
- La detección no se ha medido todavía con malware real.
