# Cambios

## 1.3.0

### Ingeniería inversa como núcleo del escaneo
- Nuevo motor `core/static_re.py`, el primero que se ejecuta sobre cualquier archivo:
  estructura y datos pegados tras el fin del formato, tallado de ejecutables ocultos
  (también cifrados con XOR), decodificación de base64, hex y `-EncodedCommand`,
  shellcode y análisis de cadenas (inyección, espionaje, persistencia, anti-VM, rescate).
- Los ejecutables extraídos se analizan y desensamblan (pefile, capstone, capa) igual
  que uno suelto. Pruebas en `tests/test_static_re.py`.
- Desofuscación de scripts: Sentinel reconstruye cadenas partidas por
  concatenación (`'Downl'+'oadStr'+'ing'`) y secuencias `Chr(87)&Chr(83)` de
  VBScript/VBA antes de analizar. Solo cuenta lo que aparece tras unir los
  trozos y no estaba ya entero, para no marcar código legítimo.

### Veredicto
- Corroboración: tres motores independientes con indicios serios dan «Peligro».
- Cada resultado explica sus motivos principales.
- Menos falsos positivos: `eval` suelto, `/OpenAction` de PDF y las reglas de texto
  en código Python con árbol sintáctico pasan a señal débil.

### Interfaz
- Una sola pantalla con barra de estado, filtros, lista y veredicto.
- Pestaña «Ingeniería inversa» en el detalle.
- Secciones nuevas: Cuarentena (restaurar o eliminar) y Ajustes (vigilar al abrir,
  cuarentena automática, vaciar lista).
- Se quitan el analista IA, la vista Motores y la demo con muestras: la lista arranca vacía.
- Informes rediseñados: veredicto, motivos, ingeniería inversa, pruebas, MITRE, IOCs e
  identidad del archivo; imprimibles y se abren al generarlos.

## 1.2.0-beta.2

Revisión del motor de análisis. Cada punto tiene su prueba en
`tests/test_robustness.py`.

### Seguridad y privacidad

- «Trazar código» ya no ejecuta el archivo. Antes corría el script dentro de
  Sentinel con funciones sustituidas y se evadía con `__import__` o `getattr`.
  Ahora recorre el árbol sintáctico y lista las llamadas con sus argumentos.
- VirusTotal solo consulta el hash. Antes subía el archivo entero si no lo
  conocía. Subir exige `VT_UPLOAD=1` en `.env`.

### Robustez

- Una excepción en un archivo ya no mata el hilo de vigilancia. Un `.py` con una
  expresión anidada a miles de niveles bastaba para dejar la protección apagada
  mientras la interfaz decía «activa». El archivo sale como «Revisar» con el
  motivo, y la interfaz reinicia el vigilante si el hilo muere.
- Cada motor se ejecuta aislado: si uno falla, los demás siguen.
- Si un motor principal falla, el resultado ya no es «Seguro» sino «Revisar»
  (por ejemplo, un `.exe` truncado). La interfaz muestra los avisos.
- El vigilante no bloquea a los demás archivos mientras uno se descarga, descarta
  los temporales que desaparecen y no vuelve a analizar un archivo sin cambios.
- YARA lee el archivo por mapeo de memoria y con 60 s de límite; el PDF y el
  análisis de código leen como máximo 64 MB.

### Detección

- Office se detecta por contenido: una macro en `.dotm`, `.xlsb`, `.xlam` o
  `.bin` ya se analiza.
- PDF: se decodifican los nombres `/J#61vaScript` y se leen los flujos
  comprimidos (`/ObjStm`).
- Los scripts que no son Python (`.ps1`, `.c`, `.php`) ya no salen en «Revisar»
  solo por no compilar como Python.
- Un ejecutable con extensión de código (`.py`, `.js`...) se marca como
  disfraz.
- PowerShell: reglas para ventana oculta, política de ejecución, exclusiones del
  antivirus y carga de ensamblados; descargar y ejecutar con IEX es prueba
  fuerte.
- ZIP: se señalan los paquetes cifrados y los nombres con `..` o ruta absoluta.
- Una detección aislada en VirusTotal (menos de 3 motores) ya no da «Peligro».
- Cada regla YARA cuenta como un indicio distinto.
- `eval(` ya no salta dentro de `retrieval(`.
- El análisis manual revisa también los archivos que el vigilante ignora.
- Los imports de carga retardada se leen y los PE que no son x86 no se
  desensamblan como si lo fueran.

### Interfaz

- Inicio con tarjetas, anillo de reparto, donut por veredicto, gráficas y línea
  de tiempo por hora. Historial que sobrevive al cierre.
- La lista de actividad ya no se pega al deslizar: las filas son widgets planos
  y el límite baja a 60. Medido en 6 ms por paso con la lista llena.
- Deslizar o maximizar ya no redibuja unos 120 widgets en cada paso. El
  contenido se reajusta una vez al soltar el borde.
- Los números de los anillos caben con tres cifras y las etiquetas no tocan el
  arco.
- Iconos de Font Awesome Free (SIL OFL) en el menú, generados con Pillow.
- El fondo de la ventana en Windows usa el color oscuro de la interfaz: se
  reduce el destello blanco al agrandar.

## 1.2.0-beta.1

Primera beta para probar fuera del equipo de desarrollo.

### Análisis

- Veredicto por evidencia. Cada regla tiene una confianza (alta, media o baja).
  Para una alerta hace falta una prueba fuerte o varios indicios distintos. Las
  señales débiles cuentan una vez cada una y, juntas, nunca pasan de «seguro».
- Firma Authenticode. Un binario con firma válida baja un escalón la confianza
  de sus hallazgos; uno del propio Windows, hasta «baja». Los disfraces de
  nombre o extensión no se atenúan nunca.
- Ejecutables por técnica completa, no por imports sueltos: inyección en otro
  proceso, *process hollowing*, descarga y ejecución, lectura global del
  teclado, imports reducidos a resolver API, secciones RWX y punto de entrada
  fuera de la sección de código.
- Ingeniería inversa con capa (Mandiant, 1054 reglas) y capstone. Solo puntúan
  las capacidades que separan malware de software normal; el resto se guarda
  como comportamiento observado. Caché por SHA-256.
- Reglas compuestas para macros autoejecutables y para scripts que decodifican y
  ejecutan, usan red y ejecutan, o abren un socket y una shell.
- YARA con confianza por regla. La regla de inyección ya no salta con DLL de
  Windows que exportan esas funciones.

Medido con archivos legítimos: `notepad.exe`, `cmd.exe`, `kernel32.dll` y
módulos de la librería estándar de Python pasan de alerta a seguro. Las
muestras de demo maliciosas siguen en peligro.

### Interfaz

- Inicio rediseñado: protección de Descargas con escudo animado, zona para
  analizar a mano, contadores, señal de vigilancia en vivo y actividad en
  tarjetas.
- Resultado en lenguaje llano (Seguro, Revisar, Peligro) con medidor animado y
  qué hacer con el archivo. Pestaña «Por qué» con las pruebas ordenadas por
  confianza.
- Gráficos con antialiasing y movimiento por tiempo real.
- El análisis manual corre en segundo plano: la ventana ya no se congela con
  ejecutables grandes.

### Correcciones

- `main.py` dejaba un watcher preparado sin arrancar y la interfaz no creaba
  otro: «Activar protección» no hacía nada al abrir Sentinel con `main.py`.
- El watcher seguía en bucle después de detenerlo.

### Instalador

- `Sentinel-Setup-<versión>.exe`: se instala sin Python ni permisos de
  administrador, con accesos directos a Sentinel y a «Sentinel (demo)».
- Informes, caché y `.env` van a `%LOCALAPPDATA%\Sentinel` cuando se ejecuta
  instalado.
- Empaquetado, Sentinel.exe se relanza como trabajador de capa.
- La cadena EICAR de la regla YARA está en hexadecimal, para que el antivirus
  no marque Sentinel como archivo de prueba.

### Para desarrollar

- `install.bat`, `run.bat` y `demo.bat`.
- `python main.py --demo` analiza seis muestras inocuas sin tocar Descargas.
- `tools/setup_rules.py` descarga reglas y firmas de capa fijadas a v10.0.0.
- `tools/run_tests.py` ejecuta las siete suites.
- `tools/package_beta.py` genera el ZIP de la beta sin `.env`.

### Límites conocidos

- capa tarda de 6 s a más de 2 minutos por ejecutable sin firmar y se corta a
  los 120 s. Mientras tanto, la vigilancia espera.
- 7-Zip queda en «Revisar»: capa ve técnicas de evasión y sondeo de teclado en
  su interfaz gráfica.
- La detección solo se ha medido con muestras sintéticas y software legítimo,
  no con malware real.
- El trazador de la beta 1 ejecutaba el archivo; corregido en la beta 2.
