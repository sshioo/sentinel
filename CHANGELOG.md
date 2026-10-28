# Cambios

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
- El trazador no es un sandbox: aísla builtins, no el proceso.
