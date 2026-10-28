# Sentinel — Producto

## Qué es
Herramienta de escritorio que vigila la carpeta de Descargas y analiza cada archivo que aparece: código fuente línea por línea (AST), y binarios/documentos con motores multi-formato (YARA, PE, Office, PDF, VirusTotal). Devuelve un veredicto con score, hallazgos mapeados a MITRE ATT&CK, traza conductual e IOCs.

## Usuarios
- Estudiante de ingeniería presentando un proyecto en feria (demo en vivo).
- Analista que quiere un primer triaje rápido de algo que se acaba de descargar.

## Trabajos principales
1. Ver, sin tocar nada, qué acaba de entrar a Descargas y si es peligroso.
2. Entender *por qué*: ver la línea, la regla y la técnica concreta.
3. Sacar una evidencia: informe HTML para adjuntar.

## Tareas clave
- Vigilar / pausar la carpeta.
- Leer la lista de eventos y su severidad de un vistazo.
- Seleccionar un archivo y ver el detalle.
- Trazar un script Python sin ejecutarlo.
- Extraer IOCs.
- Generar el informe.

## Hechos reales vs. supuestos
- Real: todo el análisis ocurre en local; VirusTotal es opcional (requiere API key).
- Real: la traza conductual instrumenta el AST; no ejecuta el payload destructivo.
- Supuesto: en la feria se demuestra con muestras inofensivas y EICAR, nunca malware real.

## No-objetivos
- Sustituir a un antivirus de producción.
- Análisis en tiempo real de tráfico de red.

## Criterio de éxito (feria)
- Descargar un archivo y verlo aparecer analizado en menos de 2 segundos.
- Detectar una muestra maliciosa con score alto y técnicas MITRE visibles.
- La interfaz se entiende sin que nadie la explique.

## Accesibilidad
- Objetivo WCAG 2.2 AA en lo aplicable a escritorio: contraste suficiente, foco visible, navegación por teclado, sin depender solo del color para transmitir estado.
