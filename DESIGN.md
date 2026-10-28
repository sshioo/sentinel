# Sentinel — Diseño

## Frase de dirección
Una consola forense: oscura, densa, hecha para mirar datos y actuar. Se parece a una herramienta de análisis de verdad (terminal, SIEM), no a un panel de marketing.

## Atributos de marca
- Precisión. Dato primero, decoración nunca.
- Contención. El color se gana su sitio; solo aparece para señalar estado.
- Gravedad. Es seguridad; el tono es serio sin ser frío.

## Anti-referencias (lo que NO quiero)
- Dashboard de startup: tarjetas grandes de métricas flotando arriba.
- Gradientes violeta/cyan "tech", glassmorphism por todas partes, texto con gradiente.
- Todo centrado, tarjetas idénticas repetidas, pills por doquier.
- Marca con un símbolo geométrico sin relación con el producto.
- Fade+rise en cada fila al aparecer.
- Menú de navegación con páginas falsas: cada entrada de la sidebar es una vista real.

## Principios extraídos
- La jerarquía la marca el tamaño y el espacio, no el color.
- El color es semántico: rojo=amenaza, ámbar=pendiente, verde=benigno, azul=en análisis online, ámbar=acción primaria.
- Los datos (rutas, hashes, líneas, IOCs) van en monoespaciada; la interfaz en sans.
- Denso pero respirable: el usuario escanea, no lee párrafos.

## Paleta oficial (tokens en `ui/theme.py`)
Superficie:
- `bg` #0E0F12 — fondo.
- `surface` #15171C — sidebar, paneles, cabecera.
- `elevated` #1C1F26 — filas, campos, botones secundarios.
- `border` #2B2E36 — bordes de 1px, separadores.
- `elevated-hover` #23262E — hover sobre elevated.

Primario (ámbar cálido):
- `primary` #E8A33D, hover #F2B653, active #CC892A, texto sobre ámbar `on-primary` #17130D.

Texto:
- `text` #F4F1E8, `text-secondary` #9296A2, `text-disabled` #656975.

Semánticos (color + fondo de badge, siempre par):
- success #4CCB91 / #14271F — benigno.
- warning #E8A33D / #302719 — pendiente.
- danger #FF626C / #321B20 — amenaza.
- info #69B9F5 / #172735 — en análisis online (VirusTotal).

Contraste: texto sobre fondo >= 7:1; `text-secondary` >= 4.5:1. Los estados no dependen solo del color: llevan texto ("AMENAZA", "BENIGNO", "PENDIENTE").

## Tipografía
Interfaz: Segoe UI (fallback; Inter si se instala). Datos: Cascadia Mono / Consolas (fallback; JetBrains Mono si se instala).
- Escala: título 22, sección 14 bold, nav/cuerpo 13, score-destacado 26 bold mono, mono 12/11, etiqueta 10.

## Estructura de pantalla
- Sidebar (224px, surface): logo + "MALWARE ANALYSIS CONSOLE" + versión; navegación real de tres vistas — Supervisión (monitor en vivo), Informes (HTML generados en `reports/out/`, botón Abrir real), Configuración (estado verdadero de motores, VirusTotal y carpeta vigilada). Indicador de estado (detenido / vigilando) fijo en la base.
- Cabecera: título de vista + descripción + botón Vigilar/Detener (primario cuando detenido, secundario cuando activo).
- Supervisión: franja de contadores (total, amenazas, pendientes, benignos, score medio) + tabla (Hora / Archivo / Tipo / Score / Estado) + panel de detalle (ruta, veredicto, hallazgos por línea con MITRE, IOCs, traza).
- Botones: primario (ámbar), secundario (elevated + borde), terciario (surface, texto atenuado), destructivo (rojo). Todos con estado hover; los dependientes de selección nacen deshabilitados.

## Espaciado y rejilla
- Base 4px. Rellenos de panel 16, separación entre bloques 12 (streams de ejemplo) o 10.
- Sin tarjetas de métricas flotantes; los contadores van en una franja compacta con separador inferior.

## Radio, borde, elevación
- Radio 6 (botones, filas), 8 (campos), 10 (paneles).
- Bordes de 1px `border`. Elevación por borde, no por sombra difusa. Material plano.

## Imágenes
- Logo `assets/logo.png` (Amber Eye) en splash (52px) y sidebar (30px); fallback a glifo `▚`. Sin imágenes decorativas.

## Movimiento
Razón: comunica cambio de estado, no decora.
- Duración corta: 150 ms (tokens `TRANSITION_MS`,16ms de tick).
- Splash de arranque con pasos reales de inicialización.
- Fila nueva: barrido de fondo único y asentado.
- Foco y hover: transición de color, no de escala.

## Vocabulario de componentes
- Sidebar de navegación con barra ámbar de sección activa.
- Cabecera de vista con título + botón de acción.
- Tabla de eventos con estado textual.
- Panel de detalle con hallazgos, MITRE, IOCs y traza.
- Lista de informes con nombre, tamaño, fecha y botón Abrir.
- Ficha de estado del sistema con etiquetas de disponibilidad por motor.

## Principios responsive
- Escritorio primero (es una consola). 1220x720 por defecto, mínimo 1024x620.
- Sin desbordes horizontales; nombre de archivo truncado con elipsis y ruta completa en el detalle.

## Excepciones intencionales
- La barra activa de la sidebar usa un borde ámbar de 3px izquierdo, no un fondo con color.
- El ámbar sirve a la vez de primario y de warning; el estado lo desambigua el texto y el fondo del badge.

