# Cómo colaborar

## Poner el entorno en marcha

```bat
install.bat
demo.bat
```

`install.bat` crea `.venv`, instala dependencias, descarga las reglas de capa y
ejecuta `tools/selfcheck.py`. Si algo sale `[--]`, esa es la pieza que falta.

## Antes de cada cambio

```bat
.venv\Scripts\python tools\run_tests.py
```

Las siete suites tienen que pasar. Si cambias un criterio de detección a
propósito, actualiza el test y explica en el commit por qué cambia el
veredicto.

## Dónde tocar

| Quiero… | Archivo |
|---|---|
| Añadir una regla de un formato | `config.py` (`BINARY_RULES`) y el motor en `core/` |
| Cambiar cuánto pesa una regla | `config.py`: `RULE_CONFIDENCE` y severidad |
| Combinar dos indicios en una prueba | `config.py`: `COMPOUND_RULES` |
| Una regla YARA | `rules/sentinel.yar`, con `confidence` en `meta` |
| Qué capacidades de capa puntúan | `config.py`: `CAPA_CATEGORIES` |
| Decidir el veredicto | `core/scoring.py` |
| La interfaz | `ui/app.py`; gráficos animados en `ui/widgets.py` y `ui/scanstage.py` |

## Criterio de confianza

- **alta**: casi nunca aparece en software legítimo. Basta para una alerta.
- **media**: sospechoso, con usos legítimos conocidos.
- **baja**: habitual en software normal. Solo aporta contexto.

Antes de subir una regla a «alta», pásala por archivos legítimos: binarios de
`C:\Windows\System32`, programas de `C:\Program Files` y la librería estándar
de Python. Si salta con alguno, no es «alta».

## Muestras

Usa solo `tools/make_samples.py` o archivos legítimos. No añadas malware real al
repositorio. Si necesitas probar con muestras reales, hazlo en una máquina
virtual aislada y sin el trazador.

## Secretos

`.env` guarda tus claves y no se versiona. Para compartir el proyecto usa
`python tools/package_beta.py`, que genera el ZIP sin `.env`.
