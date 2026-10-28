@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Creando entorno virtual .venv
    %PY% -m venv .venv || goto :error
) else (
    echo [1/4] Entorno virtual .venv ya existe
)

echo [2/4] Instalando dependencias
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || goto :error

echo [3/4] Descargando reglas de capa
".venv\Scripts\python.exe" tools\setup_rules.py

if not exist ".env" copy ".env.example" ".env" >nul

echo [4/4] Comprobando el entorno
".venv\Scripts\python.exe" tools\selfcheck.py

echo.
echo Listo. Abre Sentinel con run.bat, o con demo.bat para la demo.
pause
exit /b 0

:error
echo.
echo La instalacion fallo. Revisa el mensaje de arriba y README.md.
pause
exit /b 1
