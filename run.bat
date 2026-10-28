@echo off
chcp 65001 >nul
set "PYTHONUTF8=1"
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" main.py %*
) else (
    echo No encuentro .venv. Ejecuta primero install.bat.
    pause
)
