@echo off
rem ==============================================================================
rem AI-Driven Adaptive Deception Mesh — Windows Operations Dashboard Launcher
rem ==============================================================================
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

rem Check for virtual environment
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else if exist ".venv-sklearn-test\Scripts\activate.bat" (
    call ".venv-sklearn-test\Scripts\activate.bat"
) else if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)

rem Configure PYTHONPATH for Windows
set PYTHONPATH=%SCRIPT_DIR%;%SCRIPT_DIR%module3_ai_xai_engine;%PYTHONPATH%

echo ==================================================================
echo  Starting AI-Driven Adaptive Deception Mesh Operations Dashboard
echo  Host Binding: 127.0.0.1 (Strict Localhost Only)
echo  Dashboard URL: http://127.0.0.1:8000/
echo ==================================================================

python dashboard\server.py %*
