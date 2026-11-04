@echo off
title CyberZen System Launcher
cd /d "%~dp0"

echo ======================================================
echo    Starting CyberZen System
echo [*] Refreshing desktop shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -File create_desktop_shortcut.ps1 > nul 2>&1

echo [*] Building latest frontend bundle...
call npm run build

echo [*] Checking Backend status...
curl -s http://127.0.0.1:8000/api/health > nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Backend is already active on http://127.0.0.1:8000
    goto launch_gui
)

echo [*] Initializing FastAPI Python Research Backend...
set PYTHON_EXE=C:\Python314\python.exe
if not exist "%PYTHON_EXE%" set PYTHON_EXE=python

start "CyberZen Backend" /min "%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

echo [*] Waiting for Backend to be ready...
set count=0
:waitloop
timeout /t 1 /nobreak > nul
set /a count+=1
curl -s http://127.0.0.1:8000/api/health > nul 2>&1
if %errorlevel% equ 0 goto ready
if %count% geq 20 (
    echo [!] Backend check timed out; launching GUI anyway...
    goto launch_gui
)
goto waitloop

:ready
echo [+] Backend is ready.

:launch_gui
echo [*] Launching CyberZen Desktop Operations Center...
set APP_DIR=%~dp0
if "%APP_DIR:~-1%"=="\" set APP_DIR=%APP_DIR:~0,-1%

if exist "%LOCALAPPDATA%\CyberThreatAI\electron\electron.exe" (
    start "" "%LOCALAPPDATA%\CyberThreatAI\electron\electron.exe" "%APP_DIR%"
) else (
    call .\node_modules\.bin\electron.cmd "%APP_DIR%"
)

exit
