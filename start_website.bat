@echo off
title CyberThreat AI Website Launcher
cd /d "%~dp0"

echo ======================================================
echo    Starting CyberThreat AI Web Platform
echo ======================================================

echo [*] Checking FastAPI backend on port 8000...
curl -s http://127.0.0.1:8000/api/health > nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Backend is already running on http://127.0.0.1:8000
) else (
    echo [*] Starting FastAPI backend in background...
    set PYTHON_EXE=C:\Python314\python.exe
    if not exist "%PYTHON_EXE%" set PYTHON_EXE=python
    start "CyberThreat AI Backend" /min "%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
    timeout /t 2 /nobreak > nul
)

echo [*] Launching Vite web development server (http://localhost:5173)...
start "CyberThreat AI Web" cmd /k ""C:\Program Files\nodejs\npm.cmd" run dev"

echo [*] Waiting 2 seconds for Vite to initialize...
timeout /t 2 /nobreak > nul

echo [*] Opening browser to http://localhost:5173...
start http://localhost:5173

echo [+] CyberThreat AI web platform launched successfully!
exit
