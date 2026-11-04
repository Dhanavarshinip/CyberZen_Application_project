@echo off
title CyberThreat AI - Protected Browser Launcher
echo ============================================================
echo   CyberThreat AI - Launching Chrome with Extension
echo ============================================================
echo.

set EXT_DIR=d:\CyberThreat_AI_System\chrome_extension
set PROFILE_DIR=%LOCALAPPDATA%\Google\Chrome\CyberThreatProtectionProfile

:: Search for chrome.exe
set CHROME_EXE=
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "CHROME_EXE=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not defined CHROME_EXE if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "CHROME_EXE=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if not defined CHROME_EXE if exist "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" set "CHROME_EXE=%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"

if not defined CHROME_EXE (
    echo [!] Google Chrome was not found in standard installation directories.
    echo Please open your browser, visit chrome://extensions, enable Developer Mode,
    echo and click 'Load unpacked' pointing to:
    echo   %EXT_DIR%
    pause
    exit /b 1
)

echo [*] Starting Google Chrome with CyberThreat AI Extension loaded...
echo [*] Extension path: %EXT_DIR%
echo.

start "" "%CHROME_EXE%" --load-extension="%EXT_DIR%" --user-data-dir="%PROFILE_DIR%" "https://mail.google.com" "http://localhost:5173"

echo [+] Protected Chrome window opened.
echo You will see the CyberThreat AI 'SAFE / NOT SAFE' badge overlay in the top right.
timeout /t 3 >nul
