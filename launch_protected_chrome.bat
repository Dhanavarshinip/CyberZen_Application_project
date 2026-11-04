@echo off
REM ===============================================================
REM CyberThreat AI - Launch Google Chrome with Security Extension
REM ===============================================================
setlocal

set "EXT_PATH=%LOCALAPPDATA%\CyberThreatAI\chrome_extension"
if not exist "%EXT_PATH%\manifest.json" set "EXT_PATH=%~dp0chrome_extension"
if not exist "%EXT_PATH%\manifest.json" set "EXT_PATH=D:\cyberthreat-extension"
set "CHROME_EXE="

if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    set "CHROME_EXE=C:\Program Files\Google\Chrome\Application\chrome.exe"
) else if exist "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" (
    set "CHROME_EXE=C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
) else if exist "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" (
    set "CHROME_EXE=%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
) else if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    set "CHROME_EXE=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
) else if exist "C:\Program Files\Microsoft\Edge\Application\msedge.exe" (
    set "CHROME_EXE=C:\Program Files\Microsoft\Edge\Application\msedge.exe"
)

if "%CHROME_EXE%"=="" (
    echo [-] Error: Neither Google Chrome nor Microsoft Edge was found on your system.
    pause
    exit /b 1
)

echo [*] Launching Protected Browser with CyberThreat AI Extension: "%EXT_PATH%"
start "" "%CHROME_EXE%" --load-extension="%EXT_PATH%" --no-first-run --no-default-browser-check https://google.com
exit /b 0
