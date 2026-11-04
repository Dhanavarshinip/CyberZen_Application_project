# Setup 24/7 Continuous Background Monitoring for CyberZen
# Configures Windows Startup shortcut and Registry Run key for 100% silent execution

$appDir = "D:\CyberThreat_AI_System"
$vbsPath = Join-Path $appDir "run_monitor_hidden.vbs"
$startupDir = [Environment]::GetFolderPath("Startup")
$shortcutPath = Join-Path $startupDir "CyberThreat_AI_Monitor.lnk"

Write-Host "[*] Configuring 24/7 Silent Background Host Protection..." -ForegroundColor Cyan

# 1. Configure Windows Startup Folder Shortcut
try {
    $wshShell = New-Object -ComObject WScript.Shell
    $shortcut = $wshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "wscript.exe"
    $shortcut.Arguments = "`"$vbsPath`""
    $shortcut.WorkingDirectory = $appDir
    $shortcut.Description = "CyberZen 24/7 Continuous Endpoint Threat Monitor"
    $shortcut.Save()
    Write-Host "[+] Windows Startup shortcut configured: $shortcutPath" -ForegroundColor Green
} catch {
    Write-Warning "Failed to create startup shortcut: $_"
}

# 2. Configure Windows Registry CurrentVersion\Run (Failsafe for automated boot)
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "CyberZen24x7Monitor"
    $regValue = "wscript.exe `"$vbsPath`""
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue
    Write-Host "[+] Windows Registry Run key configured: $regName -> $regValue" -ForegroundColor Green
} catch {
    Write-Warning "Failed to set registry run key: $_"
}

# 3. Launch the background monitor right now if not already running
try {
    $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($res) {
        Write-Host "[+] CyberZen Background Monitor is already running actively." -ForegroundColor Green
    } else {
        Start-Process "wscript.exe" -ArgumentList "`"$vbsPath`"" -WorkingDirectory $appDir
        Write-Host "[+] Launched CyberZen Background Monitor in silent mode." -ForegroundColor Green
    }
} catch {
    Start-Process "wscript.exe" -ArgumentList "`"$vbsPath`"" -WorkingDirectory $appDir
    Write-Host "[+] Launched CyberZen Background Monitor in silent mode." -ForegroundColor Green
}

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " 24/7 Continuous Threat Monitoring Active & Configured " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
