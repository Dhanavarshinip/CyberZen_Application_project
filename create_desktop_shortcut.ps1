# CyberThreat AI System - Automated Desktop Shortcut Manager
# Deletes old shortcuts and creates updated shortcut across all desktop paths

$WshShell = New-Object -ComObject WScript.Shell

# Detect all active desktop locations (Local Profile, OneDrive, and Public Desktop)
$desktopDirs = @(
    [System.Environment]::GetFolderPath('Desktop'),
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:USERPROFILE 'OneDrive\Desktop')
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

Write-Host "=========================================================="
Write-Host " CyberThreat AI - Desktop Shortcut Refresh"
Write-Host "=========================================================="

# 1. Delete ALL existing CyberThreat and CyberZen shortcuts across all desktop folders
foreach ($dir in $desktopDirs) {
    $existing = Get-ChildItem -Path $dir -Include "*CyberThreat*.lnk", "*CyberZen*.lnk" -Recurse:$false -ErrorAction SilentlyContinue
    foreach ($item in $existing) {
        try {
            Remove-Item -Path $item.FullName -Force
            Write-Host "[-] Removed existing shortcut: $($item.FullName)"
        } catch {
            Write-Host "[!] Could not remove: $($item.FullName)"
        }
    }
}

# 2. Ensure verified native Electron runtime is present in LocalAppData
$runtimeDir = Join-Path $env:LOCALAPPDATA 'CyberThreatAI\electron'
$runtimeExe = Join-Path $runtimeDir 'electron.exe'

# 2b. Automatically install and configure Chrome Security Extension in LocalAppData
$targetExtDir = Join-Path $env:LOCALAPPDATA 'CyberThreatAI\chrome_extension'
try {
    New-Item -ItemType Directory -Force -Path $targetExtDir | Out-Null
    $srcExtDir = "d:\CyberThreat_AI_System\chrome_extension"
    if (Test-Path $srcExtDir) {
        Copy-Item -Path "$srcExtDir\*" -Destination $targetExtDir -Recurse -Force
        Write-Host "[+] Automatically installed Chrome Security Extension into $targetExtDir"
    }
} catch {
    Write-Host "[!] Could not copy extension to LocalAppData: $_"
}

if (-not (Test-Path $runtimeExe)) {
    Write-Host "[*] Initializing dedicated CyberThreat AI runtime in $runtimeDir..."
    New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
    
    # Source candidates
    $sources = @(
        "d:\CyberThreat_AI_System\node_modules\electron\dist",
        (Get-ChildItem "C:\Users\HP\AppData\Local\npm-cache\_npx" -Recurse -Filter "electron.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.DirectoryName })
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($src in $sources) {
        if (Test-Path (Join-Path $src 'electron.exe')) {
            Copy-Item -Path "$src\*" -Destination $runtimeDir -Recurse -Force -ErrorAction SilentlyContinue
            break
        }
    }
}

$projectPath = "d:\CyberThreat_AI_System"

if (Test-Path $runtimeExe) {
    $targetPath = $runtimeExe
    $targetArgs = "`"$projectPath`""
    $workDir = $projectPath
    $iconPath = "$runtimeExe,0"
} else {
    $targetPath = Join-Path $projectPath "start_cyberthreat_ai.bat"
    $targetArgs = ""
    $workDir = $projectPath
    $iconPath = Join-Path $projectPath "node_modules\electron\dist\electron.exe,0"
}

$officialName = "CyberZen Operations Center.lnk"

# 3. Create fresh updated shortcut in all desktop paths
foreach ($dir in $desktopDirs) {
    try {
        $shortcutPath = Join-Path -Path $dir -ChildPath $officialName
        $shortcut = $WshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetPath
        if ($targetArgs) {
            $shortcut.Arguments = $targetArgs
        }
        $shortcut.WorkingDirectory = $workDir
        $shortcut.Description = "CyberZen - Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction"
        if (Test-Path ($iconPath -split ',')[0]) {
            $shortcut.IconLocation = $iconPath
        }
        $shortcut.Save()
        Write-Host "[+] Created updated shortcut: $shortcutPath"
    } catch {
        Write-Host "[!] Error creating shortcut in $dir : $_"
    }

    # Create CyberZen Protected Browser shortcut
    try {
        $browserShortcutPath = Join-Path -Path $dir -ChildPath "CyberZen Protected Browser.lnk"
        $browserShortcut = $WshShell.CreateShortcut($browserShortcutPath)
        $browserShortcut.TargetPath = Join-Path $projectPath "launch_protected_chrome.bat"
        $browserShortcut.WorkingDirectory = $projectPath
        $browserShortcut.Description = "Launch Google Chrome with CyberZen real-time protection extension automatically loaded"
        $chromeIcon = "C:\Program Files\Google\Chrome\Application\chrome.exe,0"
        if (Test-Path ($chromeIcon -split ',')[0]) {
            $browserShortcut.IconLocation = $chromeIcon
        }
        $browserShortcut.Save()
        Write-Host "[+] Created Protected Browser shortcut: $browserShortcutPath"
    } catch {
        Write-Host "[!] Error creating browser shortcut in $dir : $_"
    }
}

Write-Host "=========================================================="
Write-Host " Desktop shortcuts successfully updated."
Write-Host "=========================================================="
