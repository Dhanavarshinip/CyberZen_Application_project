"""
Native Windows Toast Notification Module for CyberThreat AI System.

Uses winotify for ultra-fast native Windows Action Center notifications,
with fallback to PowerShell WinRT.
"""

import html
import subprocess
import threading
import sys
import os

DEFAULT_LAUNCH_URL = "http://localhost:5173/?tab=incidents&threat=1"

def show_windows_toast(title: str, message: str, status: str = "SAFE", launch_url: str = DEFAULT_LAUNCH_URL):
    """
    Shows a native Windows toast notification with click-to-open application navigation.
    Runs asynchronously in a background thread so it never blocks execution.
    """
    def _run():
        # 1. Try winotify first (fastest, direct Windows API, no powershell process overhead)
        try:
            from winotify import Notification, audio
            sound = audio.Default
            status_upper = status.upper()
            if status_upper in ("DANGEROUS", "THREAT_DETECTED"):
                sound = audio.LoopingAlarm
            elif status_upper == "SUSPICIOUS":
                sound = audio.Reminder

            toast = Notification(
                app_id="CyberThreat AI",
                title=title,
                msg=message[:180],
                duration="short",
                launch=launch_url
            )
            try:
                toast.set_audio(sound, loop=False)
            except Exception:
                pass
            toast.show()
            return
        except Exception:
            pass

        # 2. Fallback to PowerShell WinRT XML notification
        safe_title = html.escape(title)
        safe_message = html.escape(message)
        safe_launch = html.escape(launch_url)
        ps_code = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$template = @"
<toast activationType="protocol" launch="{safe_launch}">
    <visual>
        <binding template="ToastGeneric">
            <text>{safe_title}</text>
            <text>{safe_message}</text>
        </binding>
    </visual>
</toast>
"@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("CyberThreat AI")
$notifier.Show($toast)
"""
        try:
            creation_flag = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_code],
                capture_output=True,
                creationflags=creation_flag,
                timeout=5
            )
        except Exception:
            pass

    t = threading.Thread(target=_run, daemon=True, name="ToastThread")
    t.start()
    return True


def show_threat_alert_popup(
    title: str,
    file_name: str,
    status: str = "DANGEROUS",
    reasons: list = None,
    launch_url: str = DEFAULT_LAUNCH_URL
):
    """
    Displays an interactive native Windows threat dialog directly on the user's screen.
    Includes a button to navigate into the CyberThreat AI application for full causal forensic details.
    Runs non-blocking in a background thread for both online and offline operation.
    """
    def _run_popup():
        reason_text = " \\n ".join(reasons[:2]) if reasons else "Suspicious signature or heuristic detected."
        # Clean strings for PowerShell script
        safe_title = (title or "CyberThreat AI Threat Alert").replace('"', "'")
        safe_file = (file_name or "Unknown File/Process").replace('"', "'")
        safe_reason = reason_text.replace('"', "'").replace("\n", " ")
        safe_status = status.upper()

        status_color = "Crimson" if safe_status in ("DANGEROUS", "THREAT_DETECTED") else "DarkOrange"

        ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "CyberThreat AI - Security Threat Alert"
$form.Size = New-Object System.Drawing.Size(520, 310)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$form.ForeColor = [System.Drawing.Color]::White

# Header Label
$lblHeader = New-Object System.Windows.Forms.Label
$lblHeader.Text = "THREAT DETECTED IN FILE EXPLORER"
$lblHeader.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$lblHeader.ForeColor = [System.Drawing.Color]::{status_color}
$lblHeader.Location = New-Object System.Drawing.Point(24, 20)
$lblHeader.Size = New-Object System.Drawing.Size(460, 28)
$form.Controls.Add($lblHeader)

# Target File / Object
$lblFile = New-Object System.Windows.Forms.Label
$lblFile.Text = "Target: {safe_file}"
$lblFile.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$lblFile.ForeColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
$lblFile.Location = New-Object System.Drawing.Point(24, 56)
$lblFile.Size = New-Object System.Drawing.Size(460, 24)
$form.Controls.Add($lblFile)

# Reasons / Description
$lblDesc = New-Object System.Windows.Forms.Label
$lblDesc.Text = "Threat Indicators:\\n{safe_reason}\\n\\nOffline Local Monitoring: Event recorded in local SQLite database."
$lblDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblDesc.ForeColor = [System.Drawing.Color]::FromArgb(203, 213, 225)
$lblDesc.Location = New-Object System.Drawing.Point(24, 88)
$lblDesc.Size = New-Object System.Drawing.Size(460, 95)
$form.Controls.Add($lblDesc)

# Navigate Button
$btnNav = New-Object System.Windows.Forms.Button
$btnNav.Text = "Open CyberThreat AI Application"
$btnNav.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnNav.BackColor = [System.Drawing.Color]::FromArgb(2, 132, 199)
$btnNav.ForeColor = [System.Drawing.Color]::White
$btnNav.FlatStyle = "Flat"
$btnNav.Location = New-Object System.Drawing.Point(24, 205)
$btnNav.Size = New-Object System.Drawing.Size(270, 42)
$btnNav.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnNav.Add_Click({{
    Start-Process "{launch_url}"
    $form.Close()
}})
$form.Controls.Add($btnNav)

# Dismiss Button
$btnDismiss = New-Object System.Windows.Forms.Button
$btnDismiss.Text = "Dismiss"
$btnDismiss.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnDismiss.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnDismiss.ForeColor = [System.Drawing.Color]::LightGray
$btnDismiss.FlatStyle = "Flat"
$btnDismiss.Location = New-Object System.Drawing.Point(310, 205)
$btnDismiss.Size = New-Object System.Drawing.Size(120, 42)
$btnDismiss.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnDismiss.Add_Click({{
    $form.Close()
}})
$form.Controls.Add($btnDismiss)

$form.ShowDialog() | Out-Null
"""
        try:
            creation_flag = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                creationflags=creation_flag,
                timeout=180
            )
        except Exception:
            pass

    t = threading.Thread(target=_run_popup, daemon=True, name="ThreatPopupThread")
    t.start()
    return True
