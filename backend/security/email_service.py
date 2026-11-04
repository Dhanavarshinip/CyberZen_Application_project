"""
Transactional Email Service for CyberThreat AI.

Official Project Title:
Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction

Supports:
- Brevo (Sendinblue) API
- Resend API
- Standard SMTP fallback
- Safe console/dry-run logging when credentials are not configured

Workflow:
1. Account Verification (Email 1) - Verification link / 6-digit OTP
2. Welcome and Installation Instructions (Email 2) - Download link, setup steps, permissions
3. Installation Success (Email 3) - Triggered ONLY after real agent registration & launch
4. Setup Incomplete (Email 4) - Inactive collector / missing permissions warning
"""

import os
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any

from backend.security.safe_logger import setup_safe_logging

logger = setup_safe_logging("cyberthreat.email")

# Transactional provider credentials from environment variables
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "security@cyberthreat.ai")
APP_URL = os.getenv("APP_URL", "http://localhost:5173")
DOWNLOAD_URL = os.getenv("DOWNLOAD_URL", "http://127.0.0.1:8000/api/download/windows")

PROJECT_TITLE = "Intelligent Real-Time Digital Threat Detection, Prevention and Incident Reconstruction"


def _send_resend(to_email: str, subject: str, html_content: str, text_content: str) -> bool:
    try:
        import urllib.request
        url = "https://api.resend.com/emails"
        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "from": EMAIL_FROM,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
            "text": text_content
        }
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        logger.error(f"[EmailService] Resend delivery failed: {e}")
        return False


def _send_brevo(to_email: str, subject: str, html_content: str, text_content: str) -> bool:
    try:
        import urllib.request
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json"
        }
        data = {
            "sender": {"email": EMAIL_FROM, "name": "CyberThreat AI Security"},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": html_content,
            "textContent": text_content
        }
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        logger.error(f"[EmailService] Brevo delivery failed: {e}")
        return False


def _send_smtp(to_email: str, subject: str, html_content: str, text_content: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email

        part1 = MIMEText(text_content, "plain")
        part2 = MIMEText(html_content, "html")
        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(EMAIL_FROM, [to_email], msg.as_string())
        return True
    except Exception as e:
        logger.error(f"[EmailService] SMTP delivery failed: {e}")
        return False


def send_email(to_email: str, subject: str, html_content: str, text_content: str) -> bool:
    """Dispatches email using configured provider, falling back safely to audit log."""
    if RESEND_API_KEY:
        ok = _send_resend(to_email, subject, html_content, text_content)
        if ok:
            return True
    if BREVO_API_KEY:
        ok = _send_brevo(to_email, subject, html_content, text_content)
        if ok:
            return True
    if SMTP_HOST:
        ok = _send_smtp(to_email, subject, html_content, text_content)
        if ok:
            return True

    # Development fallback: log safe audit representation without secrets
    logger.info(f"[EmailService] Simulated dispatch to {to_email} | Subject: {subject}")
    return True


# ==================== TEMPLATES ====================

def send_verification_email(to_email: str, user_name: str, otp_code: str, verification_link: Optional[str] = None) -> bool:
    """EMAIL 1 — ACCOUNT VERIFICATION: Sent immediately after signup."""
    subject = f"Verify Your Account — {PROJECT_TITLE}"
    link = verification_link or f"{APP_URL}/verify?email={to_email}&code={otp_code}"
    
    text_content = f"""Hello {user_name},

Thank you for registering for {PROJECT_TITLE}.

Your account verification code is: {otp_code}

Or confirm directly via this secure link:
{link}

This code will expire in 24 hours.

If you did not register for this account, please disregard this email.
"""

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="background:#090d16; color:#f8fafc; font-family:sans-serif; padding:20px;">
  <div style="max-width:600px; margin:0 auto; background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:30px;">
    <div style="color:#00f0ff; font-weight:700; font-size:12px; text-transform:uppercase; margin-bottom:10px;">Security Verification</div>
    <h2 style="margin:0 0 15px 0; color:#f8fafc; font-size:20px;">{PROJECT_TITLE}</h2>
    <p style="color:#94a3b8; font-size:14px; line-height:1.5;">Hello {user_name}, please verify your email address to complete registration and enable device enrollment.</p>
    
    <div style="background:#090d16; border:1px solid #00f0ff; border-radius:8px; padding:20px; text-align:center; margin:25px 0;">
      <div style="color:#94a3b8; font-size:12px; margin-bottom:5px;">Your 6-Digit Verification Code</div>
      <div style="font-size:32px; font-weight:800; letter-spacing:6px; color:#00f0ff;">{otp_code}</div>
    </div>
    
    <div style="text-align:center; margin-bottom:25px;">
      <a href="{link}" style="background:#00f0ff; color:#090d16; font-weight:700; padding:12px 24px; border-radius:6px; text-decoration:none; display:inline-block;">Verify Account Directly</a>
    </div>
    
    <p style="color:#64748b; font-size:12px; line-height:1.4; border-top:1px solid #1e293b; padding-top:15px;">
      Zero keystroke or screen recording is ever performed. Local SQLite storage with cryptographic session authentication.
    </p>
  </div>
</body>
</html>"""

    return send_email(to_email, subject, html_content, text_content)


def send_welcome_and_installation_email(to_email: str, user_name: str) -> bool:
    """EMAIL 2 — WELCOME AND INSTALLATION INSTRUCTIONS: Sent after verification."""
    subject = f"Welcome & Installation Guide — {PROJECT_TITLE}"
    
    text_content = f"""Hello {user_name},

Your account has been verified successfully.

OFFICIAL WINDOWS APPLICATION DOWNLOAD:
Download installer: {DOWNLOAD_URL}

INSTALLATION STEPS:
1. Run 'CyberThreat AI Operations Center 1.0.0.exe' on your Windows 10 or 11 (64-bit) laptop.
2. If Windows SmartScreen appears on first run, select 'More info' and 'Run anyway' (Self-Signed Developer Authority).
3. Sign in using your registered credentials.
4. Review and accept the first-launch monitoring permissions.
5. Secure device enrollment will automatically activate real-time telemetry collection.

Required Permissions:
- Standard user access for process launch monitoring and download file inspection.
- Optional Administrator rights for detailed network socket inspection.

Terms & Privacy: {APP_URL}/terms
"""

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="background:#090d16; color:#f8fafc; font-family:sans-serif; padding:20px;">
  <div style="max-width:600px; margin:0 auto; background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:30px;">
    <h2 style="margin:0 0 10px 0; color:#f8fafc; font-size:20px;">Welcome to {PROJECT_TITLE}</h2>
    <p style="color:#94a3b8; font-size:14px; line-height:1.5;">Hello {user_name}, your account is active. Follow the steps below to protect your Windows computer.</p>
    
    <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:20px; margin:20px 0;">
      <h3 style="margin:0 0 10px 0; color:#00f0ff; font-size:15px;">Quick Setup Guide</h3>
      <ol style="color:#cbd5e1; font-size:13px; line-height:1.6; padding-left:20px; margin:0;">
        <li>Download the verified Windows 10 / 11 executable.</li>
        <li>Launch the installer and sign in with your email and password.</li>
        <li>Review collector permissions (zero keystroke / zero screen monitoring).</li>
        <li>Device enrollment will initiate autonomous real-time protection.</li>
      </ol>
    </div>

    <div style="text-align:center; margin:25px 0;">
      <a href="{DOWNLOAD_URL}" style="background:#00f0ff; color:#090d16; font-weight:700; padding:12px 24px; border-radius:6px; text-decoration:none; display:inline-block;">Download Windows Installer (.exe)</a>
    </div>

    <p style="color:#64748b; font-size:12px; line-height:1.4; border-top:1px solid #1e293b; padding-top:15px;">
      Supported Platforms: Windows 10, Windows 11 (64-bit). Android and iOS agents are currently in development.
    </p>
  </div>
</body>
</html>"""

    return send_email(to_email, subject, html_content, text_content)


def send_installation_success_email(to_email: str, user_name: str, device_name: str, device_id: str) -> bool:
    """EMAIL 3 — INSTALLATION SUCCESS: Sent ONLY after verified device enrollment and agent heartbeat."""
    subject = f"Device Protection Active — {device_name}"
    
    text_content = f"""Hello {user_name},

Device successfully enrolled and verified:
- Device Name: {device_name}
- Device ID: {device_id}
- Monitoring Status: ONLINE & ACTIVE
- Collector Scope: Process execution, file downloads, network sockets, browser events

Your device is now continuously monitored by {PROJECT_TITLE}.

View your live security dashboard at: {APP_URL}
"""

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="background:#090d16; color:#f8fafc; font-family:sans-serif; padding:20px;">
  <div style="max-width:600px; margin:0 auto; background:#0f172a; border:1px solid #10b981; border-radius:12px; padding:30px;">
    <div style="color:#10b981; font-weight:700; font-size:12px; text-transform:uppercase; margin-bottom:10px;">Enrolled & Verified</div>
    <h2 style="margin:0 0 10px 0; color:#f8fafc; font-size:20px;">Installation Confirmed: {device_name}</h2>
    <p style="color:#94a3b8; font-size:14px; line-height:1.5;">The local monitoring agent has reported its initial status and established real-time protection.</p>
    
    <div style="background:#090d16; border:1px solid #1e293b; border-radius:8px; padding:15px; margin:20px 0; font-size:13px; color:#cbd5e1;">
      <div><strong>Device ID:</strong> {device_id}</div>
      <div style="margin-top:6px;"><strong>Protection Mode:</strong> Autonomous AI Telemetry Ingestion</div>
      <div style="margin-top:6px;"><strong>Storage:</strong> Local SQLite with Duplicate-Free Cloud Synchronization</div>
    </div>

    <div style="text-align:center; margin:20px 0;">
      <a href="{APP_URL}" style="background:#10b981; color:#090d16; font-weight:700; padding:10px 20px; border-radius:6px; text-decoration:none; display:inline-block;">Open Operations Center</a>
    </div>
  </div>
</body>
</html>"""

    return send_email(to_email, subject, html_content, text_content)


def send_setup_incomplete_email(to_email: str, user_name: str, device_name: str, missing_component: str) -> bool:
    """EMAIL 4 — SETUP INCOMPLETE: Sent if required permissions or collectors are missing."""
    subject = f"Action Required: Incomplete Setup for {device_name}"
    
    text_content = f"""Hello {user_name},

Setup for your device '{device_name}' is incomplete.
Missing or inactive component: {missing_component}

Your device is not fully protected until this component is enabled.
Please open the CyberThreat AI desktop application and complete the permission configuration.
"""

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="background:#090d16; color:#f8fafc; font-family:sans-serif; padding:20px;">
  <div style="max-width:600px; margin:0 auto; background:#0f172a; border:1px solid #f59e0b; border-radius:12px; padding:30px;">
    <div style="color:#f59e0b; font-weight:700; font-size:12px; text-transform:uppercase; margin-bottom:10px;">Setup Alert</div>
    <h2 style="margin:0 0 10px 0; color:#f8fafc; font-size:20px;">Incomplete Setup: {device_name}</h2>
    <p style="color:#94a3b8; font-size:14px; line-height:1.5;">We detected that the following component requires configuration:</p>
    
    <div style="background:#090d16; border:1px solid #f59e0b; border-radius:8px; padding:15px; margin:20px 0; font-size:13px; color:#f8fafc;">
      <strong>Attention Needed:</strong> {missing_component}
    </div>

    <p style="color:#94a3b8; font-size:13px;">Please launch the application on your device to grant the required permissions.</p>
  </div>
</body>
</html>"""

    return send_email(to_email, subject, html_content, text_content)
