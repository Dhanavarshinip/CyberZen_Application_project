# update_browser_route.py
from pathlib import Path

p = Path(r"D:\CyberThreat_AI_System\backend\api\routes.py")
text = p.read_text(encoding="utf-8")

old_block = """        # If user_id is generic or missing, look up owner from device_id in database
        if (not user_id or user_id in ("current_user", "unpaired@cyberthreat.local", "")) and device_id:
            dev_rec = db.get_device(device_id)
            if dev_rec and dev_rec.get("user_id"):
                user_id = dev_rec["user_id"]
        
        if not user_id or user_id == "current_user":
            user_id = real_monitor.user_id if real_monitor else "current_user"
        if not device_id or device_id in ("DEV-LOCAL", "DEV-HOST", ""):
            device_id = real_monitor.device_id if real_monitor else f"DEV_CLIENT_{uuid.uuid4().hex[:6].upper()}"
        if not url:
            raise HTTPException(status_code=400, detail="URL is required.")

        # Zero-collection privacy pledge: drop any passwords, cookies, keystroke telemetry
        for forbidden in ("password", "passwords", "cookie", "cookies", "keystroke", "keystrokes", "keylog"):
            payload.pop(forbidden, None)

        # Check if device is revoked
        dev_info = db.get_device(device_id)
        if dev_info and dev_info.get("is_revoked"):
            raise HTTPException(status_code=403, detail="Device has been revoked. Telemetry collection is disabled.")

        # Online activities scope check: Only monitor registered Gmail or user-added allowed emails
        is_test = payload.get("is_test_event", False)
        browser_event_type = payload.get("browser_event_type", "WEBSITE_OPENED")
        if (browser_event_type == "GMAIL_INSPECTION" or "mail.google.com" in url.lower()) and not is_test:
            active_mailbox = payload.get("active_mailbox") or payload.get("mailbox_email") or payload.get("account_email")
            if active_mailbox and hasattr(db, "get_allowed_emails") and user_id and user_id not in ("current_user", "unpaired@cyberthreat.local", ""):
                allowed_emails = [e.lower() for e in db.get_allowed_emails(user_id)]
                if allowed_emails and active_mailbox.strip().lower() not in allowed_emails:
                    return {
                        "status": "SKIPPED",
                        "message": f"Mailbox {active_mailbox} is not in registered or allowed emails list. Monitoring paused for unapproved accounts.",
                        "monitored": False
                    }"""

new_block = """        # Check if the device is enrolled to a specific registered user
        enrolled_user = None
        if device_id:
            dev_rec = db.get_device(device_id)
            if dev_rec and dev_rec.get("user_id") and dev_rec["user_id"] not in ("current_user", "unpaired@cyberthreat.local", ""):
                enrolled_user = dev_rec["user_id"]
        
        # If payload specifies a valid registered user_id, use it
        if user_id and user_id not in ("current_user", "unpaired@cyberthreat.local", ""):
            effective_user = user_id
        elif enrolled_user:
            effective_user = enrolled_user
        else:
            effective_user = None

        user_id = effective_user or (real_monitor.user_id if (real_monitor and not device_id) else "unpaired_user")
        if not device_id or device_id in ("DEV-LOCAL", "DEV-HOST", ""):
            device_id = real_monitor.device_id if real_monitor else f"DEV_CLIENT_{uuid.uuid4().hex[:6].upper()}"
        if not url:
            raise HTTPException(status_code=400, detail="URL is required.")

        # Zero-collection privacy pledge: drop any passwords, cookies, keystroke telemetry
        for forbidden in ("password", "passwords", "cookie", "cookies", "keystroke", "keystrokes", "keylog"):
            payload.pop(forbidden, None)

        # Check if device is revoked
        dev_info = db.get_device(device_id)
        if dev_info and dev_info.get("is_revoked"):
            raise HTTPException(status_code=403, detail="Device has been revoked. Telemetry collection is disabled.")

        # Online activities scope check: Only monitor registered Gmail or user-added allowed emails
        is_test = payload.get("is_test_event", False)
        browser_event_type = payload.get("browser_event_type", "WEBSITE_OPENED")
        if (browser_event_type == "GMAIL_INSPECTION" or "mail.google.com" in url.lower()) and not is_test:
            active_mailbox = payload.get("active_mailbox") or payload.get("mailbox_email") or payload.get("account_email")
            if active_mailbox and effective_user and hasattr(db, "get_allowed_emails"):
                allowed_emails = [e.lower() for e in db.get_allowed_emails(effective_user)]
                if allowed_emails and active_mailbox.strip().lower() not in allowed_emails:
                    return {
                        "status": "SKIPPED",
                        "message": f"Mailbox {active_mailbox} is not in registered or allowed emails list. Monitoring paused for unapproved accounts.",
                        "monitored": False
                    }"""

norm_text = text.replace("\r\n", "\n")
norm_old = old_block.replace("\r\n", "\n")
norm_new = new_block.replace("\r\n", "\n")

if norm_old in norm_text:
    norm_text = norm_text.replace(norm_old, norm_new)
    p.write_text(norm_text, encoding="utf-8")
    print("[+] routes.py browser event handling updated cleanly")
else:
    print("[-] routes.py browser event handling match failed")
