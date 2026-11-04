"""
Native Windows Toast Notification Dispatcher for CyberThreat AI System.

Dispatches actual Windows Action Center notifications directly to the desktop
of the specific host running the monitoring agent.
"""

import sys
import threading
from typing import Optional

def _dispatch_toast_thread(title: str, message: str, status: str):
    try:
        from winotify import Notification, audio
        
        # Audio sound and priority based on severity
        sound = audio.Default
        if status.upper() in ("DANGEROUS", "THREAT_DETECTED"):
            sound = audio.LoopingAlarm
        elif status.upper() == "SUSPICIOUS":
            sound = audio.Reminder

        toast = Notification(
            app_id="CyberThreat AI",
            title=title,
            msg=message[:180],
            duration="short"
        )
        try:
            toast.set_audio(sound, loop=False)
        except Exception:
            pass
        toast.show()
    except Exception as e:
        # Fallback to quiet console notice if winotify is unavailable
        pass

def send_windows_toast(title: str, message: str, status: str = "SAFE"):
    """
    Sends native Windows notification asynchronously without blocking monitoring loops.
    """
    t = threading.Thread(
        target=_dispatch_toast_thread,
        args=(title, message, status),
        daemon=True,
        name="WindowsToastDispatcher"
    )
    t.start()
