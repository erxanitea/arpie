"""
Cross-platform native OS desktop notification utility for Arpie.
Surfaces urgent intrusion alerts as system popups even when Arpie is in the background.
"""

import os
import platform
import subprocess
import shutil


def send_desktop_notification(title: str, message: str, severity: str = "critical"):
    """Fires a native OS popup notification (Linux notify-send / Windows toast / macOS osascript)."""
    current_os = platform.system()
    assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets"))
    logo_path = os.path.join(assets_dir, "arpie-logo.png")
    if not os.path.exists(logo_path):
        logo_path = os.path.join(assets_dir, "logo.png")

    try:
        if current_os == "Linux":
            if shutil.which("notify-send"):
                urgency = "critical" if severity in ("high", "critical") else "normal"
                icon = "dialog-error" if severity in ("high", "critical") else "dialog-warning"
                cmd = ["notify-send", "-a", "Arpie Endpoint NIDS", "-u", urgency, "-i", icon, title, message]
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


        elif current_os == "Windows":
            # PowerShell balloon notification
            ps_script = f"""
            [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null
            $notify = new-object system.windows.forms.notifyicon
            $notify.icon = [system.drawing.systemicons]::Information
            $notify.visible = $true
            $notify.showballoontip(10, '{title}', '{message}', [system.windows.forms.tooltipicon]::Warning)
            """
            subprocess.Popen(["powershell", "-Command", ps_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif current_os == "Darwin": # macOS
            apple_script = f'display notification "{message}" with title "{title}" subtitle "Arpie Threat Response"'
            subprocess.Popen(["osascript", "-e", apple_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass  # Never crash the NIDS engine if notification delivery fails
