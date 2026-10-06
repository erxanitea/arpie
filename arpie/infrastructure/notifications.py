"""
Cross-platform native OS desktop notification utility for Arpie.
Surfaces urgent intrusion alerts as system popups even when Arpie is in the background.
"""

import os
import platform
import subprocess
import shutil
from contextlib import suppress


def send_desktop_notification(title: str, message: str, severity: str = "critical") -> bool:
    """Fires a native OS popup notification (Linux notify-send / Windows toast / macOS osascript)."""
    current_os = platform.system()
    assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets"))
    logo_path = os.path.join(assets_dir, "arpie-logo.png")
    if not os.path.exists(logo_path):
        logo_path = os.path.join(assets_dir, "logo.png")

    with suppress(Exception):
        if current_os == "Linux":
            if notify_send := shutil.which("notify-send"):
                urgency = "critical" if severity in {"high", "critical"} else "normal"
                icon = "dialog-error" if severity in {"high", "critical"} else "dialog-warning"
                cmd = [notify_send, "-a", "Arpie Endpoint NIDS", "-u", urgency, "-i", icon, title, message]

                # When Arpie is launched with sudo (needed for raw packet
                # capture), this process runs as root and has no access to
                # the desktop's D-Bus session bus, so notify-send silently
                # fails. Drop back to the invoking user's session via
                # runuser (no password needed, since the caller is already
                # root) and point it at that user's bus socket.
                sudo_uid = os.environ.get("SUDO_UID")
                sudo_user = os.environ.get("SUDO_USER")
                if os.geteuid() == 0 and sudo_uid and sudo_user and shutil.which("runuser"):
                    bus_addr = f"unix:path=/run/user/{sudo_uid}/bus"
                    cmd = [
                        "runuser", "-u", sudo_user, "--",
                        "env", f"DBUS_SESSION_BUS_ADDRESS={bus_addr}", f"XDG_RUNTIME_DIR=/run/user/{sudo_uid}",
                        *cmd,
                    ]

                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                if result.returncode != 0:
                    print(f"[notifications] notify-send failed (exit {result.returncode}): "
                          f"{result.stderr.decode(errors='replace').strip()}")
                return result.returncode == 0


        elif current_os == "Windows":
            # PowerShell balloon notification
            safe_title = title.replace("'", "''")
            safe_message = message.replace("'", "''")
            ps_script = f"""
            [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null
            $notify = new-object system.windows.forms.notifyicon
            $notify.icon = [system.drawing.systemicons]::Information
            $notify.visible = $true
            $notify.showballoontip(10, '{safe_title}', '{safe_message}', [system.windows.forms.tooltipicon]::Warning)
            """
            subprocess.Popen(["powershell", "-Command", ps_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        elif current_os == "Darwin": # macOS
            safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
            safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
            apple_script = f'display notification "{safe_message}" with title "{safe_title}" subtitle "Arpie Threat Response"'
            subprocess.Popen(["osascript", "-e", apple_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
    return False
