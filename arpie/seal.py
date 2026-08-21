"""
Seal Mode — a reversible, user-confirmed temporary firewall rule that
blocks a suspicious host. Requires explicit confirmation (never applied
automatically), auto-restores after `auto_restore_seconds`, and every
action is written to the audit log via Database.log_action.

Platform notes:
- Windows: uses `netsh advfirewall firewall` rules.
- Linux: uses `iptables`.
Both require the process to run with administrator/root privileges;
if the underlying command fails (e.g. insufficient privileges), the
action is logged as failed and surfaced to the UI rather than silently
swallowed.
"""

import platform
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .db import Database


RULE_NAME_PREFIX = "Arpie_Seal_"


@dataclass
class SealResult:
    success: bool
    message: str


class SealManager:
    def __init__(self, db: Database, session_id: int, auto_restore_seconds: int = 1800):
        self.db = db
        self.session_id = session_id
        self.auto_restore_seconds = auto_restore_seconds
        self._sealed_targets: dict[str, threading.Timer] = {}

    def seal(self, target_ip: str, event_id: Optional[int], confirmed_by_user: bool) -> SealResult:
        if not confirmed_by_user:
            return SealResult(False, "Seal Mode requires explicit user confirmation.")

        result = self._apply_block(target_ip)
        self.db.log_action(
            self.session_id, event_id, action="seal", target=target_ip,
            confirmed_by_user=True,
            notes=result.message,
        )
        if result.success:
            timer = threading.Timer(self.auto_restore_seconds, self.unseal, args=[target_ip, event_id, False])
            timer.daemon = True
            timer.start()
            self._sealed_targets[target_ip] = timer
        return result

    def unseal(self, target_ip: str, event_id: Optional[int] = None, confirmed_by_user: bool = True) -> SealResult:
        result = self._remove_block(target_ip)
        note = result.message + (" (auto-restored)" if not confirmed_by_user else " (manual restore)")
        self.db.log_action(
            self.session_id, event_id, action="unseal", target=target_ip,
            confirmed_by_user=confirmed_by_user, notes=note,
        )
        timer = self._sealed_targets.pop(target_ip, None)
        if timer:
            timer.cancel()
        return result

    def sealed_targets(self):
        return list(self._sealed_targets.keys())

    # ---- platform-specific firewall calls ----
    def _rule_name(self, target_ip: str) -> str:
        return f"{RULE_NAME_PREFIX}{target_ip.replace('.', '_').replace(':', '_')}"

    def _apply_block(self, target_ip: str) -> SealResult:
        system = platform.system()
        rule = self._rule_name(target_ip)
        try:
            if system == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule}", "dir=in", "action=block", f"remoteip={target_ip}"],
                    check=True, capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule}_out", "dir=out", "action=block", f"remoteip={target_ip}"],
                    check=True, capture_output=True, timeout=10,
                )
            elif system == "Linux":
                subprocess.run(["iptables", "-I", "INPUT", "-s", target_ip, "-j", "DROP"],
                                check=True, capture_output=True, timeout=10)
                subprocess.run(["iptables", "-I", "OUTPUT", "-d", target_ip, "-j", "DROP"],
                                check=True, capture_output=True, timeout=10)
            else:
                return SealResult(False, f"Seal Mode not implemented for platform: {system}")
            return SealResult(True, f"Blocked {target_ip} via {system} firewall.")
        except subprocess.CalledProcessError as e:
            return SealResult(False, f"Failed to seal {target_ip}: {e}")
        except Exception as e:
            return SealResult(False, f"Failed to seal {target_ip} (requires admin/root): {e}")

    def _remove_block(self, target_ip: str) -> SealResult:
        system = platform.system()
        rule = self._rule_name(target_ip)
        try:
            if system == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                                check=False, capture_output=True, timeout=10)
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}_out"],
                                check=False, capture_output=True, timeout=10)
            elif system == "Linux":
                subprocess.run(["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"],
                                check=False, capture_output=True, timeout=10)
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", target_ip, "-j", "DROP"],
                                check=False, capture_output=True, timeout=10)
            else:
                return SealResult(False, f"Seal Mode not implemented for platform: {system}")
            return SealResult(True, f"Restored connectivity to {target_ip}.")
        except Exception as e:
            return SealResult(False, f"Failed to unseal {target_ip}: {e}")
