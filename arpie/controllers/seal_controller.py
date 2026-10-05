import ipaddress

from arpie.middleware.auth import can_manage_operators, is_authenticated
from arpie.security import SealManager


class SealController:

    def __init__(self, app):
        self.app = app

    def activate(self, dialog, target_ip=None, event_id=None):
        app = self.app
        target_ip = target_ip or (app.selected_alert or {}).get("source")
        if not target_ip:
            app.status_toast = "Select an alert with a source host before activating Seal Mode."
            return None
        return self.block_ip(target_ip, dialog, "Emergency Seal", event_id=event_id)

    def block_ip(self, ip: str, dialog=None, label="Isolation", event_id=None):
        app = self.app
        if not is_authenticated(app):
            app.status_toast = "Sign in is required before using Seal Mode."
            return None
        if not can_manage_operators(app):
            app.status_toast = "Evaluator / Administrator privileges are required for Seal Mode."
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            app.status_toast = f"Invalid host address: {ip}"
            return None
        if (address.is_loopback or address.is_unspecified or address.is_multicast
                or address.is_reserved or address.is_link_local):
            app.status_toast = f"Refusing to block unsafe address: {ip}"
            return None
        ctx = getattr(app, "network_context", None)
        if ip in {getattr(app, "local_ip", None), getattr(ctx, "gateway_ip", None)}:
            app.status_toast = "Refusing to block this endpoint or the active gateway."
            return None
        if dialog is not None:
            app.close_dialog(dialog)
        if app.session_id and not app.seal_mgr:
            app.seal_mgr = SealManager(app.db, app.session_id)
        if not app.seal_mgr:
            app.status_toast = "Seal Mode is unavailable until a monitoring session is active."
            return None
        result = app.seal_mgr.seal(ip, event_id=event_id, confirmed_by_user=True)
        if result.success and ip not in app.active_blocks:
            app.active_blocks.append(ip)
        app.status_toast = f"{label} result: {result.message}"
        app.update_view_content()
        app.page.update()
        return result

    def unblock_ip(self, ip: str):
        app = self.app
        if not is_authenticated(app) or not can_manage_operators(app):
            app.status_toast = "Evaluator / Administrator privileges are required for Seal Mode."
            return None
        if app.seal_mgr:
            result = app.seal_mgr.unseal(ip, confirmed_by_user=True)
            app.status_toast = f"Unseal: {result.message}"
            if result.success and ip in app.active_blocks:
                app.active_blocks.remove(ip)
        else:
            app.status_toast = "Seal Mode has no active session."
        app.update_view_content()
        app.page.update()
        return result if app.seal_mgr else None