from arpie.security import SealManager


class SealController:

    def __init__(self, app):
        self.app = app

    def activate(self, dialog):
        return self.block_ip("192.168.1.50", dialog, "Emergency Seal")

    def block_ip(self, ip: str, dialog=None, label="Isolation"):
        app = self.app
        if dialog is not None:
            app.close_dialog(dialog)
        if ip not in app.active_blocks:
            app.active_blocks.append(ip)
        if app.session_id and not app.seal_mgr:
            app.seal_mgr = SealManager(app.db, app.session_id)
        if app.seal_mgr:
            result = app.seal_mgr.seal(ip, event_id=None, confirmed_by_user=True)
            app.status_toast = f"{label} result: {result.message}"
        else:
            app.status_toast = f"{label} activated: Host isolation applied."
        app.update_view_content()
        app.page.update()

    def unblock_ip(self, ip: str):
        app = self.app
        if ip in app.active_blocks:
            app.active_blocks.remove(ip)
        if app.seal_mgr:
            result = app.seal_mgr.unseal(ip, confirmed_by_user=True)
            app.status_toast = f"Unseal: {result.message}"
        else:
            app.status_toast = f"Host {ip} unblocked."
        app.update_view_content()
        app.page.update()