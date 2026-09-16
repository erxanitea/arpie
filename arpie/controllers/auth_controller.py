import datetime

from ..middleware.mfa import verify as mfa_verify
from ..network import detect_network_context


class AuthController:

    def __init__(self, app):
        self.app = app

    def verify_mfa_login(self, code: str) -> tuple[bool, str]:
        app = self.app
        op = app._pending_operator
        if not op:
            return False, "No pending MFA session."
        secret = app.db.get_totp_secret(op["username"])
        if not secret:
            return False, "TOTP not configured."
        if mfa_verify(secret, code) or app.db.consume_recovery_code(op["username"], code):
            self.complete_login(op)
            return True, ""
        return False, "Invalid or expired code. Try again."

    def cancel_mfa_login(self):
        self.app._pending_operator = None
        self.app.current_screen = "login"
        self.app.render()

    def complete_login(self, operator: dict):
        app = self.app
        app.operator_id = operator.get("id")
        app.user_name = operator.get("display_name") or operator.get("username", "")
        app.user_role = operator.get("role", "End User")
        app.operator_username = operator.get("username", "")
        app.operator_email = operator.get("email", "")
        app.operator_last_login = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        app.network_context = detect_network_context()
        app._restore_session_from_db()
        app._pending_operator = None
        app.current_screen = "context"
        app.render()