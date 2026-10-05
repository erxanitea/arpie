from arpie.views.mixins._typing import MixinBase


class AuthMixin(MixinBase):
    """Thin delegation to ``auth_controller`` plus operator credential/rule editing."""

    def verify_mfa_login(self, code: str) -> tuple[bool, str]:
        return self.auth_controller.verify_mfa_login(code)

    def cancel_mfa_login(self):
        self.auth_controller.cancel_mfa_login()

    def _complete_login(self, operator: dict):
        self.auth_controller.complete_login(operator)

    def enable_totp(self, username: str) -> tuple[str, list[str]]:
        from arpie.middleware.mfa import generate_secret, generate_recovery_codes
        secret = generate_secret()
        codes = generate_recovery_codes(8)
        self.db.set_totp_secret(username, secret)
        self.db.set_recovery_codes(username, codes)
        return secret, codes

    def disable_totp(self, username: str):
        self.db.set_totp_secret(username, None)
        self.db.set_recovery_codes(username, None)

    def save_operator_credentials(self, username: str, current_pw: str, new_pw: str) -> tuple[bool, str]:
        display_name = (username or "").strip()
        if not display_name:
            return False, "Display name cannot be empty."

        operator = self.db.authenticate_operator(self.operator_username, current_pw)
        if not operator:
            return False, "Current password verification failed."

        if new_pw:
            if len(new_pw) < 4:
                return False, "New password must be at least 4 characters."
            self.db.update_operator_password(self.operator_username, new_pw)

        self.db.update_operator_display_name(self.operator_username, display_name)
        self.user_name = display_name
        return True, f"Account details for '{self.operator_username}' updated successfully."
