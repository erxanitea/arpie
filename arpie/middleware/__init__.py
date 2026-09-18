"""
Middleware — cross-cutting security concerns applied at controller entry:
role policy, session validity, and multi-factor authentication.

The packet detection pipeline lives in ``arpie.detection``; it is core domain,
not a cross-cutting concern.
"""

from arpie.middleware.auth import (
    is_evaluator,
    require_role,
    require_evaluator,
    is_authenticated,
    check_session_valid,
    can_manage_operators,
    can_manage_system_settings,
    ROLE_EVALUATOR,
    ROLE_END_USER,
    VALID_ROLES,
)
from arpie.middleware.mfa import (
    available as mfa_available,
    generate_secret,
    totp,
    verify,
    provisioning_uri,
    generate_recovery_codes,
    generate_qr_base64,
)

__all__ = [
    "is_evaluator",
    "require_role",
    "require_evaluator",
    "is_authenticated",
    "check_session_valid",
    "can_manage_operators",
    "can_manage_system_settings",
    "ROLE_EVALUATOR",
    "ROLE_END_USER",
    "VALID_ROLES",
    "mfa_available",
    "generate_secret",
    "totp",
    "verify",
    "provisioning_uri",
    "generate_recovery_codes",
    "generate_qr_base64",
]
