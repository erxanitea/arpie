from ..middleware.auth import ROLE_EVALUATOR


def can_manage_operators(app) -> bool:
    """Return whether the current authenticated operator may manage users."""
    return bool(getattr(app, "operator_id", None)) and getattr(app, "user_role", None) == ROLE_EVALUATOR


def can_manage_system_settings(app) -> bool:
    """Return whether the current operator may change evaluator settings."""
    return can_manage_operators(app)
