from functools import wraps

ROLE_EVALUATOR = "Evaluator/Administrator"
ROLE_END_USER = "End User"

VALID_ROLES = {ROLE_EVALUATOR, ROLE_END_USER}


def is_evaluator(user_role: str) -> bool:
    return user_role == ROLE_EVALUATOR


def require_role(allowed_role: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            app = args[0] if args else kwargs.get("app")
            if app is None:
                raise PermissionError("No application context available.")
            current_role = getattr(app, "user_role", None)
            if current_role != allowed_role:
                raise PermissionError(
                    f"Action requires '{allowed_role}' role, current role is '{current_role}'."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_evaluator(func):
    return require_role(ROLE_EVALUATOR)(func)


def is_authenticated(app) -> bool:
    return bool(getattr(app, "operator_id", None))


def check_session_valid(app) -> tuple[bool, str]:
    if not is_authenticated(app):
        return False, "Not authenticated."
    db = getattr(app, "db", None)
    if db is None:
        return False, "No database connection."
    username = getattr(app, "operator_username", "")
    if not username:
        return False, "No operator username in session."
    operator = db.get_operator_by_username(username)
    if operator is None:
        return False, "Operator account no longer exists."
    return True, ""


def can_manage_operators(app) -> bool:
    """Return whether the current authenticated operator may manage users."""
    return bool(getattr(app, "operator_id", None)) and getattr(app, "user_role", None) == ROLE_EVALUATOR


def can_manage_system_settings(app) -> bool:
    """Return whether the current operator may change evaluator settings."""
    return can_manage_operators(app)
