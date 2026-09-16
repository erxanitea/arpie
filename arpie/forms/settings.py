from pathlib import Path


def validate_threshold(name: str, value: str) -> tuple[bool, str]:
    value = (value or "").strip()
    if not value:
        return False, f"Threshold '{name}' cannot be empty."
    try:
        num = int(value)
    except ValueError:
        return False, f"Threshold '{name}' must be a whole number."
    if num < 1:
        return False, f"Threshold '{name}' must be at least 1."
    if num > 100_000:
        return False, f"Threshold '{name}' exceeds the maximum allowed value (100,000)."
    return True, ""


def validate_export_path(path_str: str) -> tuple[bool, str]:
    cleaned = (path_str or "").strip()
    if not cleaned:
        return False, "Export path cannot be empty."
    try:
        target = Path(cleaned).expanduser().resolve()
        if target.exists() and not target.is_dir():
            return False, "Path exists but is not a directory."
        return True, ""
    except Exception as exc:
        return False, f"Invalid path: {exc}"


def validate_api_key(key: str, name: str = "API key") -> tuple[bool, str]:
    key = (key or "").strip()
    if not key:
        return True, ""
    if len(key) < 8:
        return False, f"{name} appears too short to be valid."
    if " " in key or "\n" in key:
        return False, f"{name} must not contain whitespace."
    return True, ""
