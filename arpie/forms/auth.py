import re

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MIN_PASSWORD_LENGTH = 8

_COMMON_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "qwerty123",
    "11111111", "abc12345", "letmein1", "admin123", "iloveyou1",
    "welcome1", "changeme", "passw0rd", "qwertyuiop",
}

MIN_USERNAME_LENGTH = 3


def validate_email(email: str) -> tuple[bool, str]:
    email = (email or "").strip()
    if not email:
        return False, "Email is required."
    if len(email) > 254:
        return False, "Email address is too long."
    if not _EMAIL_RE.match(email):
        return False, "Enter a valid email address (e.g. name@example.com)."
    return True, ""


def validate_password(password: str, username: str = "", email: str = "") -> tuple[bool, str]:
    pw = password or ""
    if len(pw) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if not re.search(r"[A-Za-z]", pw):
        return False, "Password must include at least one letter."
    if not re.search(r"\d", pw):
        return False, "Password must include at least one number."
    if pw.lower() in _COMMON_PASSWORDS:
        return False, "That password is too common — choose something less guessable."
    if username and pw.lower() == username.strip().lower():
        return False, "Password must not be the same as your username."
    if email:
        local = email.strip().lower().split("@")[0]
        if local and pw.lower() == local:
            return False, "Password must not be the same as your email."
    return True, ""


def password_strength(password: str) -> tuple[int, str]:
    pw = password or ""
    score = 0
    if len(pw) >= MIN_PASSWORD_LENGTH:
        score += 1
    if len(pw) >= 12:
        score += 1
    if re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw):
        score += 1
    if re.search(r"[^A-Za-z0-9]", pw):
        score += 1
    label = ["Very weak", "Weak", "Fair", "Good", "Strong"][max(0, min(4, score))]
    return score, label


def validate_username(username: str) -> tuple[bool, str]:
    username = (username or "").strip()
    if not username:
        return False, "Username is required."
    if len(username) < MIN_USERNAME_LENGTH:
        return False, f"Username must be at least {MIN_USERNAME_LENGTH} characters."
    if not re.match(r"^[A-Za-z0-9_.-]+$", username):
        return False, "Username may only contain letters, digits, underscores, dots, or hyphens."
    return True, ""
