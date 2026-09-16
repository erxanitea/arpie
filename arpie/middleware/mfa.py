"""
TOTP two-factor authentication (RFC 6238), implemented on the standard library
so Arpie gains optional 2FA with no extra dependency.

Compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.:
HMAC-SHA1, 30-second step, 6 digits, base32 secret. `verify` accepts a ±1 step
window to tolerate clock skew.
"""

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

_STEP = 30
_DIGITS = 6


def available() -> bool:
    return True


def generate_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int, digits: int = _DIGITS) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    bincode = (
        ((mac[offset] & 0x7F) << 24)
        | (mac[offset + 1] << 16)
        | (mac[offset + 2] << 8)
        | mac[offset + 3]
    )
    return str(bincode % (10 ** digits)).zfill(digits)


def totp(secret: str, at: float | None = None, step: int = _STEP, digits: int = _DIGITS) -> str:
    counter = int((at if at is not None else time.time()) // step)
    return _hotp(secret, counter, digits)


def verify(secret: str, code: str, window: int = 1, step: int = _STEP, digits: int = _DIGITS) -> bool:
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = int(time.time() // step)
    for w in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret, now + w, digits), code):
            return True
    return False


def provisioning_uri(secret: str, account_name: str, issuer: str = "Arpie") -> str:
    label = quote(f"{issuer}:{account_name}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={_DIGITS}&period={_STEP}")


def generate_recovery_codes(count: int = 8) -> list[str]:
    codes = []
    for _ in range(count):
        raw = os.urandom(4).hex()
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def generate_qr_base64(uri: str) -> str:
    import io
    try:
        import qrcode  # type: ignore[import-untyped]
        img = qrcode.make(uri, box_size=6, border=2)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        encoded = base64.b64encode(buf.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except ImportError:
        return ""
