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
    """Always true — this is a stdlib implementation (kept for parity with
    other optional-capability modules)."""
    return True


def generate_secret() -> str:
    """A fresh base32 TOTP secret (160-bit, no padding)."""
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
    """Constant-time verify of a 6-digit code across a ±`window` step range."""
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
    """otpauth:// URI to add the account to an authenticator app (via QR or the
    secret shown for manual entry)."""
    label = quote(f"{issuer}:{account_name}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={_DIGITS}&period={_STEP}")
