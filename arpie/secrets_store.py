"""
Secret storage for Arpie.

API keys (AbuseIPDB, IPinfo) are credentials, so they must not sit in plaintext
in the SQLite database. The correct place for a desktop app's secrets is the
operating system's secure store — Windows Credential Manager, macOS Keychain, or
the Linux Secret Service — accessed here via the ``keyring`` library.

Every call degrades gracefully: if ``keyring`` is missing or has no usable
backend (a headless server, CI), the functions return False/None instead of
raising, and the caller falls back to environment variables. Secrets are never
written to the database.
"""

from typing import Optional

_SERVICE = "Arpie"


def _keyring():
    try:
        import keyring  # type: ignore[import-not-found]
        return keyring
    except Exception:
        return None


def available() -> bool:
    """True only if a real OS secret backend is usable here."""
    kr = _keyring()
    if kr is None:
        return False
    try:
        backend = kr.get_keyring()
        # keyring ships a 'fail'/'null' backend when nothing real is available.
        name = backend.__class__.__name__.lower()
        if "fail" in name or "null" in name:
            return False
        kr.get_password(_SERVICE, "__probe__")
        return True
    except Exception:
        return False


def set_secret(name: str, value: str) -> bool:
    kr = _keyring()
    if kr is None or not value:
        return False
    try:
        kr.set_password(_SERVICE, name, value)
        return True
    except Exception:
        return False


def get_secret(name: str) -> Optional[str]:
    kr = _keyring()
    if kr is None:
        return None
    try:
        return kr.get_password(_SERVICE, name)
    except Exception:
        return None


def delete_secret(name: str) -> bool:
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.delete_password(_SERVICE, name)
        return True
    except Exception:
        return False
