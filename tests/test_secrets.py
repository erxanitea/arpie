"""Secret storage must degrade gracefully when no OS keyring backend exists
(headless server / CI), never raising and never falling back to plaintext."""

from arpie.security import secrets_store


def test_secret_ops_never_raise_without_backend():
    # get returns str|None, set/delete/available return bool — regardless of
    # whether a keyring backend is present.
    assert secrets_store.get_secret("arpie_test_probe") is None or isinstance(
        secrets_store.get_secret("arpie_test_probe"), str)
    assert isinstance(secrets_store.set_secret("arpie_test_probe", "v"), bool)
    assert isinstance(secrets_store.delete_secret("arpie_test_probe"), bool)
    assert isinstance(secrets_store.available(), bool)
