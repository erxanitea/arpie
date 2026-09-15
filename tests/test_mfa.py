import base64
from arpie import mfa


def test_rfc6238_test_vector():
    # RFC 6238 SHA1: ASCII secret '12345678901234567890' at T=59 -> 287082 (6 digits)
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.totp(secret, at=59) == "287082"


def test_generate_and_verify_roundtrip():
    secret = mfa.generate_secret()
    assert len(secret) == 32
    assert mfa.verify(secret, mfa.totp(secret)) is True


def test_verify_rejects_wrong_and_garbage():
    secret = mfa.generate_secret()
    assert mfa.verify(secret, "000000") is False
    assert mfa.verify(secret, "abcdef") is False
    assert mfa.verify(secret, "") is False
    assert mfa.verify("", "123456") is False


def test_provisioning_uri_shape():
    uri = mfa.provisioning_uri("ABCDEF", "user@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABCDEF" in uri
    assert "issuer=Arpie" in uri
