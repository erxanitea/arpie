from arpie.forms.auth import validate_email, validate_password, password_strength


def test_email_rejects_malformed():
    for bad in ("", "nope", "a@b", "a b@c.com", "@x.com", "x@y."):
        assert validate_email(bad)[0] is False
    for good in ("a@b.com", "era.dumangcas@example.co", "user+tag@sub.domain.org"):
        assert validate_email(good)[0] is True


def test_password_minimum_and_composition():
    assert validate_password("short1")[0] is False          # < 8
    assert validate_password("abcdefgh")[0] is False         # no digit
    assert validate_password("12345678")[0] is False         # no letter (also common)
    assert validate_password("Secret123")[0] is True


def test_password_rejects_common_and_identity():
    assert validate_password("password1")[0] is False
    assert validate_password("era12345", username="era12345")[0] is False
    assert validate_password("erauser1", username="x", email="erauser1@x.com")[0] is False


def test_password_strength_monotonic():
    assert password_strength("abc")[0] <= password_strength("abcdefgh")[0]
    assert password_strength("Secret123!")[0] >= password_strength("secret12")[0]
