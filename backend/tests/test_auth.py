"""Unit tests for password hashing and JWT token handling."""

import pytest
from pydantic import ValidationError

from app.core.security import (
    BCRYPT_MAX_PASSWORD_BYTES,
    PasswordTooLongError,
    create_access_token,
    decode_access_token,
    hash_password,
    password_byte_length,
    verify_password,
)
from app.schemas.user import PasswordChange, UserRegister


def test_password_hashing():
    password = "SecurePassword123!"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_jwt_token_generation_and_validation():
    payload = {"sub": "42", "email": "test@example.com"}
    token = create_access_token(payload)
    assert isinstance(token, str)
    decoded = decode_access_token(token)
    assert decoded["sub"] == "42"
    assert decoded["email"] == "test@example.com"


# --- Password length / bcrypt 72-byte boundary -------------------------------
#
# bcrypt operates on bytes and refuses input longer than 72 bytes. The schemas
# must reject such passwords up front instead of letting the hashing layer raise
# (which previously surfaced as an internal error).

def _register_payload(password: str) -> dict:
    return {"email": "a@example.com", "username": "user1", "password": password}


def test_password_at_bcrypt_byte_limit_is_accepted():
    """Exactly 72 bytes must still work (regression: off-by-one)."""
    password = "A1" + "a" * (BCRYPT_MAX_PASSWORD_BYTES - 2)
    assert password_byte_length(password) == BCRYPT_MAX_PASSWORD_BYTES

    # Hashing succeeds and round-trips.
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True

    # The schema accepts it too.
    req = UserRegister(**_register_payload(password))
    assert req.password == password


def test_password_one_byte_over_limit_is_rejected_by_schema():
    password = "A1" + "a" * (BCRYPT_MAX_PASSWORD_BYTES - 1)
    assert password_byte_length(password) == BCRYPT_MAX_PASSWORD_BYTES + 1
    with pytest.raises(ValidationError) as exc:
        UserRegister(**_register_payload(password))
    assert "72 bytes" in str(exc.value)


def test_password_over_limit_is_rejected_by_hash_helper():
    """The hashing layer must raise a clean, typed error (not bcrypt's)."""
    password = "A1" + "a" * (BCRYPT_MAX_PASSWORD_BYTES - 1)
    with pytest.raises(PasswordTooLongError) as exc:
        hash_password(password)
    # No internal library wording leaks out.
    assert "72 bytes" in str(exc.value)
    assert "bcrypt" not in str(exc.value).lower()


def test_multibyte_password_limit_is_measured_in_bytes():
    """Character count is not the limit — UTF-8 byte length is."""
    # 30 three-byte characters = 90 bytes but only 30 characters.
    password = "\u4e00" * 30 + "Aa1"
    assert len(password) == 33
    assert password_byte_length(password) > BCRYPT_MAX_PASSWORD_BYTES
    with pytest.raises(ValidationError):
        UserRegister(**_register_payload(password))

    # 24 three-byte characters = 72 bytes exactly: allowed.
    ok_password = "\u4e00" * 23 + "Aa1"
    assert password_byte_length(ok_password) == BCRYPT_MAX_PASSWORD_BYTES
    assert UserRegister(**_register_payload(ok_password)).password == ok_password


def test_password_change_rejects_overlong_password():
    long_password = "A1" + "a" * (BCRYPT_MAX_PASSWORD_BYTES - 1)
    with pytest.raises(ValidationError):
        PasswordChange(current_password="SecurePassword123!", new_password=long_password)


def test_password_composition_rules_still_enforced():
    with pytest.raises(ValidationError, match="uppercase"):
        UserRegister(**_register_payload("lowercase123"))
    with pytest.raises(ValidationError, match="lowercase"):
        UserRegister(**_register_payload("UPPERCASE123"))
    with pytest.raises(ValidationError, match="digit"):
        UserRegister(**_register_payload("NoDigitsHere"))
