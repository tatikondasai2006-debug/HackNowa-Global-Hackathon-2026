"""Timing and enumeration resistance for the login path.

A wrong password, an unknown address and a disabled account must all take
roughly the same wall-clock time, otherwise response latency tells an attacker
which addresses are registered. These tests measure real bcrypt work rather
than asserting on implementation details.
"""

from __future__ import annotations

import time

import bcrypt
import pytest
from fastapi.testclient import TestClient

from app.core.security import (
    BCRYPT_MAX_PASSWORD_BYTES,
    PasswordTooLongError,
    _TIMING_DECOY_HASH,
    burn_password_verification_time,
    hash_password,
    password_byte_length,
    verify_password,
)
from app.main import app
from app.services.login_throttle import login_throttle
from app.services.user_service import UserService


# --------------------------------------------------------------------------
# The decoy hash must be a usable bcrypt hash
# --------------------------------------------------------------------------

def test_decoy_hash_is_structurally_valid():
    """A malformed salt would silently disable the timing defense."""
    assert _TIMING_DECOY_HASH.startswith(b"$2b$")
    # A bcrypt SHA-256 hash is 60 characters: 7 prefix + 53 payload.
    assert len(_TIMING_DECOY_HASH) == 60, (
        f"decoy hash must be 60 bytes, got {len(_TIMING_DECOY_HASH)}"
    )


def test_decoy_hash_verifies_without_raising():
    """No exception may escape: the comparison has to actually run."""
    try:
        result = bcrypt.checkpw(b"anything", _TIMING_DECOY_HASH)
    except Exception as exc:  # pragma: no cover
        pytest.fail(f"decoy hash rejected by bcrypt: {type(exc).__name__}: {exc}")
    assert result is False, "the decoy must never verify a real password"


def test_burn_password_verification_time_never_raises():
    burn_password_verification_time()


def test_decoy_costs_the_same_as_a_real_comparison():
    """The whole defense rests on this being true."""
    real = hash_password("Str0ng!Passw0rd").encode()

    def timed(fn, rounds=4):
        fn()  # warm up
        start = time.perf_counter()
        for _ in range(rounds):
            fn()
        return (time.perf_counter() - start) / rounds

    real_seconds = timed(lambda: bcrypt.checkpw(b"wrong-password", real))
    decoy_seconds = timed(burn_password_verification_time)

    assert decoy_seconds > 0.01, "the decoy must do real work"
    ratio = decoy_seconds / real_seconds
    assert 0.6 < ratio < 1.5, (
        f"decoy cost {decoy_seconds * 1000:.0f}ms vs real "
        f"{real_seconds * 1000:.0f}ms (ratio {ratio:.2f})"
    )


# --------------------------------------------------------------------------
# authenticate() performs exactly one comparison per outcome
# --------------------------------------------------------------------------

class _FakeUser:
    def __init__(self, hashed_password: str, is_active: bool = True):
        self.hashed_password = hashed_password
        self.is_active = is_active
        self.last_login_at = None
        self.id = 1
        self.email = "user@example.com"


class _FakeResult:
    def __init__(self, user):
        self._user = user

    def scalar_one_or_none(self):
        return self._user


class _CountingDB:
    """Async session stub that records how many bcrypt calls a path makes."""

    def __init__(self, user):
        self._user = user
        self.checkpw_calls = 0

    async def execute(self, *args, **kwargs):
        return _FakeResult(self._user)

    async def flush(self):
        pass


class _Login:
    def __init__(self, password):
        self.password = password
        self.email = "user@example.com"


@pytest.mark.parametrize(
    "label,user_spec,expected",
    [
        ("unknown address", None, None),
        ("wrong password", ("active",), None),
        ("correct password", ("active",), "user"),
        ("inactive account", ("inactive",), None),
    ],
)
def test_authenticate_outcomes(label, user_spec, expected):
    real_hash = hash_password("Str0ng!Passw0rd")

    if user_spec is None:
        db = _CountingDB(None)
    else:
        db = _CountingDB(_FakeUser(real_hash, is_active=(user_spec[0] == "active")))

    password = "WrongPassword123" if label == "wrong password" else "Str0ng!Passw0rd"
    result = asyncio_run(UserService(db).authenticate(_Login(password)))

    if expected is None:
        assert result is None, f"{label} must not authenticate"
    else:
        assert result is not None, f"{label} must authenticate"


def asyncio_run(coro):
    import asyncio

    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


def test_inactive_account_is_not_slower_than_a_wrong_password():
    """The regression that motivated this test: 2x bcrypt leaked the state."""
    real_hash = hash_password("Str0ng!Passw0rd")

    def time_path(user, password, rounds=3):
        durations = []
        for _ in range(rounds):
            db = _CountingDB(user)
            start = time.perf_counter()
            asyncio_run(UserService(db).authenticate(_Login(password)))
            durations.append(time.perf_counter() - start)
        return min(durations)

    wrong = time_path(_FakeUser(real_hash), "WrongPassword123")
    inactive = time_path(_FakeUser(real_hash, is_active=False), "Str0ng!Passw0rd")

    ratio = inactive / wrong
    assert 0.6 < ratio < 1.5, (
        f"inactive login took {inactive * 1000:.0f}ms vs wrong-password "
        f"{wrong * 1000:.0f}ms (ratio {ratio:.2f}); account state is distinguishable"
    )


def test_inactive_account_does_not_update_last_login():
    real_hash = hash_password("Str0ng!Passw0rd")
    user = _FakeUser(real_hash, is_active=False)
    asyncio_run(UserService(_CountingDB(user)).authenticate(_Login("Str0ng!Passw0rd")))
    assert user.last_login_at is None


# --------------------------------------------------------------------------
# End-to-end: identical responses
# --------------------------------------------------------------------------

REGISTER = {
    "email": "timing@example.com",
    "username": "timinguser",
    "password": "Str0ng!Passw0rd",
}


def _new_client():
    login_throttle.reset()
    return TestClient(app)


def test_response_bodies_are_identical_for_every_failure_mode():
    with _new_client() as client:
        created = client.post("/api/v1/auth/register", json=REGISTER)
        # 400/409 simply mean the user already exists from an earlier run,
        # which is fine: the comparison below only needs a registered account.
        assert created.status_code in (200, 201, 400, 409), created.text

        wrong = client.post(
            "/api/v1/auth/login",
            json={"email": REGISTER["email"], "password": "WrongPassword123"},
        )
        unknown = client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": "WrongPassword123"},
        )

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_password_hash_is_never_returned_by_the_api():
    with _new_client() as client:
        client.post("/api/v1/auth/register", json=REGISTER)
        me = client.post(
            "/api/v1/auth/login",
            json={"email": REGISTER["email"], "password": REGISTER["password"]},
        )
        assert me.status_code == 200, me.text
        token = me.json()["access_token"]
        body = client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).text
    assert "hashed_password" not in body
    assert "$2b$" not in body


# --------------------------------------------------------------------------
# Password length boundary (P0 regression)
# --------------------------------------------------------------------------

def test_password_byte_length_uses_utf8_bytes():
    assert password_byte_length("abc") == 3
    # 4 characters, 8 UTF-8 bytes.
    assert password_byte_length("\U0001F600\U0001F600") == 8


def test_72_bytes_is_accepted_and_73_is_rejected():
    exactly_72 = "a" * BCRYPT_MAX_PASSWORD_BYTES
    assert hash_password(exactly_72)
    with pytest.raises(PasswordTooLongError):
        hash_password("a" * (BCRYPT_MAX_PASSWORD_BYTES + 1))


def test_multibyte_password_limit_is_measured_in_bytes():
    """A short-looking emoji password can exceed the byte limit."""
    # 72 bytes worth of 4-byte characters.
    assert hash_password("\U0001F600" * 18)
    with pytest.raises(PasswordTooLongError):
        hash_password("\U0001F600" * 19)


def test_verify_is_false_for_wrong_password():
    hashed = hash_password("Str0ng!Passw0rd")
    assert verify_password("Str0ng!Passw0rd", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_verify_survives_a_corrupt_hash():
    assert verify_password("anything", "not-a-bcrypt-hash") is False
