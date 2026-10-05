"""Tests for login throttling and account-enumeration resistance.

  * progressive backoff after repeated failures
  * no permanent lockout (history expires, success clears it)
  * identical response for unknown accounts and wrong passwords
  * X-Forwarded-For is ignored unless explicitly trusted
  * legitimate users can still sign in
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.security import client_ip_from_request
from app.services.login_throttle import LoginThrottle, login_throttle


# --------------------------------------------------------------------------
# Backoff behaviour
# --------------------------------------------------------------------------

@pytest.fixture
def throttle():
    t = LoginThrottle(
        max_failures=3,
        base_delay=2,
        max_delay=20,
        window_seconds=60,
    )
    return t


def test_first_attempts_are_free(throttle):
    """A typo must never be punished."""
    key = throttle.make_key("1.2.3.4", "user@example.com")
    assert throttle.delay_for(key) == 0
    assert throttle.record_failure(key) == 0
    assert throttle.delay_for(key) == 0
    assert throttle.record_failure(key) == 0
    assert throttle.delay_for(key) == 0
    assert throttle.record_failure(key) == 0
    # Third failure is still within the free allowance.
    assert throttle.delay_for(key) == 0


def test_backoff_starts_after_the_threshold(throttle):
    """Failures up to the threshold are free; the next one is delayed."""
    key = throttle.make_key("1.2.3.4", "user@example.com")
    for _ in range(3):
        throttle.record_failure(key)
    # The fourth failure is the first over the threshold: one base delay.
    assert throttle.record_failure(key) == 2
    assert throttle.delay_for(key) > 0


def test_backoff_doubles_per_extra_failure(throttle):
    key = throttle.make_key("1.2.3.4", "user@example.com")
    for _ in range(3):
        throttle.record_failure(key)
    assert throttle.record_failure(key) == 2
    assert throttle.record_failure(key) == 4
    assert throttle.record_failure(key) == 8
    assert throttle.record_failure(key) == 16


def test_backoff_is_capped(throttle):
    key = throttle.make_key("1.2.3.4", "user@example.com")
    for _ in range(3):
        throttle.record_failure(key)
    for _ in range(20):
        delay = throttle.record_failure(key)
    assert delay == 20, "delay must never exceed LOGIN_MAX_DELAY_SECONDS"


def test_delay_counts_down(throttle):
    """A long backoff is reported as a shrinking wait, not a static one."""
    t = LoginThrottle(max_failures=1, base_delay=60, max_delay=60, window_seconds=600)
    key = t.make_key("1.2.3.4", "user@example.com")
    t.record_failure(key)
    t.record_failure(key)
    first = t.delay_for(key)
    assert first >= 30, f"expected a long wait, got {first}s"
    time.sleep(1.1)
    second = t.delay_for(key)
    assert second < first, f"the wait must shrink over time ({second} vs {first})"


def test_success_clears_the_history(throttle):
    key = throttle.make_key("1.2.3.4", "user@example.com")
    for _ in range(6):
        throttle.record_failure(key)
    assert throttle.failure_count(key) == 6
    throttle.record_success(key)
    assert throttle.failure_count(key) == 0
    assert throttle.delay_for(key) == 0


def test_history_expires_so_there_is_no_permanent_lockout(throttle):
    """An old burst must not keep a user locked out forever."""
    t = LoginThrottle(max_failures=1, base_delay=600, max_delay=600, window_seconds=1)
    key = t.make_key("1.2.3.4", "user@example.com")
    # One failure is within the allowance; the second trips the backoff.
    t.record_failure(key)
    assert t.delay_for(key) == 0
    t.record_failure(key)
    assert t.delay_for(key) > 0
    time.sleep(1.1)
    # History aged out: the user is allowed to try again.
    assert t.delay_for(key) == 0
    assert t.failure_count(key) == 0


def test_keys_are_normalised(throttle):
    """Casing must not hand an attacker a fresh budget."""
    a = throttle.make_key("1.2.3.4", "User@Example.com")
    b = throttle.make_key("1.2.3.4", "  user@example.com ")
    assert a == b
    c = throttle.make_key("1.2.3.4", "other@example.com")
    assert a != c


def test_different_clients_have_separate_budgets(throttle):
    a = throttle.make_key("1.1.1.1", "user@example.com")
    b = throttle.make_key("2.2.2.2", "user@example.com")
    for _ in range(5):
        throttle.record_failure(a)
    assert throttle.delay_for(a) > 0
    assert throttle.delay_for(b) == 0


def test_store_is_bounded(throttle):
    """Spraying many addresses must not grow the store without limit."""
    t = LoginThrottle(max_failures=1, base_delay=1, max_delay=1, window_seconds=0)
    for i in range(200):
        t.record_failure(t.make_key(f"10.0.{i // 256}.{i % 256}", "u@e.com"))
    # Advance the monotonic clock past the (deliberately zero) window. Windows
    # time.monotonic() has ~15ms granularity, so same-tick writes are kept.
    time.sleep(0.05)
    t.record_failure(t.make_key("10.9.9.9", "u@e.com"))
    assert t.size() <= 2, f"stale entries were never pruned (size={t.size()})"


def test_reset_clears_everything(throttle):
    throttle.record_failure(throttle.make_key("1.2.3.4", "u@e.com"))
    assert throttle.size() == 1
    throttle.reset()
    assert throttle.size() == 0


# --------------------------------------------------------------------------
# Client IP resolution
# --------------------------------------------------------------------------

class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, headers=None, host="10.0.0.1"):
        self.headers = headers or {}
        self.client = _FakeClient(host)


def test_forwarded_header_ignored_by_default(monkeypatch):
    """Trusting XFF unconditionally would let callers dodge the throttle."""
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
    request = _FakeRequest({"x-forwarded-for": "9.9.9.9", "x-real-ip": "8.8.8.8"})
    assert client_ip_from_request(request) == "10.0.0.1"


def test_forwarded_header_used_when_trusted(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    request = _FakeRequest({"x-forwarded-for": "9.9.9.9, 10.0.0.1"})
    assert client_ip_from_request(request) == "9.9.9.9"


def test_first_forwarded_hop_is_used(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    request = _FakeRequest({"x-forwarded-for": "  1.2.3.4 , 5.6.7.8"})
    assert client_ip_from_request(request) == "1.2.3.4"


def test_real_ip_used_when_no_forwarded_header(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    assert client_ip_from_request(_FakeRequest({"x-real-ip": "7.7.7.7"})) == "7.7.7.7"


def test_falls_back_to_peer_when_headers_absent(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    assert client_ip_from_request(_FakeRequest({}, host="4.4.4.4")) == "4.4.4.4"
    assert client_ip_from_request(_FakeRequest({}, host=None)) == "unknown"


# --------------------------------------------------------------------------
# End-to-end through the API
# --------------------------------------------------------------------------

def _login_client(monkeypatch, **throttle_settings):
    from app.core.config import Settings

    overrides = {
        "LOGIN_MAX_FAILED_ATTEMPTS": 3,
        "LOGIN_BASE_DELAY_SECONDS": 1,
        "LOGIN_MAX_DELAY_SECONDS": 8,
        "LOGIN_FAILURE_WINDOW_SECONDS": 60,
    }
    overrides.update(throttle_settings)
    for key, value in overrides.items():
        monkeypatch.setattr(settings, key, value)
    login_throttle.reset()
    from app.main import app

    return TestClient(app)


def test_unknown_email_and_wrong_password_are_indistinguishable(monkeypatch):
    """The response must not reveal whether an account exists."""
    client = _login_client(monkeypatch)
    with client:
        client.post(
            "/api/v1/auth/register",
            json={"email": "real@example.com", "username": "realuser", "password": "Str0ng!Passw0rd"},
        )

        wrong_password = client.post(
            "/api/v1/auth/login",
            json={"email": "real@example.com", "password": "WrongPassword123"},
        )
        unknown_email = client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "WrongPassword123"},
        )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()
    assert wrong_password.json()["detail"] == "Incorrect email or password"


def test_repeated_failures_are_throttled_with_429(monkeypatch):
    client = _login_client(monkeypatch, LOGIN_MAX_FAILED_ATTEMPTS=2)
    with client:
        statuses = []
        for _ in range(6):
            response = client.post(
                "/api/v1/auth/login",
                json={"email": "real@example.com", "password": "WrongPassword123"},
            )
            statuses.append(response.status_code)

    assert statuses[:2] == [401, 401], "the first attempts must be rejected normally"
    assert 429 in statuses, f"brute force was never throttled: {statuses}"
    # Once throttled it stays throttled for the same key.
    assert statuses[-1] == 429


def test_throttled_response_sets_retry_after(monkeypatch):
    client = _login_client(monkeypatch, LOGIN_MAX_FAILED_ATTEMPTS=1, LOGIN_BASE_DELAY_SECONDS=5)
    with client:
        for _ in range(3):
            response = client.post(
                "/api/v1/auth/login",
                json={"email": "real@example.com", "password": "WrongPassword123"},
            )
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert int(response.headers["Retry-After"]) > 0


def test_legitimate_user_can_still_log_in(monkeypatch):
    """Correct credentials must always work, even after other failures."""
    client = _login_client(monkeypatch, LOGIN_MAX_FAILED_ATTEMPTS=2)
    with client:
        client.post(
            "/api/v1/auth/register",
            json={"email": "real@example.com", "username": "realuser", "password": "Str0ng!Passw0rd"},
        )
        # Fail twice first.
        for _ in range(2):
            client.post(
                "/api/v1/auth/login",
                json={"email": "real@example.com", "password": "WrongPassword123"},
            )
        # Now the real password: the throttle must not have blocked it.
        good = client.post(
            "/api/v1/auth/login",
            json={"email": "real@example.com", "password": "Str0ng!Passw0rd"},
        )
    assert good.status_code == 200, good.text
    assert good.json()["token_type"] == "bearer"


def test_successful_login_resets_the_throttle(monkeypatch):
    client = _login_client(monkeypatch, LOGIN_MAX_FAILED_ATTEMPTS=2)
    with client:
        client.post(
            "/api/v1/auth/register",
            json={"email": "reset@example.com", "username": "resetuser", "password": "Str0ng!Passw0rd"},
        )
        for _ in range(2):
            client.post(
                "/api/v1/auth/login",
                json={"email": "reset@example.com", "password": "WrongPassword123"},
            )
        ok = client.post(
            "/api/v1/auth/login",
            json={"email": "reset@example.com", "password": "Str0ng!Passw0rd"},
        )
        assert ok.status_code == 200

        key = login_throttle.make_key("testclient", "reset@example.com")
        assert login_throttle.failure_count(key) == 0

        # A fresh burst is allowed the full allowance again.
        statuses = [
            client.post(
                "/api/v1/auth/login",
                json={"email": "reset@example.com", "password": "WrongPassword123"},
            ).status_code
            for _ in range(2)
        ]
    assert statuses == [401, 401]
