"""Tests for log secret redaction.

The redaction must hold for *every* logger in the process, including application
loggers such as ``app.services.gemini_service`` that propagate to the root
handler. Two earlier defects are guarded against explicitly:

  * a filter attached only to the root / ``app`` logger did not apply to records
    emitted by ``app.services.*`` (Python filters a record on its originating
    logger only, then propagates to handlers unfiltered);
  * masking appended ``:***REDACTED***`` after a matched API key instead of
    removing it, leaving the credential fully readable in the log.
"""

from __future__ import annotations

import io
import logging

import pytest

from app.core.logging_config import (
    REDACTED,
    SecretRedactionFilter,
    install_secret_redaction,
    redact,
)

AIZA = "AIzaSyFAKEfakefakefakefakefakefakefake"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlSGVyZQ"
GENERIC = "supersecretvalue12345"


@pytest.fixture
def filt() -> SecretRedactionFilter:
    return SecretRedactionFilter(extra_values=[GENERIC])


@pytest.fixture
def captured():
    """Capture output from any logger, installed after redaction is set up."""
    install_secret_redaction()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    yield stream
    root.removeHandler(handler)
    root.setLevel(previous_level)


def assert_clean(text: str, *secrets: str) -> None:
    for secret in secrets:
        assert secret not in text, f"secret leaked into log output: {text!r}"


# --------------------------------------------------------------------------
# redact_text
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text,secret",
    [
        (f"calling Gemini with {AIZA}", AIZA),
        (f"token {JWT} expired", JWT),
        (f"Authorization: Bearer {GENERIC}", GENERIC),
        (f"api_key={GENERIC}", GENERIC),
        (f'password: "{GENERIC}"', GENERIC),
        (f"access_token={GENERIC}", GENERIC),
        (f"gemini_api_key={GENERIC}", GENERIC),
        (f"client_secret={GENERIC}", GENERIC),
    ],
)
def test_credentials_are_removed(filt, text, secret):
    assert_clean(filt.redact_text(text), secret)
    assert REDACTED in filt.redact_text(text)


def test_configured_values_are_removed_anywhere(filt):
    """A secret we know about is masked even with no recognisable shape."""
    text = f"value was {GENERIC} during startup"
    assert_clean(filt.redact_text(text), GENERIC)


def test_short_configured_values_are_not_registered():
    """Very short strings would redact unrelated text, so they are ignored."""
    f = SecretRedactionFilter(extra_values=["ab", "abcd", "abcde"])
    assert f.redact_text("ab cd abcde") == "ab cd abcde"


def test_redaction_is_idempotent(filt):
    once = filt.redact_text(f"key={AIZA} and {GENERIC}")
    assert filt.redact_text(once) == once


def test_redaction_preserves_useful_context(filt):
    """The operator should still see *what* failed, just not the value."""
    out = filt.redact_text(f"gemini_api_key={AIZA} rejected for project cyber-123")
    assert "gemini_api_key=" in out
    assert "cyber-123" in out
    assert_clean(out, AIZA)


def test_benign_text_is_untouched(filt):
    text = "scan finished: 12 findings, report written to ./reports/scan-3.pdf"
    assert filt.redact_text(text) == text


# --------------------------------------------------------------------------
# redact() helper
# --------------------------------------------------------------------------

def test_redact_masks_sensitive_dict_keys(filt):
    out = redact({"password": GENERIC, "user": "alice", "token": "abc"})
    assert out["password"] == REDACTED
    assert out["token"] == REDACTED
    assert out["user"] == "alice"


def test_redact_walks_nested_structures(filt):
    out = redact({"outer": [{"api_key": AIZA}, "plain"]})
    assert out["outer"][0]["api_key"] == REDACTED
    assert out["outer"][1] == "plain"


def test_redact_leaves_non_strings_alone(filt):
    assert redact(42) == 42
    assert redact(None) is None


# --------------------------------------------------------------------------
# Process-wide coverage: the regression that leaked a real API key
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "logger_name",
    [
        "app.services.gemini_service",
        "app.api.auth",
        "app.core.security",
        "app.services.user_service",
        "some.third.party.library",
        "rootish",
    ],
)
def test_every_logger_is_covered(captured, logger_name):
    logging.getLogger(logger_name).error("failed for %s", AIZA)
    assert_clean(captured.getvalue(), AIZA)
    assert REDACTED in captured.getvalue()


def test_propagated_child_record_is_redacted(captured):
    """The specific case a root-logger filter misses."""
    child = logging.getLogger("app.services.deeply.nested")
    # The record travels up through real intermediate loggers to the root
    # handler, so only the record factory can have scrubbed it.
    assert child.name.count(".") == 3
    assert child.parent is not logging.getLogger()
    assert child.propagate is True
    child.error("key %s", AIZA)
    assert_clean(captured.getvalue(), AIZA)


def test_assembled_message_is_redacted(captured):
    """The pattern exists only after the format string meets the argument."""
    logging.getLogger("app.api.auth").warning("api_key=%s", GENERIC)
    text = captured.getvalue()
    assert_clean(text, GENERIC)
    assert "api_key=" in text


def test_authorization_header_is_redacted(captured):
    logging.getLogger("uvicorn.access").info(
        "request headers: %s", {"authorization": f"Bearer {GENERIC}"}
    )
    assert_clean(captured.getvalue(), GENERIC)


def test_exception_text_is_not_leaked(captured):
    """A secret inside an exception message must not reach the log."""
    logging.getLogger("app.services.gemini").error(
        "call failed: %s", ValueError(f"invalid key {AIZA}")
    )
    assert_clean(captured.getvalue(), AIZA)


def test_benign_application_log_survives(captured):
    logging.getLogger("app.services.scan_service").info(
        "scan %s finished with %s findings", 7, 3
    )
    text = captured.getvalue()
    assert "scan 7 finished with 3 findings" in text


def test_install_is_idempotent(captured):
    install_secret_redaction()
    install_secret_redaction()
    logging.getLogger("app.services.gemini_service").error("k %s", AIZA)
    assert_clean(captured.getvalue(), AIZA)


def test_record_factory_is_installed():
    install_secret_redaction()
    factory = logging.getLogRecordFactory()
    assert getattr(factory, "_secret_redaction_installed", False)
