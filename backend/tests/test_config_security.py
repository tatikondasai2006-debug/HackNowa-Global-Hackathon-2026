"""Tests for production configuration hardening (item 5).

  * ENVIRONMENT is normalised and drives is_production
  * startup validation refuses an unsafe production configuration
  * development never hard-fails on a warning, so local work is not blocked
  * /docs, /redoc and /openapi.json are off in production by default
  * CORS is explicit (no wildcard) and proxy headers are off by default
  * SecretStr keeps secrets out of repr / dict / JSON serialisation
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from app.core.config import (
    MIN_JWT_SECRET_LENGTH,
    InsecureConfigurationError,
    Settings,
)

BACKEND_DIR = Path(__file__).resolve().parents[1]

# A syntactically valid, clearly synthetic production secret.
GOOD_SECRET = "a" * 48
SAFE_CORS = "https://app.example.com"


def make_settings(**overrides) -> Settings:
    """Build a Settings instance with every relevant field pinned.

    Every field is passed explicitly so the developer's local .env cannot
    influence the result of a test.
    """
    base = {
        "ENVIRONMENT": "production",
        "DEBUG": False,
        "JWT_SECRET_KEY": GOOD_SECRET,
        "CORS_ORIGINS": SAFE_CORS,
        "GEMINI_API_KEY": "",
    }
    base.update(overrides)
    return Settings(**base)


# --------------------------------------------------------------------------
# ENVIRONMENT
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["production", "PRODUCTION", " prod ", "Prod"])
def test_production_aliases(raw):
    assert Settings(ENVIRONMENT=raw).is_production is True
    assert Settings(ENVIRONMENT=raw).ENVIRONMENT == "production"


@pytest.mark.parametrize("raw", ["development", "dev", "LOCAL", "development "])
def test_development_aliases(raw):
    s = Settings(ENVIRONMENT=raw)
    assert s.is_production is False
    assert s.ENVIRONMENT == "development"


@pytest.mark.parametrize("raw,expected", [("test", "test"), ("testing", "test"),
                                          ("staging", "staging"), ("stage", "staging")])
def test_other_environments_are_preserved(raw, expected):
    assert Settings(ENVIRONMENT=raw).ENVIRONMENT == expected
    assert Settings(ENVIRONMENT=raw).is_production is False


def test_unknown_environment_defaults_to_development():
    s = Settings(ENVIRONMENT="")
    assert s.ENVIRONMENT == "development"
    assert s.is_production is False


# --------------------------------------------------------------------------
# API docs
# --------------------------------------------------------------------------

def test_docs_enabled_in_development():
    assert Settings(ENVIRONMENT="development").api_docs_enabled is True


def test_docs_disabled_in_production_by_default():
    assert make_settings().api_docs_enabled is False


def test_docs_can_be_force_enabled_in_production():
    """An operator who accepts the risk can still expose the schema."""
    assert make_settings(ENABLE_API_DOCS=True).api_docs_enabled is True


def test_docs_can_be_force_disabled_in_development():
    assert Settings(ENVIRONMENT="development", ENABLE_API_DOCS=False).api_docs_enabled is False


# --------------------------------------------------------------------------
# Production startup validation
# --------------------------------------------------------------------------

def test_clean_production_config_passes():
    assert make_settings().validate_runtime_config() == []


def test_debug_true_in_production_is_fatal():
    with pytest.raises(InsecureConfigurationError) as exc:
        make_settings(DEBUG=True).validate_runtime_config()
    assert "DEBUG must be false" in str(exc.value)


def test_wildcard_cors_is_fatal_in_production():
    with pytest.raises(InsecureConfigurationError) as exc:
        make_settings(CORS_ORIGINS="*").validate_runtime_config()
    assert 'must not contain "*"' in str(exc.value)


def test_wildcard_cors_among_others_is_fatal():
    with pytest.raises(InsecureConfigurationError, match='must not contain'):
        make_settings(CORS_ORIGINS="https://app.example.com, *").validate_runtime_config()


def test_empty_cors_is_fatal_in_production():
    with pytest.raises(InsecureConfigurationError, match="at least one explicit origin"):
        make_settings(CORS_ORIGINS="").validate_runtime_config()
    with pytest.raises(InsecureConfigurationError, match="at least one explicit origin"):
        make_settings(CORS_ORIGINS=" , , ").validate_runtime_config()


def test_missing_jwt_secret_is_fatal_in_production():
    with pytest.raises(InsecureConfigurationError) as exc:
        make_settings(JWT_SECRET_KEY="").validate_runtime_config()
    assert "JWT_SECRET_KEY is not set" in str(exc.value)


def test_placeholder_jwt_secret_is_fatal_in_production():
    with pytest.raises(InsecureConfigurationError, match="example placeholder"):
        make_settings(
            JWT_SECRET_KEY="CHANGE_ME_TO_A_RANDOM_SECRET_KEY_AT_LEAST_32_CHARS"
        ).validate_runtime_config()
    with pytest.raises(InsecureConfigurationError, match="example placeholder"):
        make_settings(JWT_SECRET_KEY="changeme").validate_runtime_config()


def test_short_jwt_secret_is_fatal_in_production():
    with pytest.raises(InsecureConfigurationError) as exc:
        make_settings(JWT_SECRET_KEY="short-key").validate_runtime_config()
    assert f"at least {MIN_JWT_SECRET_LENGTH} characters" in str(exc.value)


def test_placeholder_gemini_key_is_fatal_in_production():
    with pytest.raises(InsecureConfigurationError, match="GEMINI_API_KEY"):
        make_settings(GEMINI_API_KEY="your_gemini_api_key_here").validate_runtime_config()


def test_unset_gemini_key_is_fine_in_production():
    """AI is optional; leaving the key out must not block a deployment."""
    assert make_settings(GEMINI_API_KEY="").validate_runtime_config() == []


def test_every_problem_is_reported_together():
    """Operators get the whole list, not one error per restart."""
    with pytest.raises(InsecureConfigurationError) as exc:
        make_settings(
            DEBUG=True, CORS_ORIGINS="*", JWT_SECRET_KEY="x"
        ).validate_runtime_config()
    message = str(exc.value)
    assert "DEBUG must be false" in message
    assert "must not contain" in message
    assert "at least" in message


def test_unsafe_development_config_warns_but_still_starts():
    """Local work must not be blocked by a production-only rule."""
    s = make_settings(
        ENVIRONMENT="development", DEBUG=True, CORS_ORIGINS="*", JWT_SECRET_KEY="x"
    )
    problems = s.validate_runtime_config()
    assert problems, "development should surface warnings"
    joined = " ".join(problems)
    assert "must not contain" in joined, "wildcard CORS is a real problem everywhere"
    assert "at least" in joined, "a short JWT secret is a real problem everywhere"


# --------------------------------------------------------------------------
# Ephemeral development JWT key
# --------------------------------------------------------------------------

def test_development_generates_ephemeral_key_when_unset():
    s = Settings(ENVIRONMENT="development", JWT_SECRET_KEY="")
    key = s.jwt_secret_key
    assert len(key) >= MIN_JWT_SECRET_LENGTH
    # Stable within the process, so tokens stay valid until restart.
    assert s.jwt_secret_key == key


def test_production_refuses_to_use_an_ephemeral_key():
    s = make_settings(JWT_SECRET_KEY="")
    with pytest.raises(InsecureConfigurationError):
        _ = s.jwt_secret_key


def test_explicit_secret_is_used_verbatim():
    assert make_settings().jwt_secret_key == GOOD_SECRET


# --------------------------------------------------------------------------
# Secret handling
# --------------------------------------------------------------------------

def test_secrets_are_absent_from_repr():
    s = make_settings(JWT_SECRET_KEY="super-secret-jwt-value-1234567890",
                      GEMINI_API_KEY="AIzaSyFAKEfakefakefakefakefakefake")
    text = repr(s) + str(s) + s.model_dump_json()
    assert "super-secret-jwt-value" not in text
    assert "AIzaSyFAKE" not in text


def test_secret_fields_are_masked_in_json_dump():
    s = make_settings(GEMINI_API_KEY="AIzaSyFAKEfakefakefakefakefakefake")
    dumped = s.model_dump(mode="json")
    assert "AIzaSyFAKE" not in json.dumps(dumped)
    assert dumped["GEMINI_API_KEY"] == "**********"


def test_secret_accessors_return_plaintext_for_sdk_use():
    s = make_settings(JWT_SECRET_KEY="the-jwt-value", GEMINI_API_KEY="the-gemini-value")
    assert s.jwt_secret_key == "the-jwt-value"
    assert s.gemini_api_key == "the-gemini-value"


def test_ai_enabled_reflects_key_presence():
    assert make_settings(GEMINI_API_KEY="real-key").is_ai_enabled is True
    assert make_settings(GEMINI_API_KEY="").is_ai_enabled is False


# --------------------------------------------------------------------------
# CORS parsing
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://a.com", ["https://a.com"]),
        ("https://a.com,https://b.com", ["https://a.com", "https://b.com"]),
        ("  https://a.com ,  https://b.com  ", ["https://a.com", "https://b.com"]),
        ("https://a.com,,https://b.com,", ["https://a.com", "https://b.com"]),
        ("", []),
        (" , , ", []),
    ],
)
def test_cors_parsing(raw, expected):
    assert Settings(CORS_ORIGINS=raw).cors_origins_list == expected


def test_wildcard_detection():
    assert Settings(CORS_ORIGINS="*").has_wildcard_cors_origin is True
    assert Settings(CORS_ORIGINS="https://a.com,*").has_wildcard_cors_origin is True
    assert Settings(CORS_ORIGINS="https://a.com").has_wildcard_cors_origin is False


def test_proxy_headers_off_by_default():
    """Trusting XFF by default would let callers spoof their IP."""
    assert Settings().TRUST_PROXY_HEADERS is False


# --------------------------------------------------------------------------
# Integration: docs are actually unreachable in production
# --------------------------------------------------------------------------

_PROBE = textwrap.dedent(
    """
    import json
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    result = {
        path: client.get(path).status_code
        for path in ("/docs", "/redoc", "/openapi.json", "/health")
    }
    print("PROBE_RESULT " + json.dumps(result))
    """
)


def _probe(**env) -> dict:
    """Import the real app in a clean subprocess with the given environment."""
    child_env = dict(os.environ)
    child_env.pop("PYTEST_CURRENT_TEST", None)
    child_env.update(env)
    proc = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", _PROBE],
        cwd=str(BACKEND_DIR),
        env=child_env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("PROBE_RESULT "):
            return json.loads(line[len("PROBE_RESULT "):])
    raise AssertionError(
        f"probe failed (rc={proc.returncode})\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


def test_docs_endpoints_are_reachable_in_development():
    result = _probe(
        ENVIRONMENT="development",
        DEBUG="false",
        CORS_ORIGINS=SAFE_CORS,
        DATABASE_URL="sqlite+aiosqlite:///./test_probe_dev.db",
    )
    assert result["/docs"] == 200
    assert result["/redoc"] == 200
    assert result["/openapi.json"] == 200
    assert result["/health"] == 200


def test_docs_endpoints_are_absent_in_production():
    result = _probe(
        ENVIRONMENT="production",
        DEBUG="false",
        CORS_ORIGINS=SAFE_CORS,
        JWT_SECRET_KEY=GOOD_SECRET,
        DATABASE_URL="sqlite+aiosqlite:///./test_probe_prod.db",
    )
    assert result["/docs"] == 404, "Swagger UI must not be served in production"
    assert result["/redoc"] == 404
    assert result["/openapi.json"] == 404, "the schema must not leak in production"
    # The API itself must still work.
    assert result["/health"] == 200


def test_production_startup_aborts_on_unsafe_config():
    """The process must refuse to serve rather than degrade silently."""
    script = textwrap.dedent(
        """
        from fastapi.testclient import TestClient
        from app.main import app
        try:
            with TestClient(app) as client:
                client.get("/health")
        except Exception as exc:
            print("REFUSED " + type(exc).__name__)
        else:
            print("STARTED")
        """
    )
    child_env = dict(os.environ)
    child_env.update(
        {
            "ENVIRONMENT": "production",
            "DEBUG": "true",  # fatal
            "CORS_ORIGINS": "*",  # fatal
            "JWT_SECRET_KEY": GOOD_SECRET,
            "DATABASE_URL": "sqlite+aiosqlite:///./test_probe_refuse.db",
        }
    )
    proc = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", script],
        cwd=str(BACKEND_DIR),
        env=child_env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert "REFUSED" in proc.stdout, (
        f"expected startup refusal\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
