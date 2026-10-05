"""Application configuration loaded from environment variables."""

import logging
import secrets
from typing import List, Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# Placeholder values that must never be used to run a production deployment.
INSECURE_JWT_SECRETS = frozenset(
    {
        "CHANGE_ME_TO_A_RANDOM_SECRET_KEY_AT_LEAST_32_CHARS",
        "change_me_to_a_random_secret_key_at_least_32_chars",
        "dev_secret_key_change_in_production_at_least_32_chars_long",
        "secret",
        "changeme",
    }
)

MIN_JWT_SECRET_LENGTH = 32

PLACEHOLDER_API_KEYS = frozenset(
    {
        "",
        "your_gemini_api_key_here",
        "your-gemini-api-key-here",
        "changeme",
        "change_me",
    }
)


class InsecureConfigurationError(RuntimeError):
    """Raised at startup when the configuration is unsafe for production."""


class Settings(BaseSettings):
    """Application settings with environment variable binding."""

    # Application
    APP_NAME: str = "CyberSentinel"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    # ENVIRONMENT drives production hardening. "production" (or "prod") makes
    # startup validation reject DEBUG mode, wildcard CORS and placeholder
    # secrets, and turns the API docs off unless explicitly re-enabled.
    ENVIRONMENT: str = "development"
    # Debug is off unless explicitly enabled. In production, leaving it on is a
    # startup error (see validate_runtime_config).
    DEBUG: bool = False

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./cybersentinel.db"
    # Schema management. False keeps the existing create_all behaviour used by
    # the SQLite development database; set true to run Alembic at startup.
    USE_ALEMBIC: bool = False

    # JWT Authentication
    # No default: an empty value makes development fall back to a randomly
    # generated ephemeral key (tokens then reset on restart) and makes
    # production fail fast. Never commit a real secret here.
    JWT_SECRET_KEY: SecretStr = SecretStr("")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Google Gemini AI (backend only — never expose to the frontend)
    # SecretStr keeps the key out of repr(), logs and accidental serialisation.
    GEMINI_API_KEY: SecretStr = SecretStr("")
    GEMINI_MODEL: str = "gemini-flash-latest"
    GEMINI_TIMEOUT_SECONDS: float = 20.0

    # Scanner Configuration
    # SCAN_TIMEOUT_SECONDS is the hard wall-clock budget for a single scan. When
    # exceeded the scan is cancelled and marked FAILED so jobs can never be
    # stranded in `pending`/`running` forever. Must exceed the slowest target.
    SCAN_TIMEOUT_SECONDS: int = 300
    # MAX_CONCURRENT_SCANS bounds how many scans may be pending/running at
    # once across all users. Enforced from the database, so slots are released
    # automatically when a scan reaches a terminal state. 0 disables scans.
    MAX_CONCURRENT_SCANS: int = 5
    # Rolling window for the per-user scan quota. Set to 0 or negative to
    # disallow scan creation entirely.
    SCAN_RATE_LIMIT_PER_HOUR: int = 20
    SCAN_RATE_LIMIT_WINDOW_SECONDS: int = 3600

    # Login throttling. Progressive backoff after repeated failed logins so a
    # single typo cannot cause a long lockout, while credential stuffing is
    # still slowed to a crawl.
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_BASE_DELAY_SECONDS: int = 5
    LOGIN_MAX_DELAY_SECONDS: int = 900
    LOGIN_FAILURE_WINDOW_SECONDS: int = 900

    # RAG Configuration
    CHROMA_PERSIST_DIR: str = "./chroma_db"
    RAG_COLLECTION_NAME: str = "cybersecurity_knowledge"

    # Report Configuration
    REPORT_OUTPUT_DIR: str = "./reports"

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    # Serve /docs, /redoc and /openapi.json. Auto-disabled in production
    # unless explicitly switched back on.
    ENABLE_API_DOCS: Optional[bool] = None
    # Honour X-Forwarded-For / X-Real-IP. Only enable behind a proxy you
    # control, otherwise clients can spoof their address and bypass throttling.
    TRUST_PROXY_HEADERS: bool = False

    # Logging
    LOG_LEVEL: str = "INFO"

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string."""
        return [
            origin.strip()
            for origin in self.CORS_ORIGINS.split(",")
            if origin.strip()
        ]

    @property
    def is_ai_enabled(self) -> bool:
        """Check if AI features are available."""
        return bool(self.gemini_api_key)

    @property
    def gemini_api_key(self) -> str:
        """The Gemini key as plain text, for use in SDK calls only."""
        return self.GEMINI_API_KEY.get_secret_value()

    @property
    def jwt_secret_key(self) -> str:
        """The JWT signing key as plain text, for use in token calls only.

        In development, an unset key falls back to a randomly generated
        ephemeral value so nothing is hardcoded; production refuses to start
        without a real key.
        """
        value = self.JWT_SECRET_KEY.get_secret_value()
        if value:
            return value
        if not self.is_production:
            global _EPHEMERAL_JWT_SECRET
            if _EPHEMERAL_JWT_SECRET is None:
                _EPHEMERAL_JWT_SECRET = secrets.token_urlsafe(48)
                logger.warning(
                    "JWT_SECRET_KEY is not set. Generated an ephemeral development "
                    "key; all sessions will be invalidated when the process "
                    "restarts. Set JWT_SECRET_KEY before deploying."
                )
            return _EPHEMERAL_JWT_SECRET
        raise InsecureConfigurationError(
            "JWT_SECRET_KEY must be set when ENVIRONMENT=production"
        )

    @property
    def is_production(self) -> bool:
        """True when the app should behave as a production deployment."""
        return self.ENVIRONMENT.strip().lower() in ("production", "prod")

    @property
    def api_docs_enabled(self) -> bool:
        """Whether Swagger/OpenAPI endpoints should be mounted.

        Defaults to off in production and on in development, and can be forced
        either way with ENABLE_API_DOCS.
        """
        if self.ENABLE_API_DOCS is not None:
            return bool(self.ENABLE_API_DOCS)
        return not self.is_production

    @property
    def has_wildcard_cors_origin(self) -> bool:
        """True when CORS_ORIGINS contains a wildcard entry."""
        return any(origin == "*" for origin in self.cors_origins_list)

    @field_validator("ENVIRONMENT")
    @classmethod
    def _normalise_environment(cls, value: str) -> str:
        env = (value or "").strip().lower()
        if env in ("prod", "production"):
            return "production"
        if env in ("dev", "development", "local"):
            return "development"
        if env in ("test", "testing"):
            return "test"
        if env in ("staging", "stage"):
            return "staging"
        return env or "development"

    def validate_runtime_config(self) -> List[str]:
        """Validate configuration for the current environment.

        Returns a list of human-readable problems. An empty list means the
        configuration is acceptable. Production additionally raises
        InsecureConfigurationError so the process refuses to start rather than
        serving with unsafe settings.
        """
        problems: List[str] = []

        if self.DEBUG and self.is_production:
            problems.append(
                "DEBUG must be false when ENVIRONMENT=production; it leaks "
                "tracebacks and internal detail."
            )

        if self.has_wildcard_cors_origin:
            problems.append(
                'CORS_ORIGINS must not contain "*" because credentialed '
                "requests are allowed. List explicit origins instead."
            )
        if not self.cors_origins_list:
            problems.append(
                "CORS_ORIGINS must list at least one explicit origin."
            )

        secret = self.JWT_SECRET_KEY.get_secret_value()
        if not secret:
            problems.append(
                "JWT_SECRET_KEY is not set. Generate one with "
                "`python -c \"import secrets; print(secrets.token_urlsafe(48))\"`."
            )
        elif secret.strip().lower() in INSECURE_JWT_SECRETS:
            problems.append(
                "JWT_SECRET_KEY is still the example placeholder. Set a unique "
                "random value."
            )
        elif len(secret) < MIN_JWT_SECRET_LENGTH:
            problems.append(
                f"JWT_SECRET_KEY must be at least {MIN_JWT_SECRET_LENGTH} characters."
            )

        # An unset (or explicitly empty) key just disables AI, which is
        # supported. Only literal placeholder text is a misconfiguration.
        gemini_key = self.gemini_api_key.strip()
        if gemini_key and gemini_key.lower() in PLACEHOLDER_API_KEYS:
            problems.append(
                "GEMINI_API_KEY is still the example placeholder. Leave it unset "
                "to disable AI features."
            )

        if self.is_production and problems:
            raise InsecureConfigurationError(
                "Refusing to start with an unsafe production configuration:\n- "
                + "\n- ".join(problems)
            )
        return problems

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Process-local fallback JWT key, only ever used outside production.
_EPHEMERAL_JWT_SECRET: Optional[str] = None

# Global settings instance
settings = Settings()
