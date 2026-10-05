"""Logging hardening: keep configured secrets out of log output.

Any log record that happens to contain a configured secret (an API key, the
JWT signing key, a raw password) is rewritten before a handler emits it. This
is a defence-in-depth measure: code should not log secrets in the first place,
but a stray ``logger.debug("%s", settings.GEMINI_API_KEY)`` or an exception
message containing a token must not end up in a log file or a log aggregator.
Exception tracebacks and stack text are covered too, since those are rendered
after filtering.
"""

from __future__ import annotations

import logging
import re
import traceback
from typing import Any, Iterable, List, Optional

REDACTED = "***REDACTED***"

# Loggers that get the redaction filter attached directly. This is a convenience
# only: the record factory installed by install_secret_redaction() is what
# guarantees coverage of arbitrary logger names such as "app.services.x".
_FILTER_TARGETS = (
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "app",
    "app.core",
)

# Header/query names whose values are always masked.
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "x-api-key",
        "x-auth-token",
        "api-key",
        "api_key",
        "apikey",
        "access_token",
        "access-token",
        "accesstoken",
        "refresh_token",
        "refresh-token",
        "refreshtoken",
        "token",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "jwt",
        "jwt_secret_key",
        "gemini_api_key",
        "cookie",
        "set-cookie",
        "proxy-authorization",
    }
)

# Standalone credential shapes, matched independently of any configuration.
# Case-insensitive sub-patterns use scoped groups: a bare (?i) is only legal at
# the very start of a pattern, not inside an alternation. These matches are
# replaced wholesale, because the match *is* the secret.
CREDENTIAL_PATTERNS = (
    # Google API keys
    r"AIza[0-9A-Za-z_\-]{10,}",
    # JWTs
    r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    # Bearer tokens
    r"(?i:\bbearer)\s+[A-Za-z0-9._\-]{10,}",
)

# ``name=value`` / ``name: value`` assignments for sensitive names. The name is
# preserved so the log stays useful; only the value is dropped.
ASSIGNMENT_PATTERN = (
    r"(?i:\b(?:api[_\-]?key|apikey|secret|password|passwd|token|access[_\-]?token"
    r"|client[_\-]?secret|jwt[_\-]?secret[_\-]?key|gemini[_\-]?api[_\-]?key))"
    r"\s*[=:]\s*[\"']?[^\s\"',;}]{4,}[\"']?"
)


class SecretRedactionFilter(logging.Filter):
    """Mask secrets in log messages and arguments."""

    def __init__(self, extra_values: Optional[Iterable[str]] = None):
        super().__init__(name="secret-redaction")
        self._extra_values: List[str] = [
            v for v in (extra_values or ()) if isinstance(v, str) and len(v) >= 6
        ]

    def set_secret_values(self, values: Iterable[Optional[str]]) -> None:
        """Refresh the list of concrete values to mask (never logged)."""
        self._extra_values = [
            v
            for v in values
            if isinstance(v, str) and len(v) >= 6 and v not in REDACTED
        ]

    def redact_text(self, text: str) -> str:
        for value in self._extra_values:
            if value in text:
                text = text.replace(value, REDACTED)
        # Assignments first, so ``api_key=AIza...`` keeps its name but loses the
        # value, then bare credentials are removed wholesale.
        text = _ASSIGNMENT_RE.sub(_mask_assignment, text)
        return _BARE_CREDENTIAL_RE.sub(lambda _match: REDACTED, text)

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                for key, value in list(record.args.items()):
                    if str(key).lower() in SENSITIVE_KEYS:
                        record.args[key] = REDACTED
                    elif isinstance(value, str):
                        record.args[key] = self.redact_text(value)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self.redact_text(v) if isinstance(v, str) else v
                    for v in record.args
                )

        if record.args:
            # A credential can exist only in the *assembled* message: the
            # format string "api_key=%s" plus a bare secret argument forms a
            # pattern that neither part contains on its own. Redact the
            # composed text and collapse the arguments so the value cannot be
            # re-formatted by a downstream handler.
            try:
                composed = self.redact_text(record.getMessage())
            except Exception:  # pragma: no cover - malformed format string
                composed = None
            if isinstance(composed, str):
                record.msg = composed
                record.args = ()

        # The traceback and the stack text are rendered by the *formatter*,
        # after every filter has run, so redacting only msg/args left them
        # untouched. Any secret carried in an exception message therefore
        # reached the log verbatim. The Gemini SDK is configured with the API
        # key, so its exceptions are the realistic source.
        #
        # Rendering the traceback here and parking it in ``exc_text`` lets the
        # normal formatter emit it unchanged, so the diagnostics survive while
        # the secret does not.
        if record.exc_info:
            try:
                rendered = "".join(traceback.format_exception(*record.exc_info))
            except Exception:  # pragma: no cover - never break logging
                rendered = None
            if rendered is not None:
                record.exc_text = self.redact_text(rendered)
                record.exc_info = None
        if record.stack_info:
            record.stack_info = self.redact_text(record.stack_info)

        return True


def _mask_assignment(match: "re.Match[str]") -> str:
    """Keep the ``name=`` part of an assignment match, drop the value."""
    matched = match.group(0)
    separator = "=" if "=" in matched else ":"
    name = matched.split(separator)[0]
    return f"{name}{separator}{REDACTED}"


import re  # noqa: E402  (placed after the filter to keep the module readable)

_ASSIGNMENT_RE = re.compile(ASSIGNMENT_PATTERN)

_BARE_CREDENTIAL_RE = re.compile("|".join(CREDENTIAL_PATTERNS))

_REDACTION_FILTER: Optional[SecretRedactionFilter] = None


def get_redaction_filter() -> SecretRedactionFilter:
    """Return the process-wide redaction filter, creating it if needed."""
    global _REDACTION_FILTER
    if _REDACTION_FILTER is None:
        from app.core.config import settings

        _REDACTION_FILTER = SecretRedactionFilter()
        try:
            _REDACTION_FILTER.set_secret_values(
                [settings.gemini_api_key, settings.JWT_SECRET_KEY.get_secret_value()]
            )
        except Exception:
            # Never let redaction setup break startup.
            pass
    return _REDACTION_FILTER


def redact(value: Any) -> Any:
    """Redact a string (or structure containing strings) for logging."""
    filt = get_redaction_filter()
    if isinstance(value, str):
        return filt.redact_text(value)
    if isinstance(value, dict):
        return {
            k: (REDACTED if str(k).lower() in SENSITIVE_KEYS else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(redact(v) for v in value)
    return value


def install_secret_redaction() -> SecretRedactionFilter:
    """Install secret redaction process-wide.

    Two layers are used, because neither alone is sufficient:

    1. A :mod:`logging` record factory. Every ``LogRecord`` in the process is
       created through it, so the message and arguments are scrubbed no matter
       which logger emitted them. This is what actually protects application
       loggers such as ``app.services.gemini_service``.
    2. A filter attached to every handler that already exists, plus the root and
       uvicorn loggers, as defence in depth.

    Layer 2 alone is not enough: Python applies a logger's own filters only to
    records logged through that exact logger, so a filter on the root or ``app``
    logger does not touch records emitted by ``app.services.*``, and those are
    then propagated to the root *handlers* with no filtering at all.
    """
    filt = get_redaction_filter()
    _install_record_factory(filt)

    for logger in (logging.getLogger(), *(logging.getLogger(n) for n in _FILTER_TARGETS)):
        if filt not in logger.filters:
            logger.addFilter(filt)

    # Handlers created by uvicorn/logging.basicConfig after this call are still
    # covered by the record factory, so existing ones are enough here.
    for handler in _all_handlers():
        if filt not in handler.filters:
            handler.addFilter(filt)
    return filt


def _all_handlers() -> List[logging.Handler]:
    """Every handler currently attached anywhere in the logger hierarchy."""
    seen: List[logging.Handler] = []
    visited = set()
    logger = logging.getLogger()
    while logger is not None:
        if id(logger) in visited:
            break
        visited.add(id(logger))
        for handler in logger.handlers:
            if handler not in seen:
                seen.append(handler)
        logger = logger.parent
    return seen


def _install_record_factory(filt: SecretRedactionFilter) -> None:
    """Wrap the active record factory so every record is redacted once."""
    current = logging.getLogRecordFactory()
    if getattr(current, "_secret_redaction_installed", False):
        return

    def factory(*args, **kwargs):
        record = current(*args, **kwargs)
        try:
            filt.filter(record)
        except Exception:  # pragma: no cover - never break logging
            pass
        return record

    factory._secret_redaction_installed = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)
