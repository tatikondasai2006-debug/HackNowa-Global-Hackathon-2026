"""Login throttling for brute-force and credential-stuffing resistance.

Design notes
------------
* **Progressive backoff, never a hard lockout.** After
  ``LOGIN_MAX_FAILED_ATTEMPTS`` failures the delay doubles per extra failure up
  to ``LOGIN_MAX_DELAY_SECONDS``. A single mistyped password costs one free
  attempt, so a legitimate user is never locked out by a typo, but an attacker
  gets down to a handful of attempts per hour.
* **Failures expire.** Counters older than ``LOGIN_FAILURE_WINDOW_SECONDS`` are
  discarded, so a burst cannot produce a permanent lockout. A successful login
  clears the counter immediately.
* **No account enumeration.** Throttle state is keyed on the client IP *and* the
  submitted email, and a failure is recorded identically whether or not the
  account exists. The rejection message is the same in every case.
* **Bounded memory.** Stale entries are pruned on write, so the store cannot
  grow without limit from an attacker spraying many distinct addresses.

Limitation: the store is per-process. Running multiple uvicorn workers means
each worker keeps its own counters, so the effective limit is multiplied by the
worker count. Move the counters to Redis (or the database) before scaling out.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)

Key = Tuple[str, str]


@dataclass
class _Entry:
    """Failure history for one (client, email) pair."""

    failures: int = 0
    first_failure_at: float = field(default_factory=time.monotonic)
    last_failure_at: float = field(default_factory=time.monotonic)
    locked_until: float = 0.0


class LoginThrottle:
    """In-memory progressive-backoff throttle for failed logins."""

    def __init__(
        self,
        max_failures: Optional[int] = None,
        base_delay: Optional[int] = None,
        max_delay: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ):
        # Resolved lazily so tests and config reloads can change settings.
        self._max_failures = max_failures
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._window = window_seconds
        self._entries: Dict[Key, _Entry] = {}
        self._lock = threading.Lock()

    # -- configuration ----------------------------------------------------
    @property
    def max_failures(self) -> int:
        return (
            self._max_failures
            if self._max_failures is not None
            else settings.LOGIN_MAX_FAILED_ATTEMPTS
        )

    @property
    def base_delay(self) -> int:
        return (
            self._base_delay
            if self._base_delay is not None
            else settings.LOGIN_BASE_DELAY_SECONDS
        )

    @property
    def max_delay(self) -> int:
        return (
            self._max_delay
            if self._max_delay is not None
            else settings.LOGIN_MAX_DELAY_SECONDS
        )

    @property
    def window_seconds(self) -> int:
        return (
            self._window
            if self._window is not None
            else settings.LOGIN_FAILURE_WINDOW_SECONDS
        )

    # -- internals --------------------------------------------------------
    @staticmethod
    def make_key(client_ip: str, email: str) -> Key:
        """Normalise the throttle key.

        The email is lowercased so casing differences do not hand an attacker a
        fresh budget, and the IP is lowercased/stripped for IPv6 consistency.
        """
        return ((client_ip or "unknown").strip().lower(), (email or "").strip().lower())

    def _prune(self, now: float) -> None:
        """Drop entries whose whole window has elapsed. Caller holds the lock."""
        cutoff = now - self.window_seconds
        stale = [k for k, e in self._entries.items() if e.last_failure_at < cutoff]
        for k in stale:
            del self._entries[k]

    def delay_for(self, key: Key) -> int:
        """Seconds the caller must wait before another attempt is allowed."""
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return 0
            # Expiry is checked first, and takes precedence over any active
            # lockout. Otherwise a long backoff would outlive the failure
            # window and become exactly the permanent lockout this control is
            # meant to avoid.
            if entry.last_failure_at < now - self.window_seconds:
                del self._entries[key]
                return 0
            if entry.locked_until > now:
                return max(1, int(entry.locked_until - now))
            return 0

    def record_failure(self, key: Key) -> int:
        """Record a failed attempt and return the resulting backoff in seconds."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            entry = self._entries.get(key)
            if entry is None or entry.last_failure_at < now - self.window_seconds:
                entry = _Entry(failures=0, first_failure_at=now, last_failure_at=now)
                self._entries[key] = entry
            entry.failures += 1
            entry.last_failure_at = now
            if entry.failures <= self.max_failures:
                return 0
            # The (max_failures + 1)-th failure waits one base delay, and each
            # further failure doubles it.
            exponent = entry.failures - self.max_failures - 1
            delay = min(self.base_delay * (2**exponent), self.max_delay)
            entry.locked_until = now + delay
            logger.warning(
                "Login throttled for client=%s after %s failures; retry in %ss",
                key[0],
                entry.failures,
                delay,
            )
            return delay

    def record_success(self, key: Key) -> None:
        """Clear the failure history after a successful authentication."""
        with self._lock:
            if self._entries.pop(key, None) is not None:
                logger.info("Login throttle cleared for client=%s", key[0])

    def failure_count(self, key: Key) -> int:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return 0
            if entry.last_failure_at < time.monotonic() - self.window_seconds:
                del self._entries[key]
                return 0
            return entry.failures

    def reset(self) -> None:
        """Clear all state. Used by tests and administrative resets."""
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


login_throttle = LoginThrottle()
