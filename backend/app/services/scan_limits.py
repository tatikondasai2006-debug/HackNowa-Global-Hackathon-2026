"""Server-side admission control for scan creation.

Two independent controls, both derived from the database so they survive process
restarts:

* Rate limit  - ``SCAN_RATE_LIMIT_PER_HOUR`` scans per user per rolling window.
* Concurrency - ``MAX_CONCURRENT_SCANS`` scans in a non-terminal state.

The concurrency count is derived from scan rows rather than an in-process
counter, so a slot is released by the scan reaching a terminal state. A scan
that is still marked ``running`` after the scan timeout has elapsed can only be
a leftover from a crashed worker, so it is reclaimed as ``failed`` before
counting; that stops exceptions from permanently consuming a slot.

Counting rows and then inserting the new one is a check-then-act sequence, and
two coroutines that both observe "4 active, limit 5" would both proceed. That
was reproducible: eight concurrent requests admitted six scans when a single
slot was free. ``scan_admission_guard()`` serialises the check together with the
insert, so the pair is atomic within a process.

Scope, stated plainly: the guard is per event loop in a single process, which
matches the documented deployment (``uvicorn app.main:app`` with one worker).
Running several worker processes would give each one its own guard, so the
overshoot would be bounded by the worker count rather than eliminated. The
database count still applies, so the limit remains a real bound on total
concurrency. Closing that last gap needs a database-level serialisation
primitive, such as a conditional insert or a lock row, and is not implemented.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Dict, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ScanConcurrencyLimitError, ScanRateLimitError
from app.models.scan import ScanJob, ScanStatus

logger = logging.getLogger(__name__)

# Locks are held per running event loop rather than in one module-level object:
# an asyncio.Lock binds to the loop that first awaits it, and the test suite
# (and any in-process reloader) creates more than one loop.
_ADMISSION_LOCKS: Dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}


def _admission_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _ADMISSION_LOCKS.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _ADMISSION_LOCKS[loop] = lock
    return lock


@contextlib.asynccontextmanager
async def scan_admission_guard() -> AsyncIterator[None]:
    """Hold the admission lock across the check *and* the row insert.

    Callers must keep the slot-consuming insert inside this block; releasing the
    lock before the insert reopens the check-then-act window.
    """
    async with _admission_lock():
        yield


ACTIVE_STATUSES = (ScanStatus.PENDING.value, ScanStatus.RUNNING.value)
TERMINAL_STATUSES = (
    ScanStatus.COMPLETED.value,
    ScanStatus.FAILED.value,
    ScanStatus.CANCELLED.value,
)

# Extra slack on top of SCAN_TIMEOUT_SECONDS before a still-"running" row is
# assumed to be abandoned by a crashed worker.
ABANDONED_SCAN_GRACE_SECONDS = 60

ABANDONED_SCAN_REASON = (
    "The scan did not report a final result and was marked failed by the server."
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def reclaim_abandoned_scans(db: AsyncSession) -> int:
    """Mark scans abandoned by a crashed worker as FAILED.

    Returns the number of rows reclaimed. Never raises: reclaiming is
    best-effort housekeeping and must not block the caller.
    """
    cutoff = _utcnow() - timedelta(
        seconds=settings.SCAN_TIMEOUT_SECONDS + ABANDONED_SCAN_GRACE_SECONDS
    )
    try:
        result = await db.execute(
            select(ScanJob).where(
                ScanJob.status.in_(ACTIVE_STATUSES),
                ScanJob.created_at < cutoff,
            )
        )
        stale = result.scalars().all()
        if not stale:
            return 0
        for job in stale:
            logger.warning(
                "Reclaiming abandoned scan job id=%s status=%s (older than %ss)",
                job.id,
                job.status,
                settings.SCAN_TIMEOUT_SECONDS + ABANDONED_SCAN_GRACE_SECONDS,
            )
            job.status = ScanStatus.FAILED.value
            job.error_message = ABANDONED_SCAN_REASON
            job.current_module = None
            job.completed_at = _utcnow()
        await db.commit()
        return len(stale)
    except Exception:
        await db.rollback()
        logger.exception("Failed to reclaim abandoned scan jobs")
        return 0


async def count_active_scans(db: AsyncSession) -> int:
    """Number of scans currently occupying a concurrency slot."""
    await reclaim_abandoned_scans(db)
    result = await db.execute(
        select(func.count())
        .select_from(ScanJob)
        .where(ScanJob.status.in_(ACTIVE_STATUSES))
    )
    return int(result.scalar_one())


async def enforce_scan_concurrency(db: AsyncSession) -> int:
    """Raise ScanConcurrencyLimitError when no concurrency slot is free.

    Returns the number of active scans when a slot is available.
    """
    limit = settings.MAX_CONCURRENT_SCANS
    if limit <= 0:
        # 0 or negative means "no concurrent scans allowed".
        active = await count_active_scans(db)
        raise ScanConcurrencyLimitError(
            f"Concurrent scans are currently disabled. {active} scan(s) are "
            "still in progress.",
            retry_after=15,
            limit=limit,
        )

    active = await count_active_scans(db)
    if active >= limit:
        logger.warning(
            "Concurrency limit reached: %s active, limit %s", active, limit
        )
        raise ScanConcurrencyLimitError(
            f"The server is already running the maximum of {limit} concurrent "
            "scans. Please wait for a running scan to finish and try again.",
            retry_after=30,
            limit=limit,
        )
    return active


async def count_recent_scans(db: AsyncSession, user_id: int) -> int:
    """Number of scans this user started inside the current rate-limit window."""
    window = max(1, settings.SCAN_RATE_LIMIT_WINDOW_SECONDS)
    cutoff = _utcnow() - timedelta(seconds=window)
    result = await db.execute(
        select(func.count())
        .select_from(ScanJob)
        .where(ScanJob.user_id == user_id, ScanJob.created_at >= cutoff)
    )
    return int(result.scalar_one())


async def enforce_scan_rate_limit(db: AsyncSession, user_id: int) -> int:
    """Raise ScanRateLimitError when the user has exceeded their quota.

    Returns the number of scans used in the current window when allowed.
    """
    limit = settings.SCAN_RATE_LIMIT_PER_HOUR
    if limit <= 0:
        # 0 or negative means "no scans allowed".
        raise ScanRateLimitError(
            "Scan requests are currently disabled by the server operator.",
            retry_after=300,
            limit=limit,
            window_seconds=max(1, settings.SCAN_RATE_LIMIT_WINDOW_SECONDS),
        )

    used = await count_recent_scans(db, user_id)
    if used >= limit:
        window = max(1, settings.SCAN_RATE_LIMIT_WINDOW_SECONDS)
        logger.warning(
            "Scan rate limit hit for user_id=%s: %s used, limit %s", user_id, used, limit
        )
        raise ScanRateLimitError(
            f"You have reached the limit of {limit} scans per hour. "
            "Please try again later.",
            retry_after=window,
            limit=limit,
            window_seconds=window,
        )
    return used


async def enforce_scan_admission(db: AsyncSession, user_id: int) -> None:
    """Run every admission control for a new scan.

    Rate limiting is checked before concurrency so a user who is over quota
    gets the more actionable message.
    """
    await enforce_scan_rate_limit(db, user_id)
    await enforce_scan_concurrency(db)
