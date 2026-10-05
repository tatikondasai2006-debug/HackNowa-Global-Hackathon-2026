"""Tests for server-side scan admission control.

  * per-user scan rate limiting (SCAN_RATE_LIMIT_PER_HOUR)
  * global concurrency limiting (MAX_CONCURRENT_SCANS)
  * slot release on completed / failed / cancelled scans
  * slot recovery when a worker dies and leaves a scan stuck in `running`
  * the controls are enforced by the API, not the frontend
"""

from __future__ import annotations

import asyncio
import pathlib
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.exceptions import ScanConcurrencyLimitError, ScanRateLimitError
from app.core.security import get_current_user_id
from app.db.session import Base, get_db
from app.main import app
from app.models.scan import ScanJob, ScanStatus
from app.services import scan_limits


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

@pytest_asyncio.fixture
async def db_session(tmp_path):
    """A real async session against a throwaway SQLite file."""
    db_path = tmp_path / "limits.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path.as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _make_job(session, user_id: int, status: str, **kwargs) -> ScanJob:
    job = ScanJob(
        user_id=user_id,
        target_domain=kwargs.pop("target_domain", "example.com"),
        status=status,
        **kwargs,
    )
    session.add(job)
    await session.commit()
    return job


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recent_scans_are_counted_per_user(db_session, monkeypatch):
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_PER_HOUR", 20)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_WINDOW_SECONDS", 3600)
    now = datetime.now(timezone.utc)

    await _make_job(db_session, 1, ScanStatus.COMPLETED.value, created_at=now)
    await _make_job(db_session, 1, ScanStatus.FAILED.value, created_at=now)
    await _make_job(db_session, 2, ScanStatus.COMPLETED.value, created_at=now)

    assert await scan_limits.count_recent_scans(db_session, 1) == 2
    assert await scan_limits.count_recent_scans(db_session, 2) == 1
    assert await scan_limits.count_recent_scans(db_session, 3) == 0


@pytest.mark.asyncio
async def test_scans_outside_the_window_are_not_counted(db_session, monkeypatch):
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_PER_HOUR", 20)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_WINDOW_SECONDS", 3600)

    old = datetime.now(timezone.utc) - timedelta(hours=2)
    await _make_job(db_session, 1, ScanStatus.COMPLETED.value, created_at=old)
    assert await scan_limits.count_recent_scans(db_session, 1) == 0


@pytest.mark.asyncio
async def test_rate_limit_raises_once_quota_is_used_up(db_session, monkeypatch):
    """The (limit + 1)-th scan in the window must be refused."""
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_PER_HOUR", 3)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_WINDOW_SECONDS", 3600)

    # Two of three used: still allowed, and the usage is reported.
    for _ in range(2):
        await _make_job(db_session, 7, ScanStatus.COMPLETED.value)
    assert await scan_limits.enforce_scan_rate_limit(db_session, 7) == 2

    # The third brings the total to the limit.
    await _make_job(db_session, 7, ScanStatus.COMPLETED.value)

    # The fourth is refused, with a Retry-After matching the window.
    with pytest.raises(ScanRateLimitError) as exc:
        await scan_limits.enforce_scan_rate_limit(db_session, 7)
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "3600"
    assert "3 scans per hour" in exc.value.detail


@pytest.mark.asyncio
async def test_rate_limit_is_per_user(db_session, monkeypatch):
    """One user exhausting the quota must not affect anyone else."""
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_PER_HOUR", 2)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_WINDOW_SECONDS", 3600)

    for _ in range(2):
        await _make_job(db_session, 1, ScanStatus.COMPLETED.value)

    with pytest.raises(ScanRateLimitError):
        await scan_limits.enforce_scan_rate_limit(db_session, 1)

    # A different user is unaffected.
    assert await scan_limits.enforce_scan_rate_limit(db_session, 2) == 0


@pytest.mark.asyncio
async def test_zero_rate_limit_blocks_all_scans(db_session, monkeypatch):
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT_PER_HOUR", 0)
    with pytest.raises(ScanRateLimitError, match="disabled"):
        await scan_limits.enforce_scan_rate_limit(db_session, 1)


# --------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_only_pending_and_running_occupy_a_slot(db_session, monkeypatch):
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)
    now = datetime.now(timezone.utc)

    await _make_job(db_session, 1, ScanStatus.PENDING.value, created_at=now)
    await _make_job(db_session, 1, ScanStatus.RUNNING.value, created_at=now)
    await _make_job(db_session, 1, ScanStatus.COMPLETED.value, created_at=now)
    await _make_job(db_session, 1, ScanStatus.FAILED.value, created_at=now)
    await _make_job(db_session, 1, ScanStatus.CANCELLED.value, created_at=now)

    assert await scan_limits.count_active_scans(db_session) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_status",
    [
        ScanStatus.COMPLETED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    ],
)
async def test_terminal_scans_release_their_slot(
    db_session, monkeypatch, terminal_status
):
    """Every terminal state must free the concurrency slot."""
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 1)
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)

    job = await _make_job(db_session, 1, ScanStatus.RUNNING.value)
    with pytest.raises(ScanConcurrencyLimitError):
        await scan_limits.enforce_scan_concurrency(db_session)

    job.status = terminal_status
    await db_session.commit()

    assert await scan_limits.enforce_scan_concurrency(db_session) == 0


@pytest.mark.asyncio
async def test_concurrency_limit_raises_when_full(db_session, monkeypatch):
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 2)
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)

    await _make_job(db_session, 1, ScanStatus.RUNNING.value)
    await _make_job(db_session, 2, ScanStatus.PENDING.value)

    with pytest.raises(ScanConcurrencyLimitError) as exc:
        await scan_limits.enforce_scan_concurrency(db_session)
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "30"
    assert "maximum of 2 concurrent" in exc.value.detail


@pytest.mark.asyncio
async def test_concurrency_limit_is_global_across_users(db_session, monkeypatch):
    """Different users still share the same global pool."""
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 1)
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)

    await _make_job(db_session, 1, ScanStatus.RUNNING.value)
    with pytest.raises(ScanConcurrencyLimitError):
        await scan_limits.enforce_scan_concurrency(db_session)


@pytest.mark.asyncio
async def test_stuck_running_scan_slot_is_reclaimed(db_session, monkeypatch):
    """A crashed worker must not consume a slot forever."""
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 1)
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)
    monkeypatch.setattr(scan_limits, "ABANDONED_SCAN_GRACE_SECONDS", 60)

    stale = datetime.now(timezone.utc) - timedelta(seconds=300 + 61)
    job = await _make_job(db_session, 1, ScanStatus.RUNNING.value, created_at=stale)

    # A fresh scan is refused only while the stuck one still counts.
    assert await scan_limits.enforce_scan_concurrency(db_session) == 0

    await db_session.refresh(job)
    assert job.status == ScanStatus.FAILED.value
    assert job.error_message == scan_limits.ABANDONED_SCAN_REASON
    assert job.completed_at is not None


@pytest.mark.asyncio
async def test_fresh_running_scan_is_not_reclaimed(db_session, monkeypatch):
    """A legitimately long-running scan must keep its slot."""
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 5)
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)
    monkeypatch.setattr(scan_limits, "ABANDONED_SCAN_GRACE_SECONDS", 60)

    job = await _make_job(db_session, 1, ScanStatus.RUNNING.value)
    await db_session.refresh(job)
    assert job.status == ScanStatus.RUNNING.value
    assert await scan_limits.count_active_scans(db_session) == 1


@pytest.mark.asyncio
async def test_reclaim_swallows_database_errors(db_session, monkeypatch):
    """Housekeeping must not be able to block scan creation.

    If the reclaim query fails the limiter must degrade to a plain count rather
    than turning every scan request into a 500.
    """
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)

    async def boom(*args, **kwargs):
        raise RuntimeError("database exploded")

    monkeypatch.setattr(db_session, "execute", boom)
    # The error is logged and swallowed, not propagated.
    assert await scan_limits.reclaim_abandoned_scans(db_session) == 0

    # Once the database recovers, the limiter works normally again.
    monkeypatch.undo()
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)
    assert await scan_limits.count_active_scans(db_session) == 0


@pytest.mark.asyncio
async def test_zero_concurrency_limit_blocks_all_scans(db_session, monkeypatch):
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 0)
    monkeypatch.setattr(settings, "SCAN_TIMEOUT_SECONDS", 300)
    with pytest.raises(ScanConcurrencyLimitError, match="disabled"):
        await scan_limits.enforce_scan_concurrency(db_session)


# --------------------------------------------------------------------------
# Route level enforcement
# --------------------------------------------------------------------------

def _client_for(tmp_path, monkeypatch, **overrides):
    """Build a TestClient wired to a throwaway database."""
    db_path = tmp_path / "route.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path.as_posix()}")

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_setup())
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _get_db():
        async with maker() as session:
            yield session

    async def _fake_user() -> int:
        return 1

    for key, value in overrides.items():
        monkeypatch.setattr(settings, key, value)

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user_id] = _fake_user
    return TestClient(app)


SCAN_BODY = {
    "target_domain": "example.com",
    "authorization_confirmed": True,
    # Stop the background worker from performing a real network scan.
    "scan_options": {},
}


def test_create_scan_returns_429_when_rate_limited(tmp_path, monkeypatch):
    client = _client_for(
        tmp_path,
        monkeypatch,
        SCAN_RATE_LIMIT_PER_HOUR=1,
        SCAN_RATE_LIMIT_WINDOW_SECONDS=3600,
        MAX_CONCURRENT_SCANS=100,
        SCAN_TIMEOUT_SECONDS=300,
    )
    try:
        with client:
            first = client.post("/api/v1/scans/", json=SCAN_BODY)
            assert first.status_code == 201, first.text

            second = client.post("/api/v1/scans/", json=SCAN_BODY)
            assert second.status_code == 429, second.text
            assert "Retry-After" in second.headers
            assert "per hour" in second.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_create_scan_returns_429_when_concurrency_full(tmp_path, monkeypatch):
    client = _client_for(
        tmp_path,
        monkeypatch,
        SCAN_RATE_LIMIT_PER_HOUR=100,
        SCAN_RATE_LIMIT_WINDOW_SECONDS=3600,
        MAX_CONCURRENT_SCANS=1,
        SCAN_TIMEOUT_SECONDS=300,
    )
    try:
        with client:
            first = client.post("/api/v1/scans/", json=SCAN_BODY)
            assert first.status_code == 201, first.text

            second = client.post("/api/v1/scans/", json=SCAN_BODY)
            assert second.status_code == 429, second.text
            assert "concurrent" in second.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_rate_limit_checked_before_concurrency(tmp_path, monkeypatch):
    """A user over quota should get the rate-limit message, not the busy one."""
    client = _client_for(
        tmp_path,
        monkeypatch,
        SCAN_RATE_LIMIT_PER_HOUR=1,
        SCAN_RATE_LIMIT_WINDOW_SECONDS=3600,
        MAX_CONCURRENT_SCANS=1,
        SCAN_TIMEOUT_SECONDS=300,
    )
    try:
        with client:
            assert client.post("/api/v1/scans/", json=SCAN_BODY).status_code == 201
            body = client.post("/api/v1/scans/", json=SCAN_BODY)
            assert body.status_code == 429
            assert "per hour" in body.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_authorization_is_still_checked_before_limits(tmp_path, monkeypatch):
    """The attestation must not be bypassable by exhausting the quota."""
    client = _client_for(
        tmp_path,
        monkeypatch,
        SCAN_RATE_LIMIT_PER_HOUR=0,
        SCAN_RATE_LIMIT_WINDOW_SECONDS=3600,
        MAX_CONCURRENT_SCANS=0,
        SCAN_TIMEOUT_SECONDS=300,
    )
    try:
        with client:
            response = client.post(
                "/api/v1/scans/",
                json={"target_domain": "example.com", "authorization_confirmed": False},
            )
            assert response.status_code == 403, response.text
    finally:
        app.dependency_overrides.clear()
