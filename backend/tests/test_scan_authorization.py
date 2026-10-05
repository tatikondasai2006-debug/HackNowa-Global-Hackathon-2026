"""Tests for server-side scan authorization attestation and failure handling.

These cover the controls that must not depend on the frontend:
  * POST /scans/ refuses a request without an authorization attestation (403)
  * the attestation and the refusal are recorded in the audit trail
  * a scan that blows up or times out is marked FAILED, never left pending
"""

from __future__ import annotations

import asyncio
import pathlib
import tempfile

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.security import get_current_user_id
from app.db.session import Base, get_db
from app.main import app
from app.models.scan import AuditLog, ScanJob, ScanStatus
from app.schemas.scan import ScanRequest
from app.services.scan_service import ScanService, public_scan_error


# --------------------------------------------------------------------------
# Schema: attestation must be explicit
# --------------------------------------------------------------------------

def test_authorization_confirmed_defaults_to_false():
    """Clients that omit the attestation must be rejected, not assumed."""
    req = ScanRequest(target_domain="example.com")
    assert req.authorization_confirmed is False


def test_authorization_confirmed_can_be_set():
    req = ScanRequest(target_domain="example.com", authorization_confirmed=True)
    assert req.authorization_confirmed is True


# --------------------------------------------------------------------------
# Route: enforcement happens server-side
# --------------------------------------------------------------------------

def test_create_scan_rejects_missing_authorization(tmp_path):
    """A scan request without attestation is refused with 403, before any work."""
    db_path = tmp_path / "authz.db"
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

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user_id] = _fake_user
    try:
        with TestClient(app) as client:
            r = client.post(
                "/api/v1/scans/",
                json={"target_domain": "example.com"},
            )
            assert r.status_code == 403, r.text
            detail = r.json()["detail"].lower()
            assert "permission" in detail and "own this target" in detail

            # Explicitly false is still refused.
            r2 = client.post(
                "/api/v1/scans/",
                json={"target_domain": "example.com", "authorization_confirmed": False},
            )
            assert r2.status_code == 403
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user_id, None)

    async def _check_no_scan():
        async with maker() as session:
            rows = (await session.execute(select(ScanJob))).scalars().all()
            return len(rows)

    assert asyncio.run(_check_no_scan()) == 0
    asyncio.run(engine.dispose())


# --------------------------------------------------------------------------
# Audit trail
# --------------------------------------------------------------------------

@pytest_asyncio.fixture
async def db_engine(tmp_path):
    db_path = tmp_path / "audit.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path.as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session(db_engine):
    maker = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    return maker, db_engine


@pytest.mark.asyncio
async def test_create_scan_records_authorization_attestation(session):
    maker, _engine = session
    async with maker() as db:
        svc = ScanService(db)
        job = await svc.create_scan(
            user_id=1,
            target_domain="example.com",
            authorization_confirmed=True,
        )
        await db.commit()

        rows = (
            await db.execute(select(AuditLog).where(AuditLog.resource_id == job.id))
        ).scalars().all()
        actions = {r.action for r in rows}
        assert "scan.created" in actions
        assert "scan.authorization_attested" in actions

        created = next(r for r in rows if r.action == "scan.created")
        assert created.details["authorization_confirmed"] is True
        assert "authorization_attested_at" in created.details

        attested = next(r for r in rows if r.action == "scan.authorization_attested")
        assert "permission" in attested.details["statement"].lower()
        assert job.status == ScanStatus.PENDING.value


@pytest.mark.asyncio
async def test_create_scan_without_attestation_records_false(session):
    maker, _engine = session
    async with maker() as db:
        svc = ScanService(db)
        job = await svc.create_scan(user_id=1, target_domain="example.com")
        await db.commit()

        rows = (
            await db.execute(select(AuditLog).where(AuditLog.resource_id == job.id))
        ).scalars().all()
        assert {r.action for r in rows} == {"scan.created"}
        created = next(r for r in rows if r.action == "scan.created")
        assert created.details["authorization_confirmed"] is False


# --------------------------------------------------------------------------
# Failure handling / error sanitisation
# --------------------------------------------------------------------------

def test_public_scan_error_hides_internal_detail():
    """Internal exception text must never reach the persisted/returned reason."""
    exc = RuntimeError(
        "sqlite3.OperationalError: no such table: scan_jobs at /srv/app/db/session.py"
    )
    msg = public_scan_error(exc)
    assert "sqlite3" not in msg
    assert "/srv/app" not in msg
    assert "internal error" in msg.lower()


def test_public_scan_error_keeps_domain_validation_detail():
    """User-correctable domain problems should stay specific and actionable."""
    from app.core.exceptions import DomainValidationError

    exc = DomainValidationError("Scanning private/internal domains is not permitted")
    assert public_scan_error(exc) == "Scanning private/internal domains is not permitted"


@pytest.mark.asyncio
async def test_mark_scan_failed_transitions_pending_job(session, monkeypatch):
    """The worker's failure path must move pending/running jobs to FAILED."""
    import app.api.scans as scans_api

    maker, _engine = session
    async with maker() as db:
        svc = ScanService(db)
        job = await svc.create_scan(user_id=1, target_domain="example.com")
        await db.commit()
        scan_id = job.id

        monkeypatch.setattr(scans_api, "async_session_factory", maker)
        await scans_api._mark_scan_failed(scan_id, "The scan exceeded the maximum duration.")

        db.expire_all()
        refreshed = (
            await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        ).scalar_one()
        assert refreshed.status == ScanStatus.FAILED.value
        assert "maximum duration" in refreshed.error_message
        assert refreshed.completed_at is not None


@pytest.mark.asyncio
async def test_mark_scan_failed_does_not_overwrite_completed(session, monkeypatch):
    import app.api.scans as scans_api

    maker, _engine = session
    async with maker() as db:
        svc = ScanService(db)
        job = await svc.create_scan(user_id=1, target_domain="example.com")
        job.status = ScanStatus.COMPLETED.value
        await db.commit()
        scan_id = job.id

        monkeypatch.setattr(scans_api, "async_session_factory", maker)
        await scans_api._mark_scan_failed(scan_id, "should not be applied")

        db.expire_all()
        refreshed = (
            await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        ).scalar_one()
        assert refreshed.status == ScanStatus.COMPLETED.value
        assert refreshed.error_message is None


def test_scan_timeout_setting_is_configurable():
    from app.core.config import Settings

    s = Settings(SCAN_TIMEOUT_SECONDS=42)
    assert s.SCAN_TIMEOUT_SECONDS == 42
    # Default must be generous enough for a real multi-module scan.
    assert Settings().SCAN_TIMEOUT_SECONDS >= 120
