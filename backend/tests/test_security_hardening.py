"""Security hardening: secret leakage, identifier oracles, and response headers.

Each test here pins a defect found by STEP 13 security testing. They are written
to fail against the code as it stood before the corresponding fix.
"""

from __future__ import annotations

import asyncio
import io
import logging
import pathlib
import tempfile

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.logging_config import get_redaction_filter
from app.core.security import create_access_token
from app.db.session import Base, get_db
from app.main import app
from app.models.scan import Finding, ScanJob
from app.services.user_service import UserService

DB_FILE = pathlib.Path(tempfile.mkdtemp()) / "security_hardening.db"
engine = create_async_engine(f"sqlite+aiosqlite:///{DB_FILE.as_posix()}")
maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def _create_schema():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


asyncio.run(_create_schema())


async def _override_db():
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@pytest.fixture(autouse=True)
def _app_dependencies():
    app.dependency_overrides[get_db] = _override_db
    yield
    app.dependency_overrides.clear()


def _client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


async def _make_user(email: str):
    from app.schemas.user import UserRegister

    async with maker() as db:
        user = await UserService(db).register(
            UserRegister(
                email=email, username=email.split("@")[0], password="Str0ng!Passw0rd"
            )
        )
        await db.commit()
        return user.id, create_access_token({"sub": str(user.id), "email": email})


async def _make_completed_scan(user_id: int) -> tuple[int, int]:
    """Create a completed scan with one finding; return (scan_id, finding_id)."""
    async with maker() as db:
        scan = ScanJob(
            user_id=user_id,
            target_domain="example.com",
            target_url="https://example.com",
            status="completed",
            total_checks=1,
            completed_checks=1,
            overall_score=80.0,
            risk_level="low",
        )
        db.add(scan)
        await db.flush()
        finding = Finding(
            scan_job_id=scan.id,
            title="Missing HSTS header",
            description="Strict-Transport-Security is not set.",
            severity="medium",
            category="Headers",
        )
        db.add(finding)
        await db.commit()
        return scan.id, finding.id


# --------------------------------------------------------------------------
# 1. Validation errors must not echo submitted secrets
# --------------------------------------------------------------------------

def test_registration_validation_error_does_not_echo_password():
    """A 422 from the password policy used to carry the plaintext password.

    FastAPI's default handler serialises ``exc.errors()``, and Pydantic v2
    includes the offending ``input``. The response body therefore reflected the
    user's password back to them, and into any proxy or client log that records
    response bodies.
    """
    secret = "secret123"  # valid length, but no uppercase -> policy rejects it
    response = _client().post(
        "/api/v1/auth/register",
        json={
            "email": "leaky@example.com",
            "username": "leakyuser",
            "password": secret,
        },
    )
    assert response.status_code == 422
    assert secret not in response.text, "password echoed in a validation error"
    assert "input" not in response.text, "raw rejected input echoed in a validation error"


def test_change_password_validation_error_does_not_echo_new_password():
    """The same leak existed on the authenticated change-password route."""
    import anyio

    async def _run():
        _user_id, token = await _make_user("changepw@example.com")
        secret = "weaknewpass"  # no uppercase and no digit -> policy rejects it
        response = _client().post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "Str0ng!Passw0rd", "new_password": secret},
        )
        assert response.status_code == 422
        assert secret not in response.text, "new password echoed in a validation error"
        assert "input" not in response.text

    anyio.run(_run)


# --------------------------------------------------------------------------
# 2. Exception tracebacks must be redacted, not just the log message
# --------------------------------------------------------------------------

def test_exception_traceback_is_redacted():
    """Redaction ran before the formatter appended the traceback.

    ``logging.Filter`` only sees ``record.msg``/``record.args``; the traceback is
    appended later by ``Formatter.format()``. A secret embedded in an exception
    message -- the Gemini SDK is configured with the API key, so its exceptions
    are the realistic source -- was therefore written to the log verbatim.
    """
    secret = "AIzaSyTESTONLYSECRETVALUE0123456789"
    handler = logging.StreamHandler(io.StringIO())
    handler.setFormatter(logging.Formatter("%(message)s"))
    filt = get_redaction_filter()
    if filt not in handler.filters:
        handler.addFilter(filt)

    record = logging.LogRecord(
        name="test.exc",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="provider call failed",
        args=(),
        exc_info=(RuntimeError, RuntimeError(f"403 for key {secret}"), None),
    )
    filt.filter(record)
    handler.handle(record)

    output = handler.stream.getvalue()
    assert secret not in output, "secret survived inside an exception traceback"
    assert "provider call failed" in output, "the message itself was lost"


# --------------------------------------------------------------------------
# 3. Foreign finding IDs must be indistinguishable from missing ones
# --------------------------------------------------------------------------

def test_foreign_finding_is_indistinguishable_from_missing():
    """The route returned 404 for "no such finding" and 403 for "not yours".

    That difference is a cross-tenant oracle: any authenticated user could
    enumerate which finding IDs exist in other people's scans. Every other
    resource in the API answers a uniform 404.
    """
    import anyio

    async def _run():
        owner_id, _owner_token = await _make_user("oracle_owner@example.com")
        _other_id, other_token = await _make_user("oracle_other@example.com")
        _scan_id, finding_id = await _make_completed_scan(owner_id)

        client = _client()
        headers = {"Authorization": f"Bearer {other_token}"}

        foreign = client.post(f"/api/v1/ai/explain-finding/{finding_id}", headers=headers)
        missing = client.post("/api/v1/ai/explain-finding/999999", headers=headers)

        assert foreign.status_code == missing.status_code, (
            "foreign and missing findings are distinguishable: "
            f"{foreign.status_code} vs {missing.status_code}"
        )
        assert foreign.status_code == 404
        assert foreign.json() == missing.json(), (
            "response bodies differ and reveal whether the finding exists"
        )

    anyio.run(_run)


# --------------------------------------------------------------------------
# 4. Oversized identifiers on the AI routes must not reach the database layer
# --------------------------------------------------------------------------

def test_oversized_ids_on_ai_routes_do_not_return_500():
    """The AI routes still used a bare ``int`` for their path parameters.

    The scan and report routes were bounded to 2**63-1 after oversized IDs were
    found to overflow SQLite; the AI routes were missed.
    """
    import anyio

    huge = "9" * 400

    async def _run():
        _user_id, token = await _make_user("aibig@example.com")
        client = _client()
        headers = {"Authorization": f"Bearer {token}"}

        for path in (
            f"/api/v1/ai/explain-scan/{huge}",
            f"/api/v1/ai/explain-finding/{huge}",
        ):
            response = client.post(path, headers=headers)
            assert response.status_code < 500, (
                f"{path} returned {response.status_code}"
            )
            assert response.status_code == 422, (
                f"{path} returned {response.status_code}, expected 422"
            )

    anyio.run(_run)


# --------------------------------------------------------------------------
# 5. Report responses must not be MIME-sniffed
# --------------------------------------------------------------------------

def test_report_html_sets_nosniff():
    """HTML reports were served as text/html with no nosniff and no framing
    protection, so a browser could be induced to re-interpret the response."""
    import anyio

    async def _run():
        user_id, token = await _make_user("report_hdr@example.com")
        scan_id, _finding_id = await _make_completed_scan(user_id)

        response = _client().get(
            f"/api/v1/reports/scan/{scan_id}/view",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert "x-frame-options" in {k.lower() for k in response.headers}

    anyio.run(_run)
