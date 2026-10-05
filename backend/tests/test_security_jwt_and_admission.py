"""JWT claim handling, admission-control races, and hostile input handling.

The defects pinned here were found by STEP 13 security testing.
"""

from __future__ import annotations

import asyncio
import pathlib
import tempfile

import anyio
import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.security import create_access_token
from app.db.session import Base, get_db
from app.main import app
from app.models.scan import ScanJob
from app.services.user_service import UserService

DB_FILE = pathlib.Path(tempfile.mkdtemp()) / "security_jwt.db"
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


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# JWT handling
# --------------------------------------------------------------------------
#
# Every test below points at a *real* active account. That is what makes them
# meaningful: a rejection has to come from the token being bad, not from the
# account lookup, so a 401 cannot be produced for the wrong reason. A positive
# control asserts the same account and endpoint return 200 for a good token.


def test_positive_control_valid_token_is_accepted():
    """Baseline: the real token for a real user works."""
    async def _run():
        user_id, token = await _make_user("control@example.com")
        response = _client().get("/api/v1/auth/me", headers=_bearer(token))
        return user_id, response.status_code

    _, code = anyio.run(_run)
    assert code == 200, code


def test_alg_none_token_is_rejected():
    """A token with ``alg: none`` and an empty signature must never be honoured.

    Built by hand: python-jose refuses to *sign* with "none", and forging one by
    hand is the only way to test the verifier.
    """
    import base64
    import json

    def _b64(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = _b64({"alg": "none", "typ": "JWT"})

    async def _run():
        user_id, _token = await _make_user("algnone@example.com")
        payload = _b64({"sub": str(user_id), "exp": 9999999999})
        token = f"{header}.{payload}."
        response = _client().get("/api/v1/auth/me", headers=_bearer(token))
        return user_id, response.status_code

    user_id, code = anyio.run(_run)
    assert code in (401, 403), f"alg=none token accepted for user {user_id} ({code})"


def test_token_signed_with_a_different_secret_is_rejected():
    async def _run():
        user_id, _token = await _make_user("wrongkey@example.com")
        forged = jose_jwt.encode(
            {"sub": str(user_id), "exp": 9999999999},
            key="a-completely-different-signing-key-value",
            algorithm="HS256",
        )
        response = _client().get("/api/v1/auth/me", headers=_bearer(forged))
        return user_id, response.status_code

    user_id, code = anyio.run(_run)
    assert code in (401, 403), f"forged token accepted for user {user_id} ({code})"


def test_tampered_payload_is_rejected():
    async def _run():
        user_id, token = await _make_user("tampered@example.com")
        head, payload, sig = token.split(".")
        tampered = f"{head}.{payload[:-2]}XY.{sig}"
        response = _client().get("/api/v1/auth/me", headers=_bearer(tampered))
        return user_id, response.status_code

    user_id, code = anyio.run(_run)
    assert code in (401, 403), f"tampered token accepted for user {user_id} ({code})"


def test_expired_token_is_rejected():
    from datetime import timedelta

    async def _run():
        _user_id, token = await _make_user("expired@example.com")
        expired = create_access_token(
            {"sub": _user_id}, expires_delta=timedelta(seconds=-60)
        )
        response = _client().get("/api/v1/auth/me", headers=_bearer(expired))
        return response.status_code

    assert anyio.run(_run) == 401


def test_token_without_expiry_is_rejected():
    """A correctly signed token with no ``exp`` was accepted forever.

    python-jose validates ``exp`` only when the claim is present, so a token
    minted without one decoded cleanly and never expired.
    """
    async def _run():
        user_id, _token = await _make_user("noexp@example.com")
        no_exp = jose_jwt.encode(
            {"sub": str(user_id), "email": "noexp@example.com"},
            key=settings.jwt_secret_key,
            algorithm=settings.JWT_ALGORITHM,
        )
        response = _client().get("/api/v1/auth/me", headers=_bearer(no_exp))
        return user_id, response.status_code

    user_id, code = anyio.run(_run)
    assert code in (401, 403), f"non-expiring token accepted for user {user_id} ({code})"


def test_non_numeric_subject_is_rejected_instead_of_crashing():
    """``int(sub)`` ran unguarded, so a non-numeric subject became a 500.

    The claim is trusted input: it arrives from inside the token, and the
    conversion has to fail closed rather than raise an unhandled ValueError.
    """
    async def _run():
        user_id, _token = await _make_user("badsub@example.com")
        bad_sub = jose_jwt.encode(
            {"sub": "not-a-number", "exp": 9999999999},
            key=settings.jwt_secret_key,
            algorithm=settings.JWT_ALGORITHM,
        )
        response = _client().get("/api/v1/auth/me", headers=_bearer(bad_sub))
        return user_id, response.status_code

    user_id, code = anyio.run(_run)
    assert code == 401, f"malformed sub for user {user_id} produced {code}, expected 401"


def test_zero_and_negative_subjects_are_rejected():
    async def _run():
        _user_id, _token = await _make_user("zerosub@example.com")
        codes = []
        for subject in ("0", "-1", "1.5", "", " "):
            token = jose_jwt.encode(
                {"sub": subject, "exp": 9999999999},
                key=settings.jwt_secret_key,
                algorithm=settings.JWT_ALGORITHM,
            )
            codes.append(_client().get("/api/v1/auth/me", headers=_bearer(token)).status_code)
        return codes

    codes = anyio.run(_run)
    assert all(c == 401 for c in codes), f"bad subjects accepted: {codes}"


# --------------------------------------------------------------------------
# Hostile / malformed input
# --------------------------------------------------------------------------

def test_hostile_inputs_are_rejected_without_500():
    """Long, null-bearing, non-string and wrong-type inputs must be refused."""
    import anyio

    async def _run():
        _user_id, token = await _make_user("hostile@example.com")
        client = _client()
        headers = _bearer(token)

        bodies = [
            {"target_domain": "a" * 5000, "authorization_confirmed": True},
            {"target_domain": "example.com\x00.evil.test", "authorization_confirmed": True},
            {"target_domain": ["example.com"], "authorization_confirmed": True},
            {"target_domain": {"host": "example.com"}, "authorization_confirmed": True},
            {"target_domain": None, "authorization_confirmed": True},
            {"target_domain": 12345, "authorization_confirmed": True},
            {"target_domain": "example.com", "authorization_confirmed": "maybe"},
            {"target_domain": "例え.テスト", "authorization_confirmed": True},
            {"target_domain": "exam ple.com", "authorization_confirmed": True},
            {"target_domain": "http://169.254.169.254/", "authorization_confirmed": True},
            {"target_domain": "evil.com@127.0.0.1", "authorization_confirmed": True},
            {},
        ]
        for body in bodies:
            response = client.post("/api/v1/scans/", json=body, headers=headers)
            assert response.status_code < 500, (
                f"{body!r} produced {response.status_code}"
            )

    anyio.run(_run)


def test_malformed_json_body_does_not_500():
    response = _client().post(
        "/api/v1/scans/",
        content=b"{not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422, response.status_code


# --------------------------------------------------------------------------
# Scan admission control under concurrency
# --------------------------------------------------------------------------

def test_concurrent_requests_cannot_exceed_the_concurrency_limit():
    """Fire many simultaneous scan requests and count how many are admitted.

    The limit is enforced by counting active rows and then inserting, with no
    lock, so this documents whether the check-then-act gap is reachable.

    Driven with ``asyncio.gather`` on one event loop rather than threads: the
    requests interleave at their await points, which is exactly where the
    check-then-act window sits, and each task gets its own session so the
    connection pool cannot serialise the race away. Threads were tried first
    and deadlocked, because the async engine's pool belongs to a single loop.
    """
    async def _run():
        user_id, _token = await _make_user("racer@example.com")

        async with maker() as db:
            for i in range(settings.MAX_CONCURRENT_SCANS - 1):
                db.add(
                    ScanJob(
                        user_id=user_id,
                        target_domain=f"filler{i}.example.com",
                        target_url="https://filler.example.com",
                        status="running",
                        total_checks=1,
                    )
                )
            await db.commit()

        from app.services.scan_limits import (
            enforce_scan_admission,
            scan_admission_guard,
        )
        from app.services.scan_service import ScanService

        async def _attempt(i: int):
            # Exactly the check-then-act pair the endpoint performs, guard included.
            async with maker() as session:
                try:
                    async with scan_admission_guard():
                        await enforce_scan_admission(session, user_id)
                        await ScanService(session).create_scan(
                            user_id=user_id,
                            target_domain=f"race{i}.example.com",
                            authorization_confirmed=True,
                        )
                        await session.commit()
                    return True, None
                except Exception as exc:  # noqa: BLE001 - outcome is the data
                    await session.rollback()
                    return False, type(exc).__name__

        results = await asyncio.gather(*(_attempt(i) for i in range(8)))
        return results

    results = anyio.run(_run)
    admitted = sum(1 for ok, _ in results if ok)
    rejected = [name for ok, name in results if not ok]
    limit = settings.MAX_CONCURRENT_SCANS
    print(f"\nadmitted={admitted} limit={limit} rejected={rejected}")
    assert admitted <= limit, (
        f"concurrency limit bypassed: {admitted} scans admitted when only "
        f"{limit - (settings.MAX_CONCURRENT_SCANS - 1)} slot was free "
        f"(rejections: {rejected})"
    )
