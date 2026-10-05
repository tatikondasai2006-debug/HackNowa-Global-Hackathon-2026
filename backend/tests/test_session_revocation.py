"""Access must be re-checked against the account on every authenticated request.

`get_current_user_id` used to trust the `sub` claim alone. Because `is_active`
was only consulted while logging in, deactivating or deleting an account left
every already-issued token fully usable: the holder could still read their
profile, read their scans, and start new scans until the token expired.

These tests pin the corrected behaviour:
  * an inactive account is refused even with a valid, unexpired token
  * a token for an account that no longer exists is refused
  * an active account is unaffected
  * no authenticated route is reachable with a deactivated account's token
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

from app.core.security import create_access_token, get_current_user_id
from app.db.session import Base, get_db
from app.main import app
from app.models.user import User
from app.services.user_service import UserService

DB_FILE = pathlib.Path(tempfile.mkdtemp()) / "session_revocation.db"
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
    """Wire the real auth dependency to the throwaway database.

    `get_current_user_id` is deliberately *not* overridden: the point of these
    tests is the real token -> account lookup.
    """
    app.dependency_overrides[get_db] = _override_db
    yield
    app.dependency_overrides.clear()


async def _make_user(email: str, active: bool = True) -> tuple[int, str]:
    from app.schemas.user import UserRegister

    async with maker() as db:
        user = await UserService(db).register(
            UserRegister(email=email, username=email.split("@")[0],
                         password="Str0ng!Passw0rd")
        )
        user.is_active = active
        await db.commit()
        return user.id, create_access_token({"sub": str(user.id), "email": email})


def _client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# --------------------------------------------------------------------------
# The dependency itself
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_active_user_token_is_accepted():
    user_id, token = await _make_user("active@example.com", active=True)
    async with maker() as db:
        resolved = await get_current_user_id(
            credentials=_credentials(token), db=db
        )
    assert resolved == user_id


@pytest.mark.asyncio
async def test_inactive_user_token_is_rejected():
    """The core defect: a deactivated account keeps a usable token."""
    from fastapi import HTTPException

    _user_id, token = await _make_user("inactive@example.com", active=False)
    async with maker() as db:
        with pytest.raises(HTTPException) as exc:
            await get_current_user_id(credentials=_credentials(token), db=db)
    assert exc.value.status_code == 401
    assert "inactive" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_token_for_deleted_user_is_rejected():
    """A deleted account must not remain reachable through an old token."""
    from fastapi import HTTPException

    user_id, token = await _make_user("gone@example.com", active=True)
    async with maker() as db:
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one()
        await db.delete(user)
        await db.commit()
        with pytest.raises(HTTPException) as exc:
            await get_current_user_id(credentials=_credentials(token), db=db)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_deactivation_takes_effect_without_reissuing_a_token():
    """Flipping is_active must revoke the *existing* token immediately."""
    from fastapi import HTTPException

    user_id, token = await _make_user("revoked@example.com", active=True)
    async with maker() as db:
        await get_current_user_id(credentials=_credentials(token), db=db)  # works

        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one()
        user.is_active = False
        await db.commit()

        with pytest.raises(HTTPException):
            await get_current_user_id(credentials=_credentials(token), db=db)


# --------------------------------------------------------------------------
# End-to-end: no authenticated route may be reached
# --------------------------------------------------------------------------

def test_inactive_user_cannot_read_profile():
    asyncio.run(_seed())
    _id, token = asyncio.run(_make_user("e2e_profile@example.com", active=False))
    r = _client().get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, r.text


def test_inactive_user_cannot_start_a_scan():
    _id, token = asyncio.run(_make_user("e2e_scan@example.com", active=False))
    r = _client().post(
        "/api/v1/scans/",
        json={"target_domain": "example.com", "authorization_confirmed": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401, r.text


def test_inactive_user_cannot_read_dashboard():
    _id, token = asyncio.run(_make_user("e2e_dash@example.com", active=False))
    r = _client().get("/api/v1/dashboard/stats",
                      headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401, r.text


def test_active_user_still_works_end_to_end():
    _id, token = asyncio.run(_make_user("e2e_ok@example.com", active=True))
    r = _client().get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "e2e_ok@example.com"


async def _seed():
    async with maker() as db:
        await db.execute(select(User).limit(1))
        await db.commit()


def _credentials(token: str):
    from fastapi.security import HTTPAuthorizationCredentials

    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
