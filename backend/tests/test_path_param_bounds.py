"""Oversized integer path parameters must not surface as HTTP 500.

SQLite stores `INTEGER` primary keys as signed 64-bit values. An unbounded
Python `int` taken from a path segment (for example 400 nines) cannot be bound
by the driver, so SQLAlchemy raised `OverflowError: Python int too large to
convert to SQLite INTEGER` from inside the route. Nothing handled it, so every
affected endpoint answered 500 to unauthenticated-shaped input.

The identifiers are now bounded to the range the database can actually store, so
an out-of-range id is rejected during validation instead of exploding mid-query.
"""

from __future__ import annotations

import asyncio
import pathlib
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.security import get_current_user_id
from app.db.session import Base, get_db
from app.main import app

DB_FILE = pathlib.Path(tempfile.mkdtemp()) / "path_bounds.db"
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


async def _fake_user():
    return 1


@pytest.fixture(autouse=True)
def _app_dependencies():
    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_current_user_id] = _fake_user
    yield
    app.dependency_overrides.clear()


def _client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# An id that is a syntactically valid int but cannot be stored in a 64-bit
# column, and one that overflows by a single digit.
HUGE = "9" * 400
OVERFLOW_BY_ONE = str(2**63)

ID_ROUTES = [
    ("GET", "/api/v1/scans/{v}"),
    ("GET", "/api/v1/scans/{v}/status"),
    ("GET", "/api/v1/scans/{v}/recommendations"),
    ("DELETE", "/api/v1/scans/{v}"),
    ("GET", "/api/v1/reports/scan/{v}/pdf"),
    ("GET", "/api/v1/reports/scan/{v}/view"),
    ("GET", "/api/v1/reports/{v}/pdf"),
    ("GET", "/api/v1/reports/{v}/view"),
]


@pytest.mark.parametrize("method,template", ID_ROUTES)
@pytest.mark.parametrize("value", [HUGE, OVERFLOW_BY_ONE])
def test_oversized_id_is_rejected_without_a_server_error(method, template, value):
    response = _client().request(method, template.format(v=value))
    assert response.status_code != 500, (
        f"{method} {template} returned 500 for an out-of-range id"
    )
    assert response.status_code in (404, 422), (
        f"{method} {template} returned {response.status_code}"
    )


@pytest.mark.parametrize("method,template", ID_ROUTES)
def test_negative_id_is_handled(method, template):
    response = _client().request(method, template.format(v="-1"))
    assert response.status_code != 500
    assert response.status_code in (404, 422)


@pytest.mark.parametrize("method,template", ID_ROUTES)
def test_missing_but_valid_id_is_404(method, template):
    """Sanity check: the bounded range still admits ordinary ids."""
    response = _client().request(method, template.format(v="424242"))
    assert response.status_code == 404, response.text


def test_compare_route_survives_oversized_id():
    response = _client().get(f"/api/v1/scans/compare/1/{HUGE}")
    assert response.status_code != 500
    assert response.status_code in (404, 422)


def test_non_numeric_id_is_422():
    response = _client().get("/api/v1/scans/not-a-number")
    assert response.status_code == 422
