"""Tests for schema initialisation and Alembic readiness.

The contract is that ``USE_ALEMBIC=false`` (the default) behaves exactly as
before, and ``USE_ALEMBIC=true`` applies the checked-in migrations instead --
and that both routes end up with the same schema, so enabling Alembic cannot
silently change the shape of the database.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import settings
from app.db import session as db_session

BACKEND_DIR = Path(__file__).resolve().parents[1]
VERSIONS_DIR = BACKEND_DIR / "alembic" / "versions"


def _sync_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _async_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.as_posix()}"


def _schema(path: Path) -> dict:
    """A comparable description of the resulting schema."""
    engine = create_engine(_sync_url(path))
    try:
        inspector = inspect(engine)
        return {
            table: sorted(column["name"] for column in inspector.get_columns(table))
            for table in sorted(inspector.get_table_names())
        }
    finally:
        engine.dispose()


async def _create_all_schema(path: Path) -> dict:
    """Produce a schema the original way: create_all on a fresh database."""
    engine = create_async_engine(_async_url(path))

    def _create(sync_conn):
        db_session.Base.metadata.create_all(sync_conn)
        db_session._ensure_scan_job_score_breakdown(sync_conn)

    async with engine.begin() as conn:
        await conn.run_sync(_create)
    await engine.dispose()
    return _schema(path)


# --------------------------------------------------------------------------
# Repository layout
# --------------------------------------------------------------------------

def test_alembic_config_exists():
    assert (BACKEND_DIR / "alembic.ini").is_file()
    assert (BACKEND_DIR / "alembic" / "env.py").is_file()


def test_at_least_one_migration_is_committed():
    revisions = [p for p in VERSIONS_DIR.glob("*.py") if not p.name.startswith("_")]
    assert revisions, "no migration scripts found; the schema cannot be reproduced"


def test_alembic_url_is_not_hardcoded_in_the_ini():
    """The connection string must have a single source of truth."""
    ini = (BACKEND_DIR / "alembic.ini").read_text(encoding="utf-8")
    active = [
        line.split("=", 1)[1].strip()
        for line in ini.splitlines()
        if line.strip().startswith("sqlalchemy.url")
        and not line.strip().startswith("#")
    ]
    assert active == [""], (
        f"alembic.ini must leave sqlalchemy.url empty, found: {active}"
    )


# --------------------------------------------------------------------------
# create_all (default) path is unchanged
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_all_path_produces_the_expected_tables(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USE_ALEMBIC", False)
    db = tmp_path / "create_all.db"
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(db))
    monkeypatch.setattr(db_session, "engine", create_async_engine(_async_url(db)))

    await db_session.init_db()

    tables = set(_schema(db))
    assert {"users", "scan_jobs", "scan_results", "findings", "reports", "audit_logs"} <= tables
    # The default path must not create migration bookkeeping.
    assert "alembic_version" not in tables


@pytest.mark.asyncio
async def test_create_all_still_backfills_legacy_columns(tmp_path, monkeypatch):
    """The SQLite backfill for older databases must keep working."""
    monkeypatch.setattr(settings, "USE_ALEMBIC", False)
    db = tmp_path / "legacy.db"

    # Recreate a pre-backfill scan_jobs table.
    engine = create_engine(_sync_url(db))
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE scan_jobs (id INTEGER PRIMARY KEY)")
    engine.dispose()

    async_engine = create_async_engine(_async_url(db))
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(db))
    monkeypatch.setattr(db_session, "engine", async_engine)

    def _backfill(sync_conn):
        db_session._ensure_scan_job_score_breakdown(sync_conn)

    async with async_engine.begin() as conn:
        await conn.run_sync(_backfill)
    await async_engine.dispose()

    columns = {c["name"] for c in inspect(create_engine(_sync_url(db))).get_columns("scan_jobs")}
    assert "score_breakdown" in columns
    assert "ai_explanation_payload" in columns


# --------------------------------------------------------------------------
# Alembic path
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_alembic_path_stamps_and_upgrades(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USE_ALEMBIC", True)
    db = tmp_path / "migrated.db"
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(db))
    monkeypatch.setattr(db_session, "engine", create_async_engine(_async_url(db)))

    await db_session.init_db()

    schema = _schema(db)
    assert "alembic_version" in schema, "migrations did not run"
    assert {"users", "scan_jobs", "scan_results", "findings", "reports", "audit_logs"} <= set(schema)


@pytest.mark.asyncio
async def test_both_paths_produce_the_same_schema(tmp_path, monkeypatch):
    """Enabling Alembic must not change the shape of the database."""
    legacy = tmp_path / "legacy_create_all.db"
    migrated = tmp_path / "alembic.db"

    legacy_schema = await _create_all_schema(legacy)

    monkeypatch.setattr(settings, "USE_ALEMBIC", True)
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(migrated))
    monkeypatch.setattr(db_session, "engine", create_async_engine(_async_url(migrated)))
    await db_session.init_db()
    migrated_schema = _schema(migrated)

    # alembic_version is expected only in the migrated database.
    migrated_schema.pop("alembic_version", None)

    assert migrated_schema == legacy_schema


@pytest.mark.asyncio
async def test_adopting_an_existing_create_all_database_is_non_destructive(tmp_path, monkeypatch):
    """Switching USE_ALEMBIC on for an existing database must not lose data."""
    db = tmp_path / "existing.db"

    # Build the schema the old way and insert a row.
    engine = create_async_engine(_async_url(db))

    def _create(sync_conn):
        db_session.Base.metadata.create_all(sync_conn)

    async with engine.begin() as conn:
        await conn.run_sync(_create)
    await engine.dispose()

    sync_engine = create_engine(_sync_url(db))
    with sync_engine.begin() as conn:
        conn.exec_driver_sql(
            "INSERT INTO users (email, username, hashed_password, is_active, is_admin, "
            "created_at, updated_at) VALUES "
            "('keep@example.com', 'keepme', 'x', 1, 0, "
            "'2024-01-01 00:00:00', '2024-01-01 00:00:00')"
        )
    sync_engine.dispose()

    monkeypatch.setattr(settings, "USE_ALEMBIC", True)
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(db))
    monkeypatch.setattr(db_session, "engine", create_async_engine(_async_url(db)))
    await db_session.init_db()

    sync_engine = create_engine(_sync_url(db))
    try:
        with sync_engine.connect() as conn:
            rows = conn.exec_driver_sql(
                "SELECT email FROM users WHERE email = 'keep@example.com'"
            ).fetchall()
        assert len(rows) == 1, "existing data was destroyed by the migration"
    finally:
        sync_engine.dispose()


def test_sync_engine_helper_maps_the_async_driver():
    """A sync DBAPI must be used, so inspect()/ALTER work outside the event loop."""
    engine = db_session._sync_engine()
    try:
        assert not engine.dialect.is_async
        assert engine.dialect.name == "sqlite"
    finally:
        engine.dispose()


# --------------------------------------------------------------------------
# Adoption of a database that carries an empty alembic_version table
# --------------------------------------------------------------------------

def _recorded_revisions(path: Path) -> list[str]:
    engine = create_engine(_sync_url(path))
    try:
        with engine.connect() as conn:
            return [
                row[0]
                for row in conn.exec_driver_sql(
                    "SELECT version_num FROM alembic_version"
                ).fetchall()
            ]
    finally:
        engine.dispose()


async def _create_legacy_db_with_stale_version_table(path: Path) -> None:
    """A create_all database that also has an empty alembic_version table.

    This is the shape a real install ends up in when a migration was
    interrupted before it could record a revision, and the shape the shipped
    development database is in.
    """
    engine = create_async_engine(_async_url(path))

    def _create(sync_conn):
        db_session.Base.metadata.create_all(sync_conn)
        sync_conn.exec_driver_sql(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"
        )

    async with engine.begin() as conn:
        await conn.run_sync(_create)
    await engine.dispose()


@pytest.mark.asyncio
async def test_adoption_recovers_when_the_version_table_is_present_but_empty(
    tmp_path, monkeypatch
):
    """An empty version table must be treated as un-adopted, not as migrated.

    Previously the presence of the table suppressed the adoption stamp, so
    ``upgrade head`` replayed the initial migration and aborted with
    "table users already exists", making the app fail to start.
    """
    db = tmp_path / "stale_version_table.db"
    await _create_legacy_db_with_stale_version_table(db)

    assert _recorded_revisions(db) == [], "fixture should start with no revision"

    monkeypatch.setattr(settings, "USE_ALEMBIC", True)
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(db))
    monkeypatch.setattr(db_session, "engine", create_async_engine(_async_url(db)))

    await db_session.init_db()  # must not raise

    revisions = _recorded_revisions(db)
    assert revisions, "adoption must record a revision, leaving the table empty"


@pytest.mark.asyncio
async def test_adoption_of_an_empty_version_table_preserves_data(tmp_path, monkeypatch):
    """Recovering the version bookkeeping must not touch existing rows."""
    db = tmp_path / "stale_with_data.db"
    await _create_legacy_db_with_stale_version_table(db)

    engine = create_engine(_sync_url(db))
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "INSERT INTO users (email, username, hashed_password, is_active, is_admin, "
            "created_at, updated_at) VALUES "
            "('keep@example.com', 'keepme', 'x', 1, 0, "
            "'2024-01-01 00:00:00', '2024-01-01 00:00:00')"
        )
    engine.dispose()

    monkeypatch.setattr(settings, "USE_ALEMBIC", True)
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(db))
    monkeypatch.setattr(db_session, "engine", create_async_engine(_async_url(db)))
    await db_session.init_db()

    engine = create_engine(_sync_url(db))
    try:
        with engine.connect() as conn:
            rows = conn.exec_driver_sql(
                "SELECT email FROM users WHERE email = 'keep@example.com'"
            ).fetchall()
        assert len(rows) == 1, "existing data was destroyed while adopting"
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_adoption_is_idempotent_on_a_second_startup(tmp_path, monkeypatch):
    """A migrated database must be left alone on subsequent startups."""
    db = tmp_path / "idempotent.db"
    await _create_legacy_db_with_stale_version_table(db)

    monkeypatch.setattr(settings, "USE_ALEMBIC", True)
    monkeypatch.setattr(settings, "DATABASE_URL", _async_url(db))
    monkeypatch.setattr(db_session, "engine", create_async_engine(_async_url(db)))

    await db_session.init_db()
    first = _recorded_revisions(db)
    assert first

    await db_session.init_db()  # must not raise or re-stamp
    assert _recorded_revisions(db) == first
