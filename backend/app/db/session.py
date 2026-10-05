"""Async SQLAlchemy database session management."""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from sqlalchemy import inspect, text

from app.core.config import settings

# Async driver -> synchronous equivalent, used only to open a plain connection
# for schema inspection while adopting an existing database.
_ASYNC_TO_SYNC_DRIVERS = {
    "aiosqlite": "sqlite",
    "asyncpg": "postgresql",
    "aiomysql": "mysql",
}

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)

# Create async session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency that provides a database session.

    Yields an async session and ensures cleanup on completion.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize the database schema at application startup.

    Two modes, selected by ``USE_ALEMBIC``:

    * ``False`` (default) keeps the original behaviour: ``create_all`` plus a
      small SQLite backfill for columns added after a database was first
      created. Existing development databases are untouched.
    * ``True`` runs ``alembic upgrade head`` instead, which is the mode to use
      for any real deployment. A database that predates Alembic is stamped
      first so it is adopted rather than rebuilt, so no data is destroyed.
    """
    _register_models()

    if settings.USE_ALEMBIC:
        await run_migrations()
        return

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_scan_job_score_breakdown)


def _register_models() -> None:
    """Import the models so every table is present on Base.metadata."""
    from app.models.user import User  # noqa: F401
    from app.models.scan import (  # noqa: F401
        AuditLog,
        Finding,
        Report,
        ScanJob,
        ScanResult,
    )


def _alembic_config():
    """Build an Alembic config with absolute paths, independent of the cwd."""
    from pathlib import Path

    from alembic.config import Config

    backend_dir = Path(__file__).resolve().parents[2]
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "alembic"))
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
    return config


async def run_migrations() -> None:
    """Apply Alembic migrations to ``settings.DATABASE_URL``.

    Alembic's own environment builds its engine and calls ``asyncio.run``, which
    cannot be nested inside the running startup loop, so the migration is driven
    on a worker thread with its own event loop.
    """
    import asyncio

    from alembic import command
    from sqlalchemy import inspect as sa_inspect

    def _migrate() -> None:
        config = _alembic_config()

        # Adopt a database that already has the app tables but was created by
        # create_all. Without this, upgrade head would try to create existing
        # tables and abort. Stamping records the current revision instead.
        #
        # "Unstamped" means no revision is actually *recorded*, not merely that
        # the version table is absent: a database can carry an empty
        # alembic_version table (left behind by a create_all-era install or a
        # migration that failed before committing), and Alembic would then
        # replay the initial migration and fail on the existing tables.
        sync_engine = _sync_engine()
        try:
            with sync_engine.connect() as conn:
                inspector = sa_inspect(conn)
                tables = set(inspector.get_table_names())
                has_app_tables = bool(tables & set(Base.metadata.tables))
                has_revision = False
                if "alembic_version" in tables:
                    has_revision = bool(
                        conn.execute(
                            text("SELECT 1 FROM alembic_version LIMIT 1")
                        ).first()
                    )
        finally:
            sync_engine.dispose()

        if has_app_tables and not has_revision:
            command.stamp(config, "head")
        command.upgrade(config, "head")

    # Release the application's pooled connections before Alembic opens its own.
    # This must be awaited on the running loop: AsyncEngine.dispose() is a
    # coroutine, so calling it from the worker thread would only create an
    # un-awaited coroutine and leave the connections open. The engine reconnects
    # lazily afterwards, so the app keeps working.
    await engine.dispose()
    await asyncio.to_thread(_migrate)


def _sync_engine():
    """A synchronous engine on the same database, for schema inspection only."""
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    url = make_url(settings.DATABASE_URL)
    sync_driver = _ASYNC_TO_SYNC_DRIVERS.get(url.get_driver_name(), url.get_driver_name())
    return create_engine(url.set(drivername=sync_driver))


def _ensure_scan_job_score_breakdown(sync_conn):
    """Add score_breakdown to existing SQLite databases created before the column existed."""
    inspector = inspect(sync_conn)
    if "scan_jobs" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("scan_jobs")}
    if "score_breakdown" not in columns:
        sync_conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN score_breakdown JSON"))
    if "ai_explanation_payload" not in columns:
        sync_conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN ai_explanation_payload JSON"))


async def close_db():
    """Dispose database engine connections.

    Used during application shutdown.
    """
    await engine.dispose()
