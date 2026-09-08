"""Database connection management using asyncpg."""

from __future__ import annotations

import asyncpg
import structlog

from entropy.config import get_settings

logger = structlog.get_logger(__name__)

# Module-level connection pool
_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    """Get or create the asyncpg connection pool."""
    global _pool  # noqa: PLW0603
    if _pool is None:
        _pool = await create_pool()
    return _pool


async def create_pool() -> asyncpg.Pool:
    """Create a new connection pool from settings."""
    settings = get_settings()
    ssl_mode = "require" if str(settings.db.host).endswith("supabase.co") else None
    pool = await asyncpg.create_pool(
        dsn=settings.db.dsn,
        min_size=settings.db.min_connections,
        max_size=settings.db.max_connections,
        command_timeout=30,
        ssl=ssl_mode,
    )
    logger.info(
        "Database pool created",
        host=settings.db.host,
        db=settings.db.name,
        min=settings.db.min_connections,
        max=settings.db.max_connections,
    )
    return pool


async def close_pool() -> None:
    """Close the connection pool."""
    global _pool  # noqa: PLW0603
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed")


async def init_database() -> None:
    """Initialize database schema from migration files.

    Applies each ``*.sql`` file exactly once, tracked in the
    ``schema_migrations`` table. Each migration runs inside a transaction so
    partial application is impossible, and ``ALTER TABLE``-style migrations
    work (unlike the old DuplicateTableError-skip approach).
    """
    from pathlib import Path  # noqa: PLC0415

    pool = await get_pool()

    migration_dir = Path(__file__).parent / "migrations"
    migration_files = sorted(migration_dir.glob("*.sql"))

    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename   TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        applied_rows = await conn.fetch("SELECT filename FROM schema_migrations")
        applied = {row["filename"] for row in applied_rows}

        for migration_file in migration_files:
            if migration_file.name in applied:
                logger.debug("Migration already applied", file=migration_file.name)
                continue
            sql = migration_file.read_text(encoding="utf-8")
            try:
                async with conn.transaction():
                    await conn.execute(sql)
                    await conn.execute(
                        "INSERT INTO schema_migrations (filename) VALUES ($1)",
                        migration_file.name,
                    )
                logger.info("Migration applied", file=migration_file.name)
            except Exception as exc:
                logger.error(
                    "Migration failed",
                    file=migration_file.name,
                    error=str(exc),
                )
                raise
