"""Database connection management using asyncpg."""

from __future__ import annotations

from typing import Optional

import asyncpg
import structlog

from entropy.config import get_settings

logger = structlog.get_logger(__name__)

# Module-level connection pool
_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Get or create the asyncpg connection pool."""
    global _pool
    if _pool is None:
        _pool = await create_pool()
    return _pool


async def create_pool() -> asyncpg.Pool:
    """Create a new connection pool from settings."""
    settings = get_settings()
    pool = await asyncpg.create_pool(
        dsn=settings.db.dsn,
        min_size=settings.db.min_connections,
        max_size=settings.db.max_connections,
        command_timeout=30,
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
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed")


async def init_database() -> None:
    """Initialize database schema from migration files."""
    import importlib.resources as pkg_resources
    from pathlib import Path

    pool = await get_pool()

    migration_dir = Path(__file__).parent / "migrations"
    migration_files = sorted(migration_dir.glob("*.sql"))

    async with pool.acquire() as conn:
        for migration_file in migration_files:
            sql = migration_file.read_text(encoding="utf-8")
            try:
                await conn.execute(sql)
                logger.info("Migration applied", file=migration_file.name)
            except asyncpg.exceptions.DuplicateTableError:
                logger.debug("Migration already applied", file=migration_file.name)
            except Exception as exc:
                logger.error(
                    "Migration failed",
                    file=migration_file.name,
                    error=str(exc),
                )
                raise
