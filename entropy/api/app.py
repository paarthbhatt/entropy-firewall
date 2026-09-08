"""Main FastAPI application — Entropy LLM Firewall.

Wires up all routes, middleware, lifespan events, and error handlers.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from typing import Any, cast

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from entropy.api.middleware import RequestLoggingMiddleware, TimingMiddleware
from entropy.api.routes import admin, chat, health
from entropy.config import get_settings
from entropy.db.connection import close_pool, get_pool, init_database
from entropy.db.repository import RequestLogRepository
from entropy.providers.registry import get_registry

logger = structlog.get_logger(__name__)

_RETENTION_INTERVAL_SECONDS = 24 * 60 * 60  # daily purge


async def _retention_loop() -> None:
    """Periodically purge request logs older than the retention window."""
    settings = get_settings()
    retention_days = settings.db.log_retention_days
    if retention_days <= 0:
        logger.info("Request log retention purge disabled")
        return
    while True:
        try:
            await asyncio.sleep(_RETENTION_INTERVAL_SECONDS)
            pool = await get_pool()
            deleted = await RequestLogRepository(pool).delete_old_logs(days=retention_days)
            if deleted:
                logger.info(
                    "Purged old request logs",
                    deleted=deleted,
                    retention_days=retention_days,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Request log retention purge failed", error=str(exc))


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Application startup / shutdown lifecycle."""
    settings = get_settings()

    # -- Startup --
    logger.info(
        "Starting Entropy",
        version=settings.version,
        environment=settings.environment,
    )

    # Connect Redis
    try:
        redis_client = aioredis.from_url(
            settings.redis.url,
            socket_timeout=settings.redis.socket_timeout,
            decode_responses=True,
        )
        # redis-py types ping() differently across versions
        # (Coroutine vs Awaitable[bool] | bool); normalize via cast.
        await cast("Any", redis_client.ping())
        app.state.redis = redis_client
        logger.info("Redis connected", url=settings.redis.url)
    except Exception as exc:
        logger.error("Redis connection failed — rate limiting disabled", error=str(exc))
        if settings.environment == "production" and settings.enforce_dependencies:
            raise RuntimeError("Redis connection failed in production") from exc
        # Create a dummy Redis that won't break the app
        app.state.redis = aioredis.from_url("redis://localhost:6379/0", decode_responses=True)

    # Connect PostgreSQL
    try:
        app.state.db_pool = await get_pool()
        await init_database()
        logger.info("Database connected and migrated")
        # Retention: keep the audit table bounded with a daily purge task
        app.state.retention_task = asyncio.create_task(_retention_loop())
    except Exception as exc:
        logger.error("Database connection failed — audit logging disabled", error=str(exc))
        if settings.environment == "production" and settings.enforce_dependencies:
            raise RuntimeError("Database connection failed in production") from exc
        app.state.db_pool = None
        app.state.retention_task = None

    # Configure structlog
    log_level = getattr(logging, settings.logging.level.upper(), logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer()
            if not settings.logging.json_format
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
    )

    yield

    # -- Shutdown --
    logger.info("Shutting down Entropy")

    retention_task = getattr(app.state, "retention_task", None)
    if retention_task is not None:
        retention_task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await retention_task

    # Close cached upstream provider connections (drains httpx pools)
    with suppress(Exception):
        await get_registry().close_all()

    shutdown_redis = getattr(app.state, "redis", None)
    if shutdown_redis is not None:
        with suppress(Exception):
            # redis-py >= 5 uses aclose(); older versions use close().
            close = getattr(shutdown_redis, "aclose", None) or shutdown_redis.close
            result = close()
            if asyncio.iscoroutine(result):
                await result
    await close_pool()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description="🔥 Entropy — LLM Security Firewall. Ordering the chaos.",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # -- CORS --
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Custom middleware (outer → inner execution order) --
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(TimingMiddleware)

    # -- Routes --
    app.include_router(health.router)
    app.include_router(chat.router)
    app.include_router(admin.router)

    # -- Exception handlers --
    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException) -> JSONResponse:
        logger.warning(
            "HTTP error",
            status=exc.status_code,
            detail=exc.detail,
            path=request.url.path,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail},
        )

    @app.exception_handler(Exception)
    async def general_exc_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception", path=request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"},
        )

    return app


# Module-level app instance for uvicorn
app = create_app()
