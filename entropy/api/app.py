"""Main FastAPI application — Entropy LLM Firewall.

Wires up all routes, middleware, lifespan events, and error handlers.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from entropy.api.middleware import RequestLoggingMiddleware, TimingMiddleware
from entropy.api.routes import admin, chat, health
from entropy.config import get_settings
from entropy.db.connection import close_pool, get_pool, init_database

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
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
        await redis_client.ping()
        app.state.redis = redis_client
        logger.info("Redis connected", url=settings.redis.url)
    except Exception as exc:
        logger.error("Redis connection failed — rate limiting disabled", error=str(exc))
        # Create a dummy Redis that won't break the app
        app.state.redis = aioredis.from_url("redis://localhost:6379/0", decode_responses=True)

    # Connect PostgreSQL
    try:
        app.state.db_pool = await get_pool()
        await init_database()
        logger.info("Database connected and migrated")
    except Exception as exc:
        logger.error("Database connection failed — audit logging disabled", error=str(exc))
        app.state.db_pool = None

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer()
            if not settings.logging.json_format
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            structlog.get_level_from_name(settings.logging.level)
        ),
    )

    yield

    # -- Shutdown --
    logger.info("Shutting down Entropy")
    try:
        await app.state.redis.close()
    except Exception:
        pass
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
    app.add_middleware(BaseHTTPMiddleware, dispatch=RequestLoggingMiddleware().dispatch)
    app.add_middleware(BaseHTTPMiddleware, dispatch=TimingMiddleware().dispatch)

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
