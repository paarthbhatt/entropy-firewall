"""FastAPI application dependencies — dependency injection layer.

All shared resources (DB, Redis, Engine, Auth…) are injected through
FastAPI's ``Depends()`` system so routes stay thin and testable.
"""

from __future__ import annotations

from typing import Any, Optional

import redis.asyncio as aioredis
import structlog
from fastapi import Depends, HTTPException, Request, status

from entropy.config import get_settings
from entropy.core.engine import EntropyEngine
from entropy.db.repository import (
    APIKeyRepository,
    RequestLogRepository,
    SecurityEventRepository,
)
from entropy.providers.openai_provider import OpenAIProvider
from entropy.services.auth import AuthService
from entropy.services.rate_limiter import RateLimitService
from entropy.services.security_logger import SecurityLogger

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Resource getters  (pull from app.state set during lifespan)
# ---------------------------------------------------------------------------

def _get_redis(request: Request) -> aioredis.Redis:
    return request.app.state.redis


def _get_db_pool(request: Request) -> Any:
    return request.app.state.db_pool


# ---------------------------------------------------------------------------
# Service factories  (depend on resource getters)
# ---------------------------------------------------------------------------

def get_rate_limiter(
    redis: aioredis.Redis = Depends(_get_redis),
) -> RateLimitService:
    return RateLimitService(redis)


def get_engine() -> EntropyEngine:
    """Singleton-ish engine — created once, lives in module scope."""
    return _engine_singleton()


def get_provider() -> OpenAIProvider:
    settings = get_settings()
    if not settings.openai_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OPENAI_API_KEY is not configured",
        )
    return OpenAIProvider(api_key=settings.openai_api_key)


def get_request_log_repo(
    pool: Any = Depends(_get_db_pool),
) -> RequestLogRepository:
    return RequestLogRepository(pool)


def get_security_event_repo(
    pool: Any = Depends(_get_db_pool),
) -> SecurityEventRepository:
    return SecurityEventRepository(pool)


def get_api_key_repo(
    pool: Any = Depends(_get_db_pool),
) -> APIKeyRepository:
    return APIKeyRepository(pool)


def get_auth_service(
    repo: APIKeyRepository = Depends(get_api_key_repo),
) -> AuthService:
    return AuthService(repo)


def get_security_logger(
    repo: SecurityEventRepository = Depends(get_security_event_repo),
) -> SecurityLogger:
    return SecurityLogger(repo)


# ---------------------------------------------------------------------------
# Auth dependency  (extracts + validates API key from header)
# ---------------------------------------------------------------------------

async def require_auth(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service),
) -> dict[str, Any]:
    """Validate the ``X-API-Key`` header. Returns the key record."""
    settings = get_settings()
    raw_key = request.headers.get("X-API-Key", "")

    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    record = await auth_service.authenticate(raw_key)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    return record


# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------

_engine: Optional[EntropyEngine] = None


def _engine_singleton() -> EntropyEngine:
    global _engine
    if _engine is None:
        _engine = EntropyEngine()
    return _engine
