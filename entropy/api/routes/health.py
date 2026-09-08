"""Health and metrics routes."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from starlette.responses import Response

from entropy.api.dependencies import get_engine
from entropy.config import get_settings
from entropy.core.engine import EntropyEngine  # noqa: TC001
from entropy.models.schemas import HealthResponse
from entropy.services.metrics import PATTERNS_LOADED, get_metrics_text

router = APIRouter(tags=["system"])

# Track app start time
_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check(
    request: Request,
    engine: EntropyEngine = Depends(get_engine),  # noqa: B008
) -> HealthResponse:
    """Health check endpoint.

    Reports ``healthy`` when the detection engine is operational. Missing
    Redis/PostgreSQL only downgrades to ``degraded`` when dependencies are
    enforced (production); otherwise the firewall still scans correctly
    without them and reports ``healthy`` with the per-dependency flags
    showing what is down.
    """
    settings = get_settings()
    patterns = engine.get_pattern_count()
    PATTERNS_LOADED.set(patterns)

    redis_ok = False
    db_ok = request.app.state.db_pool is not None

    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is not None:
        try:
            await redis_client.ping()
            redis_ok = True
        except Exception:
            redis_ok = False

    deps_required = bool(settings.enforce_dependencies)
    overall_status = "healthy" if (redis_ok and db_ok) or not deps_required else "degraded"

    return HealthResponse(
        status=overall_status,
        version=settings.version,
        environment=settings.environment,
        patterns_loaded=patterns,
        uptime_seconds=round(time.time() - _start_time, 1),
        redis_connected=redis_ok,
        database_connected=db_ok,
    )


@router.get("/metrics")
async def prometheus_metrics(request: Request) -> Response:
    """Prometheus-compatible metrics endpoint.

    Open by default for scrapers. If ``ENTROPY_METRICS_TOKEN`` is configured,
    callers must present it as ``Authorization: Bearer <token>`` — this keeps
    internal request/threat counters out of unauthenticated hands.
    """
    settings = get_settings()
    expected = settings.metrics_token
    if expected:
        presented = request.headers.get("authorization", "")
        if presented != f"Bearer {expected}":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid metrics bearer token required",
            )
    return Response(
        content=get_metrics_text(),
        media_type="text/plain; charset=utf-8",
    )
