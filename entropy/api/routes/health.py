"""Health and metrics routes."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from entropy.api.dependencies import get_engine
from entropy.config import get_settings
from entropy.core.engine import EntropyEngine
from entropy.models.schemas import HealthResponse
from entropy.services.metrics import PATTERNS_LOADED, get_metrics_text
from starlette.responses import Response

router = APIRouter(tags=["system"])

# Track app start time
_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check(
    engine: EntropyEngine = Depends(get_engine),
) -> HealthResponse:
    """Health check endpoint."""
    settings = get_settings()
    patterns = engine.get_pattern_count()
    PATTERNS_LOADED.set(patterns)

    return HealthResponse(
        status="healthy",
        version=settings.version,
        environment=settings.environment,
        patterns_loaded=patterns,
        uptime_seconds=round(time.time() - _start_time, 1),
    )


@router.get("/metrics")
async def prometheus_metrics() -> Response:
    """Prometheus-compatible metrics endpoint."""
    return Response(
        content=get_metrics_text(),
        media_type="text/plain; charset=utf-8",
    )
