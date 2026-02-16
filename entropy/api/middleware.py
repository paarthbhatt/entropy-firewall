"""Custom middleware for the Entropy API."""

from __future__ import annotations

import time

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from entropy.services.metrics import REQUEST_DURATION

logger = structlog.get_logger(__name__)


class TimingMiddleware(BaseHTTPMiddleware):
    """Add ``X-Processing-Time-Ms`` header and record Prometheus histogram."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        elapsed_ms = round(elapsed * 1000, 2)

        response.headers["X-Processing-Time-Ms"] = str(elapsed_ms)

        # Prometheus
        endpoint = request.url.path
        REQUEST_DURATION.labels(endpoint=endpoint).observe(elapsed)

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request at INFO level."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        logger.info(
            "Incoming request",
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )
        response = await call_next(request)
        logger.info(
            "Response sent",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
        )
        return response
