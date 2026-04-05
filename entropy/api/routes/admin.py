"""Admin routes — API key management."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status

from entropy.api.dependencies import get_auth_service, get_request_log_repo, require_auth
from entropy.db.repository import RequestLogRepository  # noqa: TC001
from entropy.models.schemas import APIKeyCreateRequest, APIKeyCreateResponse
from entropy.services.auth import AuthService  # noqa: TC001

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin(auth_record: dict[str, Any]) -> None:
    if auth_record.get("id") != "master" and auth_record.get("user_id") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only master/admin users can access this endpoint",
        )


@router.post(
    "/api-keys",
    response_model=APIKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    body: APIKeyCreateRequest,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    auth_service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> APIKeyCreateResponse:
    """Create a new API key (requires authentication)."""
    _require_admin(auth_record)

    key_id, raw_key = await auth_service.create_key(
        name=body.name,
        user_id=body.user_id,
        rate_limit_rpm=body.rate_limit_rpm,
    )

    return APIKeyCreateResponse(
        id=key_id,
        key=raw_key,
        key_prefix=raw_key[:12],
        name=body.name,
        created_at=datetime.now(UTC).isoformat(),
    )


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    auth_service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> None:
    """Revoke an API key."""
    _require_admin(auth_record)

    ok = await auth_service.revoke_key(key_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )


@router.get("/dashboard/summary")
async def dashboard_summary(
    hours: int = 24,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    log_repo: RequestLogRepository = Depends(get_request_log_repo),  # noqa: B008
) -> dict[str, Any]:
    """Return aggregate security metrics for dashboard UI."""
    _require_admin(auth_record)
    if hours < 1 or hours > 24 * 30:
        raise HTTPException(status_code=400, detail="hours must be between 1 and 720")
    return await log_repo.dashboard_summary(hours=hours)


@router.get("/dashboard/threats")
async def dashboard_threats(
    hours: int = 24,
    limit: int = 8,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    log_repo: RequestLogRepository = Depends(get_request_log_repo),  # noqa: B008
) -> dict[str, Any]:
    """Return top threat categories for dashboard charting."""
    _require_admin(auth_record)
    if hours < 1 or hours > 24 * 30:
        raise HTTPException(status_code=400, detail="hours must be between 1 and 720")
    if limit < 1 or limit > 25:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 25")
    data = await log_repo.top_threat_categories(hours=hours, limit=limit)
    return {"window_hours": hours, "items": data}
