"""Admin routes — API key management."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status

from entropy.api.dependencies import get_auth_service, require_auth
from entropy.models.schemas import APIKeyCreateRequest, APIKeyCreateResponse
from entropy.services.auth import AuthService

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post(
    "/api-keys",
    response_model=APIKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    body: APIKeyCreateRequest,
    auth_record: dict[str, Any] = Depends(require_auth),
    auth_service: AuthService = Depends(get_auth_service),
) -> APIKeyCreateResponse:
    """Create a new API key (requires authentication)."""
    # Only master key or admin users can create keys
    if auth_record.get("id") != "master" and auth_record.get("user_id") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only master/admin users can create API keys",
        )

    key_id, raw_key = await auth_service.create_key(
        name=body.name,
        user_id=body.user_id,
        rate_limit_rpm=body.rate_limit_rpm,
    )

    from datetime import datetime, timezone

    return APIKeyCreateResponse(
        id=key_id,
        key=raw_key,
        key_prefix=raw_key[:12],
        name=body.name,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    auth_record: dict[str, Any] = Depends(require_auth),
    auth_service: AuthService = Depends(get_auth_service),
) -> None:
    """Revoke an API key."""
    if auth_record.get("id") != "master" and auth_record.get("user_id") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only master/admin users can revoke API keys",
        )

    ok = await auth_service.revoke_key(key_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
