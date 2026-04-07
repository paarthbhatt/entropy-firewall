"""Redis-backed canary token storage for enterprise deployments.

Provides persistent, distributed canary token storage with automatic TTL
cleanup and support for multi-instance deployments.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class CanaryStore:
    """Redis-backed storage for canary tokens.

    Used in enterprise deployments for:
    - Persistent canary storage across restarts
    - Multi-instance support (shared state)
    - Automatic TTL-based cleanup
    - Audit trail of canary detections
    """

    # Redis key prefixes
    TOKEN_PREFIX = "entropy:canary:token:"
    REQUEST_PREFIX = "entropy:canary:request:"
    DETECTION_PREFIX = "entropy:canary:detection:"

    def __init__(
        self,
        redis_client: Any,
        ttl_seconds: int = 300,
    ) -> None:
        """Initialize the canary store.

        Args:
            redis_client: Redis async client
            ttl_seconds: Time-to-live for canary tokens
        """
        self.redis = redis_client
        self.ttl_seconds = ttl_seconds

    async def store(
        self,
        token: str,
        request_id: str,
        system_prompt_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store a canary token with TTL.

        Args:
            token: The canary token
            request_id: Associated request ID
            system_prompt_hash: Hash of the system prompt
            metadata: Additional metadata
        """
        key = f"{self.TOKEN_PREFIX}{token}"
        data = {
            "token": token,
            "request_id": request_id,
            "injected_at": datetime.utcnow().isoformat(),
            "system_prompt_hash": system_prompt_hash,
            "metadata": metadata or {},
        }

        await self.redis.setex(
            key,
            self.ttl_seconds,
            json.dumps(data),
        )

        # Also create request ID -> token mapping
        request_key = f"{self.REQUEST_PREFIX}{request_id}"
        await self.redis.setex(
            request_key,
            self.ttl_seconds,
            token,
        )

        logger.debug(
            "Canary token stored in Redis",
            token=token[:16] + "...",
            request_id=request_id,
            ttl_seconds=self.ttl_seconds,
        )

    async def get(self, token: str) -> dict[str, Any] | None:
        """Retrieve a canary token record.

        Args:
            token: The canary token to retrieve

        Returns:
            Token data or None if not found
        """
        key = f"{self.TOKEN_PREFIX}{token}"
        data = await self.redis.get(key)

        if data:
            return json.loads(data)
        return None

    async def get_by_request(self, request_id: str) -> str | None:
        """Get canary token by request ID.

        Args:
            request_id: The request ID

        Returns:
            Canary token or None
        """
        key = f"{self.REQUEST_PREFIX}{request_id}"
        return await self.redis.get(key)

    async def exists(self, token: str) -> bool:
        """Check if a canary token exists and is valid.

        Args:
            token: The canary token to check

        Returns:
            True if token exists and hasn't expired
        """
        key = f"{self.TOKEN_PREFIX}{token}"
        return await self.redis.exists(key) > 0

    async def remove(self, token: str) -> None:
        """Remove a canary token.

        Args:
            token: The canary token to remove
        """
        key = f"{self.TOKEN_PREFIX}{token}"
        await self.redis.delete(key)

        logger.debug("Canary token removed from Redis", token=token[:16] + "...")

    async def record_detection(
        self,
        token: str,
        request_id: str,
        leaked_content: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a canary detection for audit trail.

        Args:
            token: The detected canary token
            request_id: Associated request ID
            leaked_content: Context around the leak
            metadata: Additional metadata
        """
        # Generate a detection ID
        import uuid  # noqa: PLC0415

        detection_id = str(uuid.uuid4())

        key = f"{self.DETECTION_PREFIX}{detection_id}"
        data = {
            "detection_id": detection_id,
            "token": token,
            "request_id": request_id,
            "detected_at": datetime.utcnow().isoformat(),
            "leaked_content": leaked_content,
            "metadata": metadata or {},
        }

        # Store detection with longer TTL (for audit)
        # Default: 30 days retention for detections
        await self.redis.setex(
            key,
            30 * 24 * 60 * 60,  # 30 days
            json.dumps(data),
        )

        logger.critical(
            "Canary detection recorded in Redis",
            detection_id=detection_id,
            token=token[:16] + "...",
            request_id=request_id,
        )

    async def get_detections(
        self,
        request_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get canary detections.

        Args:
            request_id: Optional filter by request ID
            limit: Maximum number of results

        Returns:
            List of detection records
        """
        detections = []

        # Scan for detection keys
        pattern = f"{self.DETECTION_PREFIX}*"
        cursor = 0

        while True:
            cursor, keys = await self.redis.scan(
                cursor=cursor,
                match=pattern,
                count=100,
            )

            for key in keys[:limit]:
                data = await self.redis.get(key)
                if data:
                    record = json.loads(data)
                    if request_id is None or record.get("request_id") == request_id:
                        detections.append(record)

            if cursor == 0 or len(detections) >= limit:
                break

        return detections[:limit]

    async def get_stats(self) -> dict[str, Any]:
        """Get canary token statistics.

        Returns:
            Statistics about active tokens and detections
        """
        # Count active tokens
        token_pattern = f"{self.TOKEN_PREFIX}*"
        token_count = 0
        cursor = 0
        while True:
            cursor, keys = await self.redis.scan(
                cursor=cursor,
                match=token_pattern,
                count=1000,
            )
            token_count += len(keys)
            if cursor == 0:
                break

        # Count detections
        detection_pattern = f"{self.DETECTION_PREFIX}*"
        detection_count = 0
        cursor = 0
        while True:
            cursor, keys = await self.redis.scan(
                cursor=cursor,
                match=detection_pattern,
                count=1000,
            )
            detection_count += len(keys)
            if cursor == 0:
                break

        return {
            "active_tokens": token_count,
            "total_detections": detection_count,
        }


__all__ = ["CanaryStore"]
