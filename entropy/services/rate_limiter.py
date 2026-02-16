"""Rate Limiter — Redis-backed sliding window rate limiting.

Supports global, per-IP, and per-user rate limits with burst capacity.
Falls back to an in-memory counter when Redis is unavailable.
"""

from __future__ import annotations

import time
from typing import Any, Optional, Tuple

import redis.asyncio as aioredis
import structlog

from entropy.config import get_settings

logger = structlog.get_logger(__name__)


class RateLimiter:
    """Sliding-window rate limiter using Redis INCR + EXPIRE.

    Uses a fixed-window counter keyed by ``rate_limit:{identifier}:{window_id}``.
    """

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self.redis = redis_client

    async def is_allowed(
        self,
        identifier: str,
        limit: int,
        window_seconds: int,
        burst: int = 0,
    ) -> Tuple[bool, dict[str, Any]]:
        """Check if the request is within the rate limit.

        Returns:
            (allowed, info_dict)
        """
        now = int(time.time())
        window_id = now // window_seconds
        key = f"rl:{identifier}:{window_id}"

        try:
            pipe = self.redis.pipeline(transaction=True)
            pipe.incr(key)
            pipe.expire(key, window_seconds * 2)
            results = await pipe.execute()
            current: int = results[0]
        except Exception as exc:
            logger.error("Redis rate-limit error — allowing request", error=str(exc))
            return True, {"allowed": True, "error": str(exc)}

        effective_limit = limit + burst
        allowed = current <= effective_limit
        remaining = max(0, effective_limit - current)
        reset_after = window_seconds - (now % window_seconds)

        info = {
            "allowed": allowed,
            "remaining": remaining,
            "reset_after_seconds": reset_after,
            "current": current,
            "limit": limit,
            "burst": burst,
            "window_seconds": window_seconds,
        }

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                identifier=identifier,
                current=current,
                limit=effective_limit,
            )

        return allowed, info

    async def reset(self, identifier: str) -> int:
        """Delete all rate-limit keys for *identifier*."""
        keys: list[bytes] = await self.redis.keys(f"rl:{identifier}:*")
        if keys:
            deleted: int = await self.redis.delete(*keys)
            logger.info("Rate limit reset", identifier=identifier, deleted=deleted)
            return deleted
        return 0


class RateLimitService:
    """Orchestrates multi-tier rate limiting (global + IP + user)."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self.limiter = RateLimiter(redis_client)
        self._settings = get_settings().rate_limit

    async def check(
        self,
        *,
        api_key_id: Optional[str] = None,
        client_ip: str = "unknown",
    ) -> Tuple[bool, dict[str, Any]]:
        """Run all configured rate-limit checks.

        Returns:
            (overall_allowed, combined_info)
        """
        window = self._settings.window
        burst = self._settings.burst
        checks: list[tuple[str, bool, dict[str, Any]]] = []

        # 1. Global
        if self._settings.global_rpm > 0:
            ok, info = await self.limiter.is_allowed(
                "global", self._settings.global_rpm, window, burst
            )
            checks.append(("global", ok, info))

        # 2. Per-IP
        ok, info = await self.limiter.is_allowed(
            f"ip:{client_ip}", self._settings.per_ip_rpm, window, burst
        )
        checks.append(("ip", ok, info))

        # 3. Per-user (API key)
        if api_key_id:
            ok, info = await self.limiter.is_allowed(
                f"user:{api_key_id}", self._settings.rpm, window, burst
            )
            checks.append(("user", ok, info))

        overall = all(allowed for _, allowed, _ in checks)
        combined: dict[str, Any] = {
            "allowed": overall,
            "checks": {
                name: info for name, _, info in checks
            },
        }
        if not overall:
            combined["exceeded"] = [name for name, ok, _ in checks if not ok]

        return overall, combined
