"""Data access layer for Entropy."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    import asyncpg

logger = structlog.get_logger(__name__)


class RequestLogRepository:
    """Repository for request audit logs."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    @property
    def enabled(self) -> bool:
        return self.pool is not None

    async def create(
        self,
        *,
        api_key_id: str | None = None,
        client_ip: str,
        provider: str = "openai",
        model: str | None = None,
        message_count: int = 0,
        input_tokens: int = 0,
        status: str = "allowed",
        threat_level: str | None = None,
        confidence: float | None = None,
        threats: list[dict[str, Any]] | None = None,
        output_tokens: int = 0,
        output_sanitized: bool = False,
        sanitizations: list[dict[str, Any]] | None = None,
        processing_ms: float = 0.0,
        provider_ms: float = 0.0,
        total_ms: float = 0.0,
    ) -> str:
        """Insert a request log entry. Returns the log ID."""
        log_id = str(uuid.uuid4())
        if self.pool is None:
            return log_id
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO request_logs (
                    id, api_key_id, client_ip, provider, model,
                    message_count, input_tokens, status, threat_level,
                    confidence, threats_json, output_tokens, output_sanitized,
                    sanitization_json, processing_ms, provider_ms, total_ms
                ) VALUES (
                    $1, $2, $3, $4, $5,
                    $6, $7, $8, $9,
                    $10, $11, $12, $13,
                    $14, $15, $16, $17
                )
                """,
                uuid.UUID(log_id),
                uuid.UUID(api_key_id) if api_key_id else None,
                client_ip,
                provider,
                model,
                message_count,
                input_tokens,
                status,
                threat_level,
                confidence,
                json.dumps(threats or []),
                output_tokens,
                output_sanitized,
                json.dumps(sanitizations or []),
                processing_ms,
                provider_ms,
                total_ms,
            )
        return log_id

    async def dashboard_summary(self, *, hours: int = 24) -> dict[str, Any]:
        """Aggregate request/security summary for dashboard views."""
        if self.pool is None:
            return {
                "window_hours": hours,
                "total_requests": 0,
                "blocked_requests": 0,
                "sanitized_requests": 0,
                "blocked_rate": 0.0,
                "avg_latency_ms": 0.0,
                "avg_processing_ms": 0.0,
                "last_event_at": None,
            }
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                WITH scoped AS (
                    SELECT *
                    FROM request_logs
                    WHERE created_at >= NOW() - ($1::text || ' hours')::interval
                )
                SELECT
                    COUNT(*)::bigint AS total_requests,
                    COUNT(*) FILTER (WHERE status = 'blocked')::bigint AS blocked_requests,
                    COUNT(*) FILTER (WHERE status = 'sanitized')::bigint AS sanitized_requests,
                    COALESCE(AVG(total_ms), 0)::double precision AS avg_latency_ms,
                    COALESCE(AVG(processing_ms), 0)::double precision AS avg_processing_ms,
                    COALESCE(MAX(created_at), NOW()) AS last_event_at
                FROM scoped
                """,
                str(hours),
            )

            total_requests = int(row["total_requests"] or 0)
            blocked_requests = int(row["blocked_requests"] or 0)
            sanitized_requests = int(row["sanitized_requests"] or 0)
            avg_latency_ms = float(row["avg_latency_ms"] or 0)
            avg_processing_ms = float(row["avg_processing_ms"] or 0)
            blocked_rate = (blocked_requests / total_requests) if total_requests > 0 else 0.0

            return {
                "window_hours": hours,
                "total_requests": total_requests,
                "blocked_requests": blocked_requests,
                "sanitized_requests": sanitized_requests,
                "blocked_rate": round(blocked_rate, 4),
                "avg_latency_ms": round(avg_latency_ms, 2),
                "avg_processing_ms": round(avg_processing_ms, 2),
                "last_event_at": row["last_event_at"].isoformat() if row["last_event_at"] else None,
            }

    async def top_threat_categories(
        self, *, hours: int = 24, limit: int = 8
    ) -> list[dict[str, Any]]:
        """Return top threat categories from logged threat payloads."""
        if self.pool is None:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                WITH scoped AS (
                    SELECT threats_json
                    FROM request_logs
                    WHERE created_at >= NOW() - ($1::text || ' hours')::interval
                ),
                exploded AS (
                    SELECT jsonb_array_elements(threats_json) AS threat
                    FROM scoped
                )
                SELECT
                    COALESCE(threat ->> 'category', 'unknown') AS category,
                    COUNT(*)::bigint AS count
                FROM exploded
                GROUP BY category
                ORDER BY count DESC
                LIMIT $2
                """,
                str(hours),
                limit,
            )

            return [
                {
                    "category": str(row["category"]),
                    "count": int(row["count"]),
                }
                for row in rows
            ]


class SecurityEventRepository:
    """Repository for security events."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    @property
    def enabled(self) -> bool:
        return self.pool is not None

    async def create(
        self,
        *,
        event_type: str,
        severity: str,
        details: dict[str, Any] | None = None,
        client_ip: str | None = None,
        request_log_id: str | None = None,
    ) -> str:
        """Insert a security event. Returns the event ID."""
        event_id = str(uuid.uuid4())
        if self.pool is None:
            return event_id
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO security_events (
                    id, request_log_id, event_type, severity, details, client_ip
                ) VALUES ($1, $2, $3, $4, $5, $6)
                """,
                uuid.UUID(event_id),
                uuid.UUID(request_log_id) if request_log_id else None,
                event_type,
                severity,
                json.dumps(details or {}),
                client_ip,
            )
        return event_id


class APIKeyRepository:
    """Repository for API key management."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def find_by_prefix(self, key_prefix: str) -> dict[str, Any] | None:
        """Look up an API key record by its prefix."""
        if self.pool is None:
            return None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, key_hash, key_prefix, name, user_id,
                       is_active, rate_limit_rpm, created_at,
                       last_used_at, expires_at
                FROM api_keys
                WHERE key_prefix = $1 AND is_active = TRUE
                """,
                key_prefix,
            )
            if row is None:
                return None
            return dict(row)

    async def create(
        self,
        *,
        key_hash: str,
        key_prefix: str,
        name: str,
        user_id: str | None = None,
        rate_limit_rpm: int | None = None,
    ) -> str:
        """Insert a new API key. Returns the key ID."""
        if self.pool is None:
            raise RuntimeError("Database pool is not available")
        key_id = str(uuid.uuid4())
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO api_keys (id, key_hash, key_prefix, name, user_id, rate_limit_rpm)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                uuid.UUID(key_id),
                key_hash,
                key_prefix,
                name,
                user_id,
                rate_limit_rpm,
            )
        return key_id

    async def deactivate(self, key_id: str) -> bool:
        """Deactivate an API key."""
        if self.pool is None:
            return False
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE api_keys SET is_active = FALSE WHERE id = $1",
                uuid.UUID(key_id),
            )
            return result == "UPDATE 1"
