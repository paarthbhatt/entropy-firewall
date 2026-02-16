"""Data access layer for Entropy."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Optional

import asyncpg
import structlog

logger = structlog.get_logger(__name__)


class RequestLogRepository:
    """Repository for request audit logs."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def create(
        self,
        *,
        api_key_id: Optional[str] = None,
        client_ip: str,
        provider: str = "openai",
        model: Optional[str] = None,
        message_count: int = 0,
        input_tokens: int = 0,
        status: str = "allowed",
        threat_level: Optional[str] = None,
        confidence: Optional[float] = None,
        threats: Optional[list[dict[str, Any]]] = None,
        output_tokens: int = 0,
        output_sanitized: bool = False,
        sanitizations: Optional[list[dict[str, Any]]] = None,
        processing_ms: float = 0.0,
        provider_ms: float = 0.0,
        total_ms: float = 0.0,
    ) -> str:
        """Insert a request log entry. Returns the log ID."""
        log_id = str(uuid.uuid4())
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


class SecurityEventRepository:
    """Repository for security events."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def create(
        self,
        *,
        event_type: str,
        severity: str,
        details: Optional[dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        request_log_id: Optional[str] = None,
    ) -> str:
        """Insert a security event. Returns the event ID."""
        event_id = str(uuid.uuid4())
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

    async def find_by_prefix(self, key_prefix: str) -> Optional[dict[str, Any]]:
        """Look up an API key record by its prefix."""
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
        user_id: Optional[str] = None,
        rate_limit_rpm: Optional[int] = None,
    ) -> str:
        """Insert a new API key. Returns the key ID."""
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
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE api_keys SET is_active = FALSE WHERE id = $1",
                uuid.UUID(key_id),
            )
            return result == "UPDATE 1"
