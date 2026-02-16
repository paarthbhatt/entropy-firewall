"""Security Logger — structured security event logging.

Wraps structlog to provide a consistent API for audit-trail entries.
Optionally writes to PostgreSQL via the SecurityEventRepository.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog

from entropy.db.repository import SecurityEventRepository

logger = structlog.get_logger("entropy.security")


class SecurityLogger:
    """High-level security event logger."""

    def __init__(self, repo: Optional[SecurityEventRepository] = None) -> None:
        self.repo = repo

    async def log_attack_blocked(
        self,
        *,
        client_ip: str,
        threats: list[dict[str, Any]],
        confidence: float,
        request_log_id: Optional[str] = None,
    ) -> None:
        """Log a blocked attack."""
        logger.warning(
            "ATTACK BLOCKED",
            client_ip=client_ip,
            confidence=confidence,
            threat_count=len(threats),
            threats=threats[:5],
        )
        if self.repo:
            await self.repo.create(
                event_type="attack_blocked",
                severity="high",
                details={"confidence": confidence, "threats": threats[:10]},
                client_ip=client_ip,
                request_log_id=request_log_id,
            )

    async def log_rate_limited(
        self,
        *,
        client_ip: str,
        exceeded: list[str],
        request_log_id: Optional[str] = None,
    ) -> None:
        """Log a rate-limit violation."""
        logger.warning(
            "RATE LIMITED",
            client_ip=client_ip,
            exceeded=exceeded,
        )
        if self.repo:
            await self.repo.create(
                event_type="rate_limited",
                severity="medium",
                details={"exceeded": exceeded},
                client_ip=client_ip,
                request_log_id=request_log_id,
            )

    async def log_pii_detected(
        self,
        *,
        client_ip: str,
        detections: list[dict[str, Any]],
        direction: str = "output",
        request_log_id: Optional[str] = None,
    ) -> None:
        """Log PII/secret detection in output."""
        logger.info(
            "PII/SECRET DETECTED",
            client_ip=client_ip,
            direction=direction,
            rules_triggered=len(detections),
        )
        if self.repo:
            await self.repo.create(
                event_type="pii_detected",
                severity="low",
                details={"direction": direction, "detections": detections},
                client_ip=client_ip,
                request_log_id=request_log_id,
            )

    async def log_request(
        self,
        *,
        client_ip: str,
        status: str,
        processing_ms: float,
        model: Optional[str] = None,
    ) -> None:
        """Log a normal request (for audit trailing)."""
        logger.info(
            "REQUEST",
            client_ip=client_ip,
            status=status,
            processing_ms=processing_ms,
            model=model,
        )
