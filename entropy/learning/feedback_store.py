"""Feedback storage for learning from security decisions.

Provides PostgreSQL-backed storage for user feedback on security
decisions and pattern performance metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class FeedbackRecord:
    """A feedback record on a security decision."""

    id: int | None = None
    request_log_id: int | None = None
    api_key_id: int | None = None
    pattern_name: str | None = None
    category: str | None = None
    threat_level: str | None = None
    was_correct: bool = False
    expected_action: str | None = None
    reason: str | None = None
    confidence: float | None = None
    original_verdict: str | None = None
    created_at: datetime | None = None


@dataclass
class PatternStats:
    """Statistics for a pattern."""

    pattern_name: str
    category: str | None = None
    total_feedback: int = 0
    correct_count: int = 0
    incorrect_count: int = 0
    accuracy_percentage: float = 0.0
    avg_confidence: float = 0.0
    last_feedback_at: datetime | None = None


class FeedbackStore:
    """PostgreSQL-backed storage for feedback data.

    Stores user feedback on security decisions and provides
    queries for pattern performance analysis.
    """

    def __init__(self, db_pool: Any) -> None:
        """Initialize with database connection pool.

        Args:
            db_pool: asyncpg connection pool
        """
        self.pool = db_pool

    async def save(self, feedback: FeedbackRecord) -> int:
        """Save a feedback record.

        Args:
            feedback: The feedback record to save

        Returns:
            The ID of the inserted record
        """
        query = """
            INSERT INTO feedback (
                request_log_id, api_key_id, pattern_name, category,
                threat_level, was_correct, expected_action, reason,
                confidence, original_verdict
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
        """

        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                query,
                feedback.request_log_id,
                feedback.api_key_id,
                feedback.pattern_name,
                feedback.category,
                feedback.threat_level,
                feedback.was_correct,
                feedback.expected_action,
                feedback.reason,
                feedback.confidence,
                feedback.original_verdict,
            )

            logger.info(
                "Feedback saved",
                feedback_id=result,
                pattern=feedback.pattern_name,
                correct=feedback.was_correct,
            )

            return result

    async def get_pattern_stats(self, pattern_name: str) -> PatternStats | None:
        """Get statistics for a specific pattern.

        Args:
            pattern_name: The pattern to get stats for

        Returns:
            PatternStats or None if no feedback exists
        """
        query = """
            SELECT
                pattern_name,
                category,
                total_feedback,
                correct_count,
                incorrect_count,
                accuracy_percentage,
                avg_confidence,
                last_feedback_at
            FROM pattern_performance
            WHERE pattern_name = $1
        """

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(query, pattern_name)

            if row:
                return PatternStats(
                    pattern_name=row["pattern_name"],
                    category=row["category"],
                    total_feedback=row["total_feedback"],
                    correct_count=row["correct_count"],
                    incorrect_count=row["incorrect_count"],
                    accuracy_percentage=float(row["accuracy_percentage"] or 0),
                    avg_confidence=float(row["avg_confidence"] or 0),
                    last_feedback_at=row["last_feedback_at"],
                )

        return None

    async def get_all_pattern_stats(self) -> list[PatternStats]:
        """Get statistics for all patterns with feedback.

        Returns:
            List of PatternStats
        """
        query = """
            SELECT
                pattern_name,
                category,
                total_feedback,
                correct_count,
                incorrect_count,
                accuracy_percentage,
                avg_confidence,
                last_feedback_at
            FROM pattern_performance
            ORDER BY total_feedback DESC
        """

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query)

            return [
                PatternStats(
                    pattern_name=row["pattern_name"],
                    category=row["category"],
                    total_feedback=row["total_feedback"],
                    correct_count=row["correct_count"],
                    incorrect_count=row["incorrect_count"],
                    accuracy_percentage=float(row["accuracy_percentage"] or 0),
                    avg_confidence=float(row["avg_confidence"] or 0),
                    last_feedback_at=row["last_feedback_at"],
                )
                for row in rows
            ]

    async def get_recent_feedback(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FeedbackRecord]:
        """Get recent feedback records.

        Args:
            limit: Maximum records to return
            offset: Offset for pagination

        Returns:
            List of FeedbackRecord
        """
        query = """
            SELECT * FROM recent_feedback
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        """

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, limit, offset)

            return [
                FeedbackRecord(
                    id=row["id"],
                    request_log_id=row["request_log_id"],
                    api_key_id=row["api_key_id"],
                    pattern_name=row["pattern_name"],
                    category=row["category"],
                    threat_level=row["threat_level"],
                    was_correct=row["was_correct"],
                    expected_action=row["expected_action"],
                    reason=row["reason"],
                    confidence=row["confidence"],
                    original_verdict=row["original_verdict"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    async def get_feedback_count(self) -> int:
        """Get total feedback count.

        Returns:
            Total number of feedback records
        """
        query = "SELECT COUNT(*) FROM feedback"

        async with self.pool.acquire() as conn:
            return await conn.fetchval(query)

    async def mark_reviewed(
        self,
        feedback_id: int,
        reviewed_by: str,
    ) -> bool:
        """Mark a feedback record as reviewed.

        Args:
            feedback_id: The feedback record ID
            reviewed_by: Who reviewed it

        Returns:
            True if updated successfully
        """
        query = """
            UPDATE feedback
            SET reviewed_at = CURRENT_TIMESTAMP,
                reviewed_by = $2
            WHERE id = $1
        """

        async with self.pool.acquire() as conn:
            result = await conn.execute(query, feedback_id, reviewed_by)
            return "UPDATE 1" in result


__all__ = ["FeedbackRecord", "FeedbackStore", "PatternStats"]
