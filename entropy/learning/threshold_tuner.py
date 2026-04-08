"""Threshold tuning based on feedback analysis.

Automatically adjusts detection thresholds based on user feedback
to reduce false positives and improve detection accuracy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from entropy.learning.feedback_store import FeedbackStore

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ThresholdAdjustment:
    """A threshold adjustment for a pattern."""

    pattern_name: str
    category: str | None
    original_threshold: float
    adjusted_threshold: float
    adjustment_reason: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0


class ThresholdTuner:
    """Automatically adjusts confidence thresholds based on feedback.

    Uses the following strategy:
    1. High false positive rate (>30%) ΓåÆ decrease threshold sensitivity
    2. High accuracy (>95%) with many samples ΓåÆ increase sensitivity
    3. Avoid over-adjusting with minimum sample requirements

    Enterprise feature: requires PostgreSQL database.
    """

    # Tuning parameters
    MIN_SAMPLES_FOR_TUNING = 50  # Minimum feedback samples required
    HIGH_FP_RATE = 0.30  # Threshold for considering FP rate high
    HIGH_ACCURACY = 0.95  # Threshold for considering accuracy high
    ADJUSTMENT_STEP = 0.05  # How much to adjust thresholds
    MAX_ADJUSTMENT = 0.3  # Maximum adjustment from original
    COOLDOWN_DAYS = 7  # Days between adjustments for same pattern

    def __init__(
        self,
        feedback_store: FeedbackStore,
        db_pool: Any,
        min_samples: int = MIN_SAMPLES_FOR_TUNING,
    ) -> None:
        """Initialize the threshold tuner.

        Args:
            feedback_store: Feedback storage instance
            db_pool: Database connection pool
            min_samples: Minimum samples required for tuning
        """
        self.feedback_store = feedback_store
        self.pool = db_pool
        self.min_samples = min_samples

    async def analyze_and_adjust(self) -> list[ThresholdAdjustment]:
        """Analyze feedback and adjust thresholds for patterns that need it.

        Returns:
            List of adjustments made
        """
        adjustments = []

        # Get all pattern statistics
        all_stats = await self.feedback_store.get_all_pattern_stats()

        for stats in all_stats:
            # Skip patterns with insufficient samples
            if stats.total_feedback < self.min_samples:
                logger.debug(
                    "Skipping pattern - insufficient samples",
                    pattern=stats.pattern_name,
                    samples=stats.total_feedback,
                )
                continue

            # Check if recently adjusted
            if await self._recently_adjusted(stats.pattern_name):
                logger.debug(
                    "Skipping pattern - recently adjusted",
                    pattern=stats.pattern_name,
                )
                continue

            # Calculate false positive rate
            fp_rate = stats.incorrect_count / stats.total_feedback

            adjustment = None

            # High false positive rate - decrease sensitivity
            if fp_rate > self.HIGH_FP_RATE:
                adjustment = await self._adjust_threshold(
                    pattern_name=stats.pattern_name,
                    category=stats.category,
                    current_accuracy=100 - stats.accuracy_percentage,
                    direction="decrease",
                    reason=(
                        f"High FP rate: {fp_rate:.1%} "
                        f"({stats.incorrect_count}/{stats.total_feedback})"
                    ),
                )

            # High accuracy - can increase sensitivity
            elif stats.accuracy_percentage >= self.HIGH_ACCURACY * 100:
                adjustment = await self._adjust_threshold(
                    pattern_name=stats.pattern_name,
                    category=stats.category,
                    current_accuracy=stats.accuracy_percentage,
                    direction="increase",
                    reason=f"High accuracy: {stats.accuracy_percentage:.1f}%",
                )

            if adjustment:
                adjustments.append(adjustment)

        if adjustments:
            logger.info(
                "Threshold tuning complete",
                adjustments=len(adjustments),
                patterns=[a.pattern_name for a in adjustments],
            )

        return adjustments

    async def get_adjusted_threshold(self, pattern_name: str) -> float | None:
        """Get the adjusted threshold for a pattern.

        Args:
            pattern_name: The pattern to get threshold for

        Returns:
            Adjusted threshold or None if no adjustment exists
        """
        query = """
            SELECT adjusted_threshold
            FROM threshold_adjustments
            WHERE pattern_name = $1
        """

        async with self.pool.acquire() as conn:
            result = await conn.fetchval(query, pattern_name)
            return float(result) if result else None

    async def _adjust_threshold(
        self,
        pattern_name: str,
        category: str | None,
        current_accuracy: float,
        direction: str,
        reason: str,
    ) -> ThresholdAdjustment | None:
        """Adjust a pattern's threshold.

        Args:
            pattern_name: Pattern to adjust
            category: Pattern category
            current_accuracy: Current accuracy percentage
            direction: "increase" or "decrease"
            reason: Reason for adjustment

        Returns:
            ThresholdAdjustment if successful, None otherwise
        """
        # Get current adjustment
        current = await self._get_current_adjustment(pattern_name)

        if current:
            original_threshold = current["original_threshold"]
            current_threshold = current["adjusted_threshold"]
            tp = current["true_positives"]
            fp = current["false_positives"]
            tn = current["true_negatives"]
            fn = current["false_negatives"]
        else:
            # No adjustment exists - use defaults
            original_threshold = 0.7  # Default threshold
            current_threshold = original_threshold
            tp = fp = tn = fn = 0

        # Calculate new threshold
        if direction == "decrease":
            # Decrease threshold to reduce false positives
            # Lower threshold = more permissive = fewer FP
            new_threshold = max(
                original_threshold - self.MAX_ADJUSTMENT,
                current_threshold - self.ADJUSTMENT_STEP,
            )
        else:
            # Increase threshold to be more strict
            new_threshold = min(
                original_threshold + self.MAX_ADJUSTMENT,
                current_threshold + self.ADJUSTMENT_STEP,
            )

        # Don't adjust if change is too small
        if abs(new_threshold - current_threshold) < 0.01:
            return None

        # Save adjustment
        query = """
            INSERT INTO threshold_adjustments (
                pattern_name, category, original_threshold, adjusted_threshold,
                adjustment_reason, true_positives, false_positives,
                true_negatives, false_negatives
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (pattern_name) DO UPDATE SET
                adjusted_threshold = EXCLUDED.adjusted_threshold,
                adjustment_reason = EXCLUDED.adjustment_reason,
                true_positives = EXCLUDED.true_positives,
                false_positives = EXCLUDED.false_positives,
                true_negatives = EXCLUDED.true_negatives,
                false_negatives = EXCLUDED.false_negatives,
                updated_at = CURRENT_TIMESTAMP
        """

        async with self.pool.acquire() as conn:
            await conn.execute(
                query,
                pattern_name,
                category,
                original_threshold,
                new_threshold,
                reason,
                tp,
                fp,
                tn,
                fn,
            )

        logger.info(
            "Threshold adjusted",
            pattern=pattern_name,
            old_threshold=current_threshold,
            new_threshold=new_threshold,
            reason=reason,
        )

        return ThresholdAdjustment(
            pattern_name=pattern_name,
            category=category,
            original_threshold=original_threshold,
            adjusted_threshold=new_threshold,
            adjustment_reason=reason,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
        )

    async def _get_current_adjustment(
        self,
        pattern_name: str,
    ) -> dict[str, Any] | None:
        """Get current threshold adjustment for a pattern."""
        query = """
            SELECT
                original_threshold,
                adjusted_threshold,
                true_positives,
                false_positives,
                true_negatives,
                false_negatives
            FROM threshold_adjustments
            WHERE pattern_name = $1
        """

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(query, pattern_name)
            if row:
                return dict(row)
        return None

    async def _recently_adjusted(self, pattern_name: str) -> bool:
        """Check if a pattern was recently adjusted.

        Args:
            pattern_name: Pattern to check

        Returns:
            True if adjusted within cooldown period
        """
        query = """
            SELECT updated_at
            FROM threshold_adjustments
            WHERE pattern_name = $1
        """

        async with self.pool.acquire() as conn:
            result = await conn.fetchval(query, pattern_name)

            if result:
                # Check if within cooldown period
                return result > datetime.utcnow() - timedelta(days=self.COOLDOWN_DAYS)

        return False

    async def reset_adjustments(self) -> int:
        """Reset all threshold adjustments to original values.

        Returns:
            Number of adjustments reset
        """
        query = "DELETE FROM threshold_adjustments RETURNING id"

        async with self.pool.acquire() as conn:
            results = await conn.fetch(query)
            count = len(results)

        logger.info("Reset all threshold adjustments", count=count)
        return count


__all__ = ["ThresholdAdjustment", "ThresholdTuner"]
