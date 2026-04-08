"""Feedback API endpoints for learning from security decisions.

Enterprise feature: Enables continuous improvement based on user feedback.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from entropy.api.dependencies import require_auth
from entropy.learning.feedback_store import FeedbackRecord, FeedbackStore
from entropy.learning.threshold_tuner import ThresholdTuner

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/feedback", tags=["feedback"])


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------


class FeedbackRequest(BaseModel):
    """Request to submit feedback on a security decision."""

    request_log_id: int | None = Field(
        default=None,
        description="ID of the original request log entry",
    )
    pattern_name: str = Field(
        ...,
        description="The pattern that was triggered",
    )
    category: str | None = Field(
        default=None,
        description="Category of the detected threat",
    )
    threat_level: str | None = Field(
        default=None,
        description="Severity level of the threat",
    )
    was_correct: bool = Field(
        ...,
        description="Was the detection correct?",
    )
    expected_action: str | None = Field(
        default=None,
        description="What action should have been taken (allow/block/sanitize)",
    )
    reason: str | None = Field(
        default=None,
        description="Explanation for the feedback",
    )
    confidence: float | None = Field(
        default=None,
        description="Confidence score of the original detection",
    )
    original_verdict: str | None = Field(
        default=None,
        description="Original verdict (allowed/blocked/sanitized)",
    )


class FeedbackResponse(BaseModel):
    """Response after submitting feedback."""

    status: str = Field(default="recorded", description="Status of the feedback")
    feedback_id: int = Field(..., description="ID of the recorded feedback")
    message: str = Field(..., description="Human-readable message")


class PatternStatsResponse(BaseModel):
    """Statistics for a pattern."""

    pattern_name: str
    category: str | None = None
    total_feedback: int
    correct_count: int
    incorrect_count: int
    accuracy_percentage: float
    avg_confidence: float
    last_feedback_at: datetime | None = None


class ThresholdAdjustmentResponse(BaseModel):
    """Response for threshold adjustment."""

    pattern_name: str
    category: str | None = None
    original_threshold: float
    adjusted_threshold: float
    adjustment_reason: str


# ---------------------------------------------------------------------------
# Dependency Injection
# ---------------------------------------------------------------------------


def get_feedback_store(request: Request) -> FeedbackStore:
    """Get feedback store from app state."""
    return FeedbackStore(request.app.state.db_pool)


def get_threshold_tuner(request: Request) -> ThresholdTuner:
    """Get threshold tuner from app state."""
    feedback_store = get_feedback_store(request)
    return ThresholdTuner(feedback_store, request.app.state.db_pool)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=FeedbackResponse)
async def submit_feedback(
    feedback: FeedbackRequest,
    request: Request,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    feedback_store: FeedbackStore = Depends(get_feedback_store),  # noqa: B008
) -> FeedbackResponse:
    """Submit feedback on a security decision.

    This feedback is used to improve detection accuracy through
    threshold tuning and pattern refinement.

    Enterprise feature: requires database backend.
    """
    api_key_id = auth_record.get("id")

    # Create feedback record
    record = FeedbackRecord(
        request_log_id=feedback.request_log_id,
        api_key_id=api_key_id if api_key_id != "master" else None,
        pattern_name=feedback.pattern_name,
        category=feedback.category,
        threat_level=feedback.threat_level,
        was_correct=feedback.was_correct,
        expected_action=feedback.expected_action,
        reason=feedback.reason,
        confidence=feedback.confidence,
        original_verdict=feedback.original_verdict,
    )

    try:
        feedback_id = await feedback_store.save(record)

        logger.info(
            "Feedback submitted",
            feedback_id=feedback_id,
            pattern=feedback.pattern_name,
            correct=feedback.was_correct,
            api_key_id=api_key_id,
        )

        return FeedbackResponse(
            feedback_id=feedback_id,
            message=f"Feedback recorded for pattern '{feedback.pattern_name}'",
        )

    except Exception as exc:
        logger.error("Failed to save feedback", error=str(exc))
        raise HTTPException(
            status_code=500,
            detail="Failed to record feedback",
        ) from exc


@router.get("/patterns/{pattern_name}/stats", response_model=PatternStatsResponse)
async def get_pattern_stats(
    pattern_name: str,
    request: Request,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    feedback_store: FeedbackStore = Depends(get_feedback_store),  # noqa: B008
) -> PatternStatsResponse:
    """Get statistics for a specific pattern.

    Shows accuracy, feedback count, and other metrics.
    """
    stats = await feedback_store.get_pattern_stats(pattern_name)

    if not stats:
        raise HTTPException(
            status_code=404,
            detail=f"No feedback found for pattern '{pattern_name}'",
        )

    return PatternStatsResponse(
        pattern_name=stats.pattern_name,
        category=stats.category,
        total_feedback=stats.total_feedback,
        correct_count=stats.correct_count,
        incorrect_count=stats.incorrect_count,
        accuracy_percentage=stats.accuracy_percentage,
        avg_confidence=stats.avg_confidence,
        last_feedback_at=stats.last_feedback_at,
    )


@router.get("/patterns", response_model=list[PatternStatsResponse])
async def list_pattern_stats(
    request: Request,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    feedback_store: FeedbackStore = Depends(get_feedback_store),  # noqa: B008
) -> list[PatternStatsResponse]:
    """List statistics for all patterns with feedback."""
    stats_list = await feedback_store.get_all_pattern_stats()

    return [
        PatternStatsResponse(
            pattern_name=stats.pattern_name,
            category=stats.category,
            total_feedback=stats.total_feedback,
            correct_count=stats.correct_count,
            incorrect_count=stats.incorrect_count,
            accuracy_percentage=stats.accuracy_percentage,
            avg_confidence=stats.avg_confidence,
            last_feedback_at=stats.last_feedback_at,
        )
        for stats in stats_list
    ]


@router.post("/tune", response_model=list[ThresholdAdjustmentResponse])
async def tune_thresholds(
    request: Request,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    tuner: ThresholdTuner = Depends(get_threshold_tuner),  # noqa: B008
) -> list[ThresholdAdjustmentResponse]:
    """Trigger threshold tuning based on accumulated feedback.

    Analyzes feedback and adjusts thresholds for patterns that need it.
    This is an enterprise feature.

    Requires master key or admin permissions.
    """
    # Check for admin/master key
    if auth_record.get("id") == "master" or auth_record.get("is_admin"):
        adjustments = await tuner.analyze_and_adjust()

        return [
            ThresholdAdjustmentResponse(
                pattern_name=adj.pattern_name,
                category=adj.category,
                original_threshold=adj.original_threshold,
                adjusted_threshold=adj.adjusted_threshold,
                adjustment_reason=adj.adjustment_reason,
            )
            for adj in adjustments
        ]

    raise HTTPException(
        status_code=403,
        detail="Threshold tuning requires admin permissions",
    )


@router.get("/recent", response_model=list[dict[str, Any]])
async def get_recent_feedback(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    feedback_store: FeedbackStore = Depends(get_feedback_store),  # noqa: B008
) -> list[dict[str, Any]]:
    """Get recent feedback records.

    Useful for dashboards and monitoring.
    """
    records = await feedback_store.get_recent_feedback(limit=limit, offset=offset)

    return [
        {
            "id": r.id,
            "pattern_name": r.pattern_name,
            "category": r.category,
            "was_correct": r.was_correct,
            "expected_action": r.expected_action,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]


@router.get("/count")
async def get_feedback_count(
    request: Request,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    feedback_store: FeedbackStore = Depends(get_feedback_store),  # noqa: B008
) -> dict[str, int]:
    """Get total feedback count."""
    count = await feedback_store.get_feedback_count()
    return {"total_feedback": count}
