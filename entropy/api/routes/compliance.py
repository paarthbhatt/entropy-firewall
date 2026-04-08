"""Entropy Compliance API routes.

Provides endpoints for:
- Violation feed (blocked/critical requests from audit log)
- Compliance stats for dashboard charts
- Manual overrides (maps to feedback learning loop)
- AI-powered policy-to-guardrails generation
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel

from entropy.api.dependencies import require_auth

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/compliance", tags=["compliance"])


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------


class ViolationRecord(BaseModel):
    violation_id: str
    request_log_id: str
    threat_level: str
    threats: list[str]
    client_ip: str
    model: str | None = None
    provider: str
    created_at: str
    status: str = "active"


class ComplianceStats(BaseModel):
    total_requests: int
    blocked: int
    sanitized: int
    allowed: int
    health_score: float
    violations_by_threat: dict[str, int]


class OverrideRequest(BaseModel):
    request_log_id: str
    action: str  # FALSE_POSITIVE | LEGAL_HOLD | DPO_EXCEPTION | REMEDIATION_IN_PROGRESS
    reason: str
    reviewer_name: str | None = "Compliance Officer"
    regulation_context: str | None = None


class GuardrailsResponse(BaseModel):
    rules_extracted: int
    rules: list[dict[str, Any]]
    guardrails_yaml: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_db(request: Request) -> Any:
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not available — compliance features require PostgreSQL.",
        )
    return pool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/violations",
    response_model=list[ViolationRecord],
    summary="Live violation feed",
    description=(
        "Returns blocked and critical requests from the audit log, "
        "formatted as compliance violations."
    ),
)
async def list_violations(
    request: Request,
    limit: int = 50,
    threat_level: str | None = None,
    _auth: dict[str, Any] = Depends(require_auth),  # noqa: B008
) -> list[ViolationRecord]:
    pool = _get_db(request)

    query = """
        SELECT
            id::text              AS request_log_id,
            threat_level,
            threats_json          AS threats,
            client_ip::text       AS client_ip,
            model,
            provider,
            created_at::text      AS created_at
        FROM request_logs
        WHERE status = 'blocked'
    """
    params: list[Any] = []

    if threat_level:
        query += " AND threat_level = $1"
        params.append(threat_level)

    query += f" ORDER BY created_at DESC LIMIT ${len(params) + 1}"
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    violations = []
    for idx, row in enumerate(rows):
        import json as _json  # noqa: PLC0415

        threats_raw = row["threats"]
        if isinstance(threats_raw, str):
            threats_raw = _json.loads(threats_raw)
        violations.append(
            ViolationRecord(
                violation_id=f"VIO-{row['created_at'][:10].replace('-', '')}-{idx:04d}",
                request_log_id=row["request_log_id"],
                threat_level=row["threat_level"] or "unknown",
                threats=[
                    t.get("type", t) if isinstance(t, dict) else str(t) for t in (threats_raw or [])
                ],
                client_ip=row["client_ip"],
                model=row["model"],
                provider=row["provider"],
                created_at=row["created_at"],
            )
        )
    return violations


@router.get(
    "/stats",
    response_model=ComplianceStats,
    summary="Compliance health metrics",
    description="Aggregated statistics for the compliance dashboard charts.",
)
async def get_compliance_stats(
    request: Request,
    _auth: dict[str, Any] = Depends(require_auth),  # noqa: B008
) -> ComplianceStats:
    pool = _get_db(request)

    async with pool.acquire() as conn:
        totals = await conn.fetchrow("""
            SELECT
                COUNT(*)                                           AS total,
                COUNT(*) FILTER (WHERE status = 'blocked')        AS blocked,
                COUNT(*) FILTER (WHERE status = 'sanitized')      AS sanitized,
                COUNT(*) FILTER (WHERE status = 'allowed')        AS allowed
            FROM request_logs
        """)

        by_threat = await conn.fetch("""
            SELECT threat_level, COUNT(*) AS cnt
            FROM request_logs
            WHERE status = 'blocked' AND threat_level IS NOT NULL
            GROUP BY threat_level
        """)

    total = totals["total"] or 1
    blocked = totals["blocked"] or 0
    # Weighted health score: critical=4x, high=3x, medium=2x, low=1x
    threat_counts: dict[str, int] = {r["threat_level"]: r["cnt"] for r in by_threat}
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    weighted_violations = sum(threat_counts.get(t, 0) * w for t, w in weights.items())
    # Normalize: 0 = all blocked, 100 = all allowed
    health = max(0.0, round((1 - (weighted_violations / (total * 4))) * 100, 1))

    return ComplianceStats(
        total_requests=total,
        blocked=blocked,
        sanitized=totals["sanitized"] or 0,
        allowed=totals["allowed"] or 0,
        health_score=health,
        violations_by_threat=threat_counts,
    )


@router.post(
    "/override",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Submit manual override decision",
    description=(
        "Compliance officer override. FALSE_POSITIVE actions automatically "
        "feed into the learning loop to improve future detection accuracy."
    ),
)
async def submit_override(
    body: OverrideRequest,
    request: Request,
    _auth: dict[str, Any] = Depends(require_auth),  # noqa: B008
) -> None:
    pool = _get_db(request)

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO compliance_overrides
                (request_log_id, reviewer_name, action, reason, regulation_context)
            VALUES ($1::uuid, $2, $3, $4, $5)
            """,
            body.request_log_id,
            body.reviewer_name,
            body.action,
            body.reason,
            body.regulation_context,
        )

    # For false positives, cascade to the feedback learning loop
    if body.action == "FALSE_POSITIVE":
        feedback_store = getattr(request.app.state, "feedback_store", None)
        if feedback_store:
            try:
                from entropy.learning.feedback_store import FeedbackRecord  # noqa: PLC0415

                record = FeedbackRecord(
                    request_log_id=int(body.request_log_id)
                    if body.request_log_id.isdigit()
                    else None,
                    was_correct=False,
                    reason=f"Compliance override: {body.reason}",
                )
                await feedback_store.save(record)
                logger.info(
                    "False positive override cascaded to learning loop",
                    request_log_id=body.request_log_id,
                )
            except Exception as exc:
                logger.warning("Could not cascade override to feedback store", error=str(exc))

    logger.info(
        "Compliance override recorded",
        action=body.action,
        request_log_id=body.request_log_id,
        reviewer=body.reviewer_name,
    )


@router.post(
    "/generate-guardrails",
    response_model=GuardrailsResponse,
    summary="AI Policy-to-Guardrails Generator",
    description=(
        "Upload a privacy policy PDF. Entropy parses it with AI and returns a "
        "ready-to-use entropy.yaml guardrails configuration file."
    ),
)
async def generate_guardrails(
    request: Request,
    file: UploadFile = File(..., description="Policy PDF (max 50MB)"),  # noqa: B008
    model: str = Form(default="gpt-4o-mini"),
    _auth: dict[str, Any] = Depends(require_auth),  # noqa: B008
) -> GuardrailsResponse:
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only PDF files are accepted.",
        )

    # Read PDF content (basic text extraction without heavy deps)
    raw_bytes = await file.read()
    if len(raw_bytes) > 50 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="PDF exceeds 50MB limit.",
        )

    document_text = _extract_pdf_text(raw_bytes)

    # Get the policy parser (requires provider registry)
    try:
        from entropy.compliance.policy_parser import PolicyParser  # noqa: PLC0415
        from entropy.providers.registry import get_registry  # noqa: PLC0415

        parser = PolicyParser(get_registry())
        rules, yaml_output = await parser.generate_guardrails_yaml(
            document_text=document_text,
            source_filename=file.filename,
            model=model,
        )
    except Exception as exc:
        logger.error("Guardrails generation failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy parsing failed: {exc}",
        ) from exc

    return GuardrailsResponse(
        rules_extracted=len(rules),
        rules=rules,
        guardrails_yaml=yaml_output,
    )


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Extract raw text from a PDF. Uses pypdf if available, falls back to raw decode."""
    try:
        import io as _io  # noqa: PLC0415

        from pypdf import PdfReader  # type: ignore[import-not-found]  # noqa: PLC0415

        reader = PdfReader(_io.BytesIO(pdf_bytes))
        pages = [p.extract_text() or "" for p in reader.pages]
        return "\n\n".join(pages)
    except ImportError:
        # Fallback: decode bytes loosely (catches many text-layer PDFs)
        return pdf_bytes.decode("latin-1", errors="replace")
