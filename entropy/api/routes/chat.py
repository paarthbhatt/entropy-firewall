"""Chat completions route — the main proxy endpoint.

This is where the full Entropy pipeline runs:
1. Auth  →  2. Rate-limit  →  3. Validate  →  4. Detect  →
5. Forward to provider  →  6. Filter output  →  7. Log  →  8. Return
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from entropy.api.dependencies import (
    get_engine,
    get_provider,
    get_rate_limiter,
    get_request_log_repo,
    get_security_logger,
    require_auth,
)
from entropy.core.engine import EntropyEngine  # noqa: TC001
from entropy.db.repository import RequestLogRepository  # noqa: TC001
from entropy.dlp.streaming_output_filter import SSEStreamingFilter
from entropy.models.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    EntropyStatus,
    EntropyVerdict,
    ErrorResponse,
    ModelInfo,
    ModelListResponse,
    ThreatLevel,
)
from entropy.providers.base import BaseProvider  # noqa: TC001
from entropy.providers.registry import get_circuit_breaker
from entropy.services.metrics import (
    ANALYSIS_DURATION,
    OUTPUT_SANITIZATIONS,
    REQUESTS_TOTAL,
    THREATS_DETECTED,
)
from entropy.services.rate_limiter import RateLimitService  # noqa: TC001
from entropy.services.security_logger import SecurityLogger  # noqa: TC001

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["chat"])

_THREAT_SEVERITY_ORDER = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def provider_label(provider: Any) -> str:
    """Return the provider name for metrics/logs (never hardcoded)."""
    return getattr(provider, "name", None) or "openai"


def top_threat_level(verdict: EntropyVerdict) -> str:
    """Return the highest threat level in a verdict as a string."""
    if not verdict.threats_detected:
        return ThreatLevel.SAFE.value
    return max(
        (t.threat_level for t in verdict.threats_detected),
        key=lambda level: _THREAT_SEVERITY_ORDER.get(level.value, 0),
        default=ThreatLevel.SAFE,
    ).value


def rate_limit_headers(rl_info: dict[str, Any]) -> dict[str, str]:
    """Build ``X-RateLimit-*`` headers from the most specific tier checked."""
    checks = rl_info.get("checks", {})
    for tier in ("user", "ip", "global"):
        info = checks.get(tier)
        if isinstance(info, dict):
            return {
                "X-RateLimit-Limit": str(info.get("limit", "")),
                "X-RateLimit-Remaining": str(info.get("remaining", "")),
                "X-RateLimit-Reset": str(info.get("reset_after_seconds", "")),
            }
    return {}


async def write_audit_log(
    log_repo: RequestLogRepository,
    *,
    api_key_id: str,
    client_ip: str,
    provider_name: str,
    model: str,
    message_count: int,
    verdict: EntropyVerdict,
    analysis_ms: float,
    provider_ms: float,
    total_ms: float,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    output_sanitized: bool = False,
    sanitizations: list[dict[str, Any]] | None = None,
) -> None:
    """Persist an audit record; never fails the request on DB errors."""
    try:
        await log_repo.create(
            api_key_id=api_key_id if api_key_id != "master" else None,
            client_ip=client_ip,
            provider=provider_name,
            model=model,
            message_count=message_count,
            input_tokens=prompt_tokens,
            status=verdict.status.value,
            threat_level=top_threat_level(verdict),
            confidence=verdict.confidence,
            threats=[t.model_dump() for t in verdict.threats_detected],
            output_tokens=completion_tokens,
            output_sanitized=output_sanitized,
            sanitizations=sanitizations or [],
            processing_ms=analysis_ms,
            provider_ms=provider_ms,
            total_ms=total_ms,
        )
    except Exception as exc:
        # Don't fail the request if logging fails
        logger.error("Failed to write audit log", error=str(exc))


@router.get("/v1/models", response_model=ModelListResponse)
async def list_models() -> ModelListResponse:
    """List available models (OpenAI compatible)."""
    return ModelListResponse(
        data=[
            ModelInfo(id="entropy-firewall-3.5", created=int(time.time())),
            ModelInfo(id="gpt-3.5-turbo", created=int(time.time())),
            ModelInfo(id="gpt-4", created=int(time.time())),
        ]
    )


@router.post("/v1/completions")
async def legacy_completions() -> Response:
    """Redirect legacy completions to chat completions."""
    return Response(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Location": "/v1/chat/completions"},
    )


@router.post("/v1/analyze", response_model=EntropyVerdict)
async def analyze_content(
    request: Request,
    body: dict[str, Any],
    engine: EntropyEngine = Depends(get_engine),  # noqa: B008
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
) -> EntropyVerdict:
    """Standalone content analysis endpoint."""
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Text field is required")

    fake_request = ChatCompletionRequest(  # type: ignore[call-arg]
        model="analyze-only",
        messages=[ChatMessage(role="user", content=text)],
    )
    history = body.get("history", [])

    return await engine.analyze_request(fake_request, conversation_history=history)


@router.post(
    "/v1/chat/completions",
    response_model=ChatCompletionResponse,
    responses={
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        403: {"model": ErrorResponse, "description": "Request blocked by Entropy"},
    },
)
async def chat_completions(  # noqa: PLR0912, PLR0915
    body: ChatCompletionRequest,
    request: Request,
    response: Response,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    engine: EntropyEngine = Depends(get_engine),  # noqa: B008
    provider: BaseProvider = Depends(get_provider),  # noqa: B008
    rate_limiter: RateLimitService = Depends(get_rate_limiter),  # noqa: B008
    log_repo: RequestLogRepository = Depends(get_request_log_repo),  # noqa: B008
    sec_logger: SecurityLogger = Depends(get_security_logger),  # noqa: B008
) -> Any:
    """OpenAI-compatible chat completion endpoint with Entropy security."""
    total_start = time.perf_counter()
    client_ip = request.client.host if request.client else "unknown"
    api_key_id = str(auth_record.get("id", ""))
    provider_name = provider_label(provider)

    # ---- 1. Rate limiting --------------------------------------------------
    allowed, rl_info = await rate_limiter.check(
        api_key_id=api_key_id,
        client_ip=client_ip,
        per_key_rpm=auth_record.get("rate_limit_rpm"),
    )
    for header, value in rate_limit_headers(rl_info).items():
        response.headers[header] = value
    if not allowed:
        REQUESTS_TOTAL.labels(status="rate_limited", provider="none").inc()
        await sec_logger.log_rate_limited(
            client_ip=client_ip,
            exceeded=rl_info.get("exceeded", []),
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=ErrorResponse(
                error="Rate limit exceeded",
                detail=f"Exceeded: {rl_info.get('exceeded', [])}",
            ).model_dump(),
            headers={
                "Retry-After": str(
                    rl_info.get("checks", {}).get("ip", {}).get("reset_after_seconds", 60)
                ),
                **rate_limit_headers(rl_info),
            },
        )

    # ---- 2. Security analysis -----------------------------------------------
    analysis_start = time.perf_counter()
    # Now async!
    verdict: EntropyVerdict = await engine.analyze_request(body)
    analysis_ms = round((time.perf_counter() - analysis_start) * 1000, 2)
    ANALYSIS_DURATION.observe(analysis_ms)

    # Record detected threats in metrics
    for threat in verdict.threats_detected:
        THREATS_DETECTED.labels(
            category=threat.category,
            threat_level=threat.threat_level.value,
        ).inc()

    if verdict.status == EntropyStatus.BLOCKED:
        REQUESTS_TOTAL.labels(status="blocked", provider="none").inc()
        try:
            await sec_logger.log_attack_blocked(
                client_ip=client_ip,
                threats=[t.model_dump() for t in verdict.threats_detected],
                confidence=verdict.confidence,
            )
        except Exception as exc:
            logger.warning("Failed to log attack blocked", error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=ErrorResponse(
                error="Request blocked by Entropy security analysis",
                detail=f"Detected {len(verdict.threats_detected)} threat(s) "
                f"with confidence {verdict.confidence:.2f}",
                entropy=verdict,
                action_suggestion=verdict.suggestion,
            ).model_dump(),
        )

    # ---- 3. Forward to LLM provider -----------------------------------------
    messages_dicts = [m.model_dump(exclude_none=True) for m in body.messages]
    extra_kwargs: dict[str, Any] = {}
    for k in (
        "temperature",
        "max_tokens",
        "top_p",
        "presence_penalty",
        "frequency_penalty",
        "stop",
        "user",
    ):
        val = getattr(body, k, None)
        if val is not None:
            extra_kwargs[k] = val

    # Circuit breaker — fail fast when the upstream provider is down
    breaker = get_circuit_breaker(provider_name)
    if not breaker.allow():
        logger.warning("Circuit breaker open — rejecting request", provider=provider_name)
        REQUESTS_TOTAL.labels(status="error", provider=provider_name).inc()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Upstream provider temporarily unavailable, please retry shortly",
        )

    # Streaming Logic — filtered through the sliding-window SSE DLP filter
    # so streaming responses get the same PII/secret redaction as
    # non-streaming ones, plus a post-stream audit record.
    if body.stream:

        async def secure_stream() -> AsyncGenerator[str, None]:
            engine_output_filter = getattr(engine, "output_filter", None)
            sse_filter = SSEStreamingFilter(
                enable_pii=getattr(engine_output_filter, "enable_pii", True),
                enable_code=getattr(engine_output_filter, "enable_code", True),
            )
            try:
                stream_iter = provider.chat_completion_stream(
                    model=body.model,
                    messages=messages_dicts,
                    **extra_kwargs,
                )
                async for chunk in sse_filter.process_sse_stream(stream_iter):
                    yield chunk
                breaker.record_success()
            except Exception as exc:
                breaker.record_failure()
                logger.error("Streaming provider call failed", error=str(exc))
                yield 'data: {"error": "Upstream provider error"}\n\n'
                yield "data: [DONE]\n\n"

            # Post-stream bookkeeping: metrics, security log, audit trail
            summary = sse_filter.output_filter.get_summary()
            stream_sanitized = summary["total_redactions"] > 0
            for detection in sse_filter.output_filter.total_detections:
                OUTPUT_SANITIZATIONS.labels(rule=detection.get("rule", "unknown")).inc()
            REQUESTS_TOTAL.labels(status="allowed", provider=provider_name).inc()
            if stream_sanitized:
                try:
                    await sec_logger.log_pii_detected(
                        client_ip=client_ip,
                        detections=sse_filter.output_filter.total_detections,
                    )
                except Exception as exc:
                    logger.warning("Failed to log streaming PII event", error=str(exc))
            await write_audit_log(
                log_repo,
                api_key_id=api_key_id,
                client_ip=client_ip,
                provider_name=provider_name,
                model=body.model,
                message_count=len(body.messages),
                verdict=verdict,
                analysis_ms=analysis_ms,
                provider_ms=0.0,
                total_ms=round((time.perf_counter() - total_start) * 1000, 2),
                output_sanitized=stream_sanitized,
                sanitizations=sse_filter.output_filter.total_detections,
            )

        return StreamingResponse(
            secure_stream(),
            media_type="text/event-stream",
            headers=rate_limit_headers(rl_info),
        )

    # Non-streaming
    provider_start = time.perf_counter()
    try:
        raw_response = await provider.chat_completion(
            model=body.model,
            messages=messages_dicts,
            **extra_kwargs,
        )
        breaker.record_success()
    except Exception as exc:
        breaker.record_failure()
        # Log the full error server-side; return a generic message so
        # upstream hostnames, key fragments, or tracebacks never leak.
        logger.error("Provider call failed", provider=provider_name, error=str(exc))
        REQUESTS_TOTAL.labels(status="error", provider=provider_name).inc()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream provider error",
        ) from exc
    provider_ms = round((time.perf_counter() - provider_start) * 1000, 2)

    # ---- 4. Output filtering ------------------------------------------------
    output_sanitized = False
    sanitization_detections: list[dict[str, Any]] = []

    # OpenAI format: choices[0].message.content
    choices = raw_response.get("choices", [])
    for choice in choices:
        # Some providers return message object, others might differ slightly
        # We assume OAI format here
        msg = choice.get("message", {})
        content = msg.get("content", "")
        if content and isinstance(content, str):
            filtered, detections, _ = engine.analyze_output(content)
            if detections:
                msg["content"] = filtered
                output_sanitized = True

                # Convert detections to list of dicts if they aren't already
                det_list = [d.model_dump() if hasattr(d, "model_dump") else d for d in detections]
                sanitization_detections.extend(det_list)

                # Log metrics
                for d in det_list:
                    rule_name = d.get("rule", "unknown") if isinstance(d, dict) else "unknown"
                    OUTPUT_SANITIZATIONS.labels(rule=rule_name).inc()

                await sec_logger.log_pii_detected(
                    client_ip=client_ip,
                    detections=det_list,
                )

    # ---- 5. Attach Entropy verdict ------------------------------------------
    verdict.output_sanitized = output_sanitized
    # We inject the entropy verdict into the response object
    # OAI clients usually ignore extra fields, but our SDK will read it
    raw_response["entropy"] = verdict.model_dump()

    # ---- 6. Audit log -------------------------------------------------------
    total_ms = round((time.perf_counter() - total_start) * 1000, 2)
    REQUESTS_TOTAL.labels(status="allowed", provider=provider_name).inc()

    # Calculate tokens if not provided
    prompt_tokens = raw_response.get("usage", {}).get("prompt_tokens", 0)
    completion_tokens = raw_response.get("usage", {}).get("completion_tokens", 0)

    await write_audit_log(
        log_repo,
        api_key_id=api_key_id,
        client_ip=client_ip,
        provider_name=provider_name,
        model=body.model,
        message_count=len(body.messages),
        verdict=verdict,
        analysis_ms=analysis_ms,
        provider_ms=provider_ms,
        total_ms=total_ms,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        output_sanitized=output_sanitized,
        sanitizations=sanitization_detections,
    )

    return raw_response


@router.get("/v1/telemetry/summary")
async def telemetry_summary(
    hours: int = 24,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    log_repo: RequestLogRepository = Depends(get_request_log_repo),  # noqa: B008
) -> dict[str, Any]:
    """Authenticated summary endpoint for website/dashboard consumption."""
    if hours < 1 or hours > 24 * 30:
        raise HTTPException(status_code=400, detail="hours must be between 1 and 720")
    summary = await log_repo.dashboard_summary(hours=hours)
    return {
        "status": "ok",
        "entropy": summary,
    }


@router.get("/v1/telemetry/threats")
async def telemetry_threats(
    hours: int = 24,
    limit: int = 8,
    auth_record: dict[str, Any] = Depends(require_auth),  # noqa: B008
    log_repo: RequestLogRepository = Depends(get_request_log_repo),  # noqa: B008
) -> dict[str, Any]:
    """Authenticated top-threat endpoint for website/dashboard consumption."""
    if hours < 1 or hours > 24 * 30:
        raise HTTPException(status_code=400, detail="hours must be between 1 and 720")
    if limit < 1 or limit > 25:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 25")
    items = await log_repo.top_threat_categories(hours=hours, limit=limit)
    return {
        "status": "ok",
        "window_hours": hours,
        "items": items,
    }
