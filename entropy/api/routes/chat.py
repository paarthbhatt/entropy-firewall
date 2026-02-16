"""Chat completions route — the main proxy endpoint.

This is where the full Entropy pipeline runs:
1. Auth  →  2. Rate-limit  →  3. Validate  →  4. Detect  →
5. Forward to provider  →  6. Filter output  →  7. Log  →  8. Return
"""

from __future__ import annotations

import time
import json
from typing import Any, AsyncGenerator

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
from entropy.core.engine import EntropyEngine
from entropy.db.repository import RequestLogRepository
from entropy.models.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionChunk,
    EntropyStatus,
    EntropyVerdict,
    ErrorResponse,
    ThreatLevel,
    ModelListResponse,
    ModelInfo,
)
from entropy.providers.openai_provider import OpenAIProvider
from entropy.services.metrics import (
    ANALYSIS_DURATION,
    OUTPUT_SANITIZATIONS,
    REQUESTS_TOTAL,
    THREATS_DETECTED,
)
from entropy.services.rate_limiter import RateLimitService
from entropy.services.security_logger import SecurityLogger

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["chat"])


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
    engine: EntropyEngine = Depends(get_engine),
    auth_record: dict[str, Any] = Depends(require_auth),
) -> EntropyVerdict:
    """Standalone content analysis endpoint."""
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Text field is required")
        
    fake_request = ChatCompletionRequest(
        model="analyze-only",
        messages=[{"role": "user", "content": text}]
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
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    auth_record: dict[str, Any] = Depends(require_auth),
    engine: EntropyEngine = Depends(get_engine),
    provider: OpenAIProvider = Depends(get_provider),
    rate_limiter: RateLimitService = Depends(get_rate_limiter),
    log_repo: RequestLogRepository = Depends(get_request_log_repo),
    sec_logger: SecurityLogger = Depends(get_security_logger),
) -> Any:
    """OpenAI-compatible chat completion endpoint with Entropy security."""
    total_start = time.perf_counter()
    client_ip = request.client.host if request.client else "unknown"
    api_key_id = str(auth_record.get("id", ""))

    # ---- 1. Rate limiting --------------------------------------------------
    allowed, rl_info = await rate_limiter.check(
        api_key_id=api_key_id,
        client_ip=client_ip,
    )
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
                    rl_info.get("checks", {})
                    .get("ip", {})
                    .get("reset_after_seconds", 60)
                ),
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
        await sec_logger.log_attack_blocked(
            client_ip=client_ip,
            threats=[t.model_dump() for t in verdict.threats_detected],
            confidence=verdict.confidence,
        )
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
    for k in ("temperature", "max_tokens", "top_p", "presence_penalty",
              "frequency_penalty", "stop", "user"):
        val = getattr(body, k, None)
        if val is not None:
            extra_kwargs[k] = val

    # Streaming Logic
    if body.stream:
        async def secure_stream() -> AsyncGenerator[str, None]:
            REQUESTS_TOTAL.labels(status="allowed", provider="openai").inc()
            
            # Create a stream from provider
            # Note: real implementation needs async stream support in provider
            # converting sync iterator to async for compatibility in this example
            stream_iter = provider.chat_completion_stream(
                model=body.model,
                messages=messages_dicts,
                **extra_kwargs,
            )
            
            # First chunk: send usage/metadata (optional in OAI spec but good for us)
            # Then yield chunks
            for chunk in stream_iter:
                # Security scanning on chunks could happen here
                # For output filtering on stream, we'd need a buffer
                yield chunk

        return StreamingResponse(
            secure_stream(),
            media_type="text/event-stream",
        )

    # Non-streaming
    provider_start = time.perf_counter()
    try:
        raw_response = await provider.chat_completion(
            model=body.model,
            messages=messages_dicts,
            **extra_kwargs,
        )
    except Exception as exc:
        logger.error("Provider call failed", error=str(exc))
        REQUESTS_TOTAL.labels(status="error", provider="openai").inc()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream provider error: {exc}",
        )
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
                det_list = [d.model_dump() if hasattr(d, 'model_dump') else d for d in detections]
                sanitization_detections.extend(det_list)
                
                # Log metrics
                for d in det_list:
                    rule_name = d.get('rule', 'unknown') if isinstance(d, dict) else 'unknown'
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
    REQUESTS_TOTAL.labels(status="allowed", provider="openai").inc()

    try:
        # Calculate tokens if not provided
        prompt_tokens = raw_response.get("usage", {}).get("prompt_tokens", 0)
        completion_tokens = raw_response.get("usage", {}).get("completion_tokens", 0)
        
        await log_repo.create(
            api_key_id=api_key_id if api_key_id != "master" else None,
            client_ip=client_ip,
            provider="openai",
            model=body.model,
            message_count=len(body.messages),
            input_tokens=prompt_tokens,
            status=verdict.status.value,
            threat_level=(
                max(
                    (t.threat_level for t in verdict.threats_detected),
                    key=lambda l: {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(l.value, 0),
                    default=ThreatLevel.SAFE,
                ).value
                if verdict.threats_detected
                else "safe"
            ),
            confidence=verdict.confidence,
            threats=[t.model_dump() for t in verdict.threats_detected],
            output_tokens=completion_tokens,
            output_sanitized=output_sanitized,
            sanitizations=sanitization_detections,
            processing_ms=analysis_ms,
            provider_ms=provider_ms,
            total_ms=total_ms,
        )
    except Exception as exc:
        # Don't fail the request if logging fails
        logger.error("Failed to write audit log", error=str(exc))

    return raw_response
