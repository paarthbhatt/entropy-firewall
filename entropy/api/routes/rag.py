"""RAG Shield API endpoints.

Provides endpoints for scanning document chunks before injection into LLM prompts.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from entropy.api.dependencies import get_engine, require_auth
from entropy.core.engine import EntropyEngine
from entropy.core.rag_scanner import RAGScanner, DocumentChunk, RAGScanResult

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/rag", tags=["rag"])


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------


class ChunkInput(BaseModel):
    """Input for a single document chunk."""

    id: str = Field(..., description="Unique identifier for the chunk")
    content: str = Field(..., description="Text content of the chunk")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Optional metadata")
    source: Optional[str] = Field(default=None, description="Source document ID")
    score: Optional[float] = Field(default=None, description="Relevance score from retriever")


class RAGScanRequest(BaseModel):
    """Request to scan document chunks."""

    chunks: list[ChunkInput] = Field(..., description="Document chunks to scan")
    detailed: bool = Field(
        default=False,
        description="Run detailed analysis (slower but more accurate)",
    )
    fail_fast: bool = Field(
        default=True,
        description="Stop scanning on first blocked chunk",
    )
    sanitize_blocked: bool = Field(
        default=True,
        description="Attempt to sanitize blocked chunks instead of removing",
    )


class ChunkResultResponse(BaseModel):
    """Result for a single chunk."""

    chunk_id: str
    status: str
    threats: list[dict[str, Any]]
    confidence: float
    sanitized_content: Optional[str] = None


class RAGScanResponse(BaseModel):
    """Response from RAG scan."""

    chunks_scanned: int
    chunks_safe: int
    chunks_blocked: int
    chunks_sanitized: int
    results: list[ChunkResultResponse]
    processing_time_ms: float
    safe_to_proceed: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=RAGScanResponse)
async def scan_documents(
    request: RAGScanRequest,
    engine: EntropyEngine = Depends(get_engine),
    auth_record: dict[str, Any] = Depends(require_auth),
) -> RAGScanResponse:
    """Scan document chunks for embedded attacks.

    Use this endpoint to scan retrieved documents before injecting them
    into LLM prompts. This prevents RAG-based prompt injection attacks.

    Enterprise feature: requires database backend for full functionality.
    """
    if not request.chunks:
        raise HTTPException(status_code=400, detail="No chunks provided")

    if len(request.chunks) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 chunks per request")

    # Create scanner
    scanner = RAGScanner(
        engine=engine,
        sanitize_blocked=request.sanitize_blocked,
    )

    # Convert to DocumentChunks
    chunks = [
        DocumentChunk(
            id=c.id,
            content=c.content,
            metadata=c.metadata,
            source=c.source,
            score=c.score,
        )
        for c in request.chunks
    ]

    # Scan
    result: RAGScanResult = await scanner.scan_chunks(
        chunks=chunks,
        detailed=request.detailed,
        fail_fast=request.fail_fast,
    )

    # Log
    logger.info(
        "RAG scan completed",
        chunks_scanned=result.chunks_scanned,
        blocked=result.chunks_blocked,
        api_key_id=auth_record.get("id"),
    )

    return RAGScanResponse(
        chunks_scanned=result.chunks_scanned,
        chunks_safe=result.chunks_safe,
        chunks_blocked=result.chunks_blocked,
        chunks_sanitized=result.chunks_sanitized,
        results=[
            ChunkResultResponse(
                chunk_id=r.chunk_id,
                status=r.status.value,
                threats=[t.model_dump() for t in r.threats],
                confidence=r.confidence,
                sanitized_content=r.sanitized_content,
            )
            for r in result.results
        ],
        processing_time_ms=result.processing_time_ms,
        safe_to_proceed=result.chunks_blocked == 0,
    )


@router.post("/quick-scan")
async def quick_scan_text(
    text: str,
    engine: EntropyEngine = Depends(get_engine),
    auth_record: dict[str, Any] = Depends(require_auth),
) -> dict[str, Any]:
    """Quick scan a single text string.

    Simplified endpoint for quick checks without chunk metadata.
    """
    scanner = RAGScanner(engine=engine)

    chunk = DocumentChunk(id="quick-scan", content=text)
    result = await scanner.scan_chunk(chunk, detailed=False)

    return {
        "status": result.status.value,
        "threats": [t.model_dump() for t in result.threats],
        "confidence": result.confidence,
        "safe": result.status.value == "allowed",
    }