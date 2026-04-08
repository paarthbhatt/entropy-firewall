"""RAG Shield ΓÇö document chunk scanner for RAG applications.

Scans retrieved document chunks for embedded attacks, malicious content,
and prompt injection before they reach the LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from entropy.core.engine import EntropyEngine
from entropy.core.input_sanitizer import InputSanitizer
from entropy.core.pattern_matcher import PatternMatcher
from entropy.models.schemas import EntropyStatus, ThreatInfo, ThreatLevel

logger = structlog.get_logger(__name__)


@dataclass
class DocumentChunk:
    """A document chunk to scan."""

    id: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    score: float | None = None


@dataclass
class ChunkScanResult:
    """Result of scanning a single chunk."""

    chunk_id: str
    status: EntropyStatus
    threats: list[ThreatInfo] = field(default_factory=list)
    confidence: float = 0.0
    sanitized_content: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RAGScanResult:
    """Result of scanning multiple document chunks."""

    chunks_scanned: int
    chunks_safe: int
    chunks_blocked: int
    chunks_sanitized: int
    results: list[ChunkScanResult] = field(default_factory=list)
    processing_time_ms: float = 0.0


class RAGScanner:
    """Scans document chunks for embedded attacks and malicious content.

    RAG applications retrieve documents from vector stores and inject them
    into prompts. Attackers can poison these documents with hidden instructions
    that bypass input filters. RAG Shield scans each chunk before injection.

    Usage:
        scanner = RAGScanner(engine)

        # Scan retrieved chunks
        result = await scanner.scan_chunks([
            DocumentChunk(id="1", content="..."),
            DocumentChunk(id="2", content="..."),
        ])

        # Filter out blocked chunks
        safe_chunks = [c for c in result.results if c.status != EntropyStatus.BLOCKED]
    """

    def __init__(
        self,
        engine: EntropyEngine | None = None,
        pattern_matcher: PatternMatcher | None = None,
        input_sanitizer: InputSanitizer | None = None,
        max_chunk_size: int = 10000,
        sanitize_blocked: bool = True,
    ) -> None:
        """Initialize the RAG scanner.

        Args:
            engine: EntropyEngine for full analysis (optional)
            pattern_matcher: PatternMatcher for quick scans (optional)
            input_sanitizer: InputSanitizer for decoding (optional)
            max_chunk_size: Maximum chunk size in characters
            sanitize_blocked: Whether to sanitize blocked chunks instead of removing
        """
        self.engine = engine or EntropyEngine()
        self.pattern_matcher = pattern_matcher or PatternMatcher()
        self.input_sanitizer = input_sanitizer or InputSanitizer()
        self.max_chunk_size = max_chunk_size
        self.sanitize_blocked = sanitize_blocked

        logger.info(
            "RAGScanner initialized",
            max_chunk_size=max_chunk_size,
            sanitize_blocked=sanitize_blocked,
        )

    async def scan_chunk(
        self,
        chunk: DocumentChunk,
        detailed: bool = True,
    ) -> ChunkScanResult:
        """Scan a single document chunk for threats.

        Args:
            chunk: The document chunk to scan
            detailed: Whether to run full analysis (slower but more accurate)

        Returns:
            ChunkScanResult with status and any detected threats
        """
        import time  # noqa: PLC0415

        start = time.perf_counter()

        # Check chunk size
        if len(chunk.content) > self.max_chunk_size:
            logger.warning(
                "Chunk exceeds max size, truncating",
                chunk_id=chunk.id,
                size=len(chunk.content),
                max_size=self.max_chunk_size,
            )
            content = chunk.content[: self.max_chunk_size]
        else:
            content = chunk.content

        threats: list[ThreatInfo] = []

        # Quick pattern scan first
        is_malicious, confidence, detections, _threat_level = self.pattern_matcher.analyze(content)

        for d in detections:
            threats.append(
                ThreatInfo(
                    category=d.pattern_category,
                    name=d.pattern_name,
                    threat_level=d.threat_level,
                    confidence=d.confidence,
                    details=d.details,
                )
            )

        # Decode any obfuscation
        sanitized_input = self.input_sanitizer.sanitize(content)
        if sanitized_input.was_obfuscated:
            threats.append(
                ThreatInfo(
                    category="obfuscation",
                    name="encoded_content_in_chunk",
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=min(0.3 * sanitized_input.layers_decoded, 0.9),
                    details=f"Decoded {sanitized_input.layers_decoded} encoding layer(s)",
                )
            )
            # Re-scan decoded content
            content = sanitized_input.decoded

        # Full analysis if requested or if quick scan found issues
        if detailed or is_malicious:
            from entropy.models.schemas import ChatCompletionRequest  # noqa: PLC0415

            fake_request = ChatCompletionRequest(
                model="rag-scan",
                messages=[{"role": "user", "content": content}],
            )
            verdict = await self.engine.analyze_request(fake_request)

            # Merge threats
            existing_categories = {t.category for t in threats}
            for t in verdict.threats_detected:
                if t.category not in existing_categories:
                    threats.append(t)

            # Update confidence
            confidence = max(confidence, verdict.confidence)

        # Determine status
        if not threats:
            status = EntropyStatus.ALLOWED
        elif any(t.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL) for t in threats):
            status = EntropyStatus.BLOCKED
        else:
            status = EntropyStatus.SANITIZED

        # Sanitize content if needed
        sanitized_content = None
        if status == EntropyStatus.BLOCKED and self.sanitize_blocked:
            sanitized, _, _ = self.engine.analyze_output(content)
            if sanitized != content:
                sanitized_content = sanitized

        elapsed_ms = (time.perf_counter() - start) * 1000

        logger.debug(
            "Chunk scanned",
            chunk_id=chunk.id,
            status=status.value,
            threats=len(threats),
            elapsed_ms=round(elapsed_ms, 2),
        )

        return ChunkScanResult(
            chunk_id=chunk.id,
            status=status,
            threats=threats,
            confidence=confidence,
            sanitized_content=sanitized_content,
            metadata=chunk.metadata,
        )

    async def scan_chunks(
        self,
        chunks: list[DocumentChunk],
        detailed: bool = False,
        fail_fast: bool = True,
    ) -> RAGScanResult:
        """Scan multiple document chunks.

        Args:
            chunks: List of document chunks to scan
            detailed: Whether to run full analysis on each chunk
            fail_fast: Stop scanning on first blocked chunk

        Returns:
            RAGScanResult with aggregated results
        """
        import time  # noqa: PLC0415

        start = time.perf_counter()

        results: list[ChunkScanResult] = []
        chunks_safe = 0
        chunks_blocked = 0
        chunks_sanitized = 0

        for chunk in chunks:
            result = await self.scan_chunk(chunk, detailed=detailed)
            results.append(result)

            if result.status == EntropyStatus.ALLOWED:
                chunks_safe += 1
            elif result.status == EntropyStatus.BLOCKED:
                chunks_blocked += 1
                if fail_fast:
                    break
            else:
                chunks_sanitized += 1

        elapsed_ms = (time.perf_counter() - start) * 1000

        logger.info(
            "RAG scan complete",
            chunks_scanned=len(results),
            safe=chunks_safe,
            blocked=chunks_blocked,
            sanitized=chunks_sanitized,
            elapsed_ms=round(elapsed_ms, 2),
        )

        return RAGScanResult(
            chunks_scanned=len(results),
            chunks_safe=chunks_safe,
            chunks_blocked=chunks_blocked,
            chunks_sanitized=chunks_sanitized,
            results=results,
            processing_time_ms=elapsed_ms,
        )

    def get_safe_chunks(
        self,
        scan_result: RAGScanResult,
        original_chunks: list[DocumentChunk],
    ) -> list[DocumentChunk]:
        """Get safe chunks from scan result.

        Args:
            scan_result: Result from scan_chunks
            original_chunks: Original chunks for reference

        Returns:
            List of safe (allowed or sanitized) chunks
        """
        safe_chunks = []

        for i, result in enumerate(scan_result.results):
            if result.status == EntropyStatus.ALLOWED:
                safe_chunks.append(original_chunks[i])
            elif result.status == EntropyStatus.SANITIZED and result.sanitized_content:
                # Use sanitized content
                chunk = DocumentChunk(
                    id=original_chunks[i].id,
                    content=result.sanitized_content,
                    metadata=original_chunks[i].metadata,
                    source=original_chunks[i].source,
                    score=original_chunks[i].score,
                )
                safe_chunks.append(chunk)

        return safe_chunks


__all__ = [
    "ChunkScanResult",
    "DocumentChunk",
    "RAGScanResult",
    "RAGScanner",
]
