"""Streaming Output Filter ΓÇö sliding window PII detection for streaming responses.

Detects and redacts sensitive data (PII, secrets, etc.) in streaming LLM responses
using a sliding window buffer to handle patterns that span chunk boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

import structlog

from entropy.core.output_filter import OutputFilter, SanitizationRule

logger = structlog.get_logger(__name__)


@dataclass
class StreamingFilterResult:
    """Result of processing a streaming chunk."""

    safe_content: str
    detections: list[dict[str, Any]]
    was_redacted: bool = False


@dataclass
class PendingMatch:
    """A potential match that spans chunk boundaries."""

    rule: SanitizationRule
    partial_match: str
    start_pos: int
    remaining_pattern: str


class StreamingOutputFilter:
    """Sliding-window PII detection for streaming responses.

    Strategy:
    - Maintain a buffer of N characters (default 128)
    - For each incoming chunk: append to buffer
    - Scan buffer for PII/secrets patterns
    - Yield safe content, hold potentially unsafe content
    - Handle patterns that span chunk boundaries

    This ensures that even patterns split across multiple chunks
    (like a credit card number split between two SSE events) are
    properly detected and redacted.
    """

    def __init__(
        self,
        window_size: int = 128,
        rules: list[SanitizationRule] | None = None,
        enable_pii: bool = True,
        enable_code: bool = True,
    ) -> None:
        """Initialize the streaming filter.

        Args:
            window_size: Size of the sliding window buffer (in characters)
            rules: Custom sanitization rules (if None, uses defaults)
            enable_pii: Enable PII detection rules
            enable_code: Enable code/secret detection rules
        """
        self.window_size = window_size
        self.buffer = ""
        self.enable_pii = enable_pii
        self.enable_code = enable_code

        # Use provided rules or create default filter
        if rules:
            self.rules = rules
        else:
            # Create a filter to get default rules
            default_filter = OutputFilter(enable_pii=enable_pii, enable_code=enable_code)
            self.rules = default_filter.rules

        # Track total detections for reporting
        self.total_detections: list[dict[str, Any]] = []
        self.total_redactions = 0

        logger.info(
            "StreamingOutputFilter initialized",
            window_size=window_size,
            rules=len(self.rules),
        )

    async def process_stream(
        self,
        stream: AsyncIterator[str],
    ) -> AsyncIterator[str]:
        """Process streaming text, yielding safe chunks.

        This is the main entry point for streaming filtering.

        Args:
            stream: Async iterator of text chunks

        Yields:
            Redacted, safe text chunks
        """
        async for chunk in stream:
            # Add chunk to buffer
            self.buffer += chunk

            # Scan buffer for complete matches
            safe_content, hold = self._scan_and_split()
            self.buffer = hold

            if safe_content:
                yield safe_content

        # Flush remaining buffer
        if self.buffer:
            final = self._redact(self.buffer)
            self.total_detections.extend(
                [
                    {"rule": r.name, "category": r.category}
                    for r in self.rules
                    if r.pattern.search(self.buffer)
                ]
            )
            yield final

    def process_chunk(self, chunk: str) -> StreamingFilterResult:
        """Process a single chunk (non-async for use in generators).

        Args:
            chunk: Text chunk to process

        Returns:
            StreamingFilterResult with safe content and detections
        """
        self.buffer += chunk

        safe_content, hold = self._scan_and_split()
        self.buffer = hold

        # Find detections in the safe content
        detections = []
        if safe_content:
            for rule in self.rules:
                matches = list(rule.pattern.finditer(safe_content))
                if matches:
                    detections.append(
                        {
                            "rule": rule.name,
                            "category": rule.category,
                            "count": len(matches),
                        }
                    )

        was_redacted = bool(detections)
        if was_redacted:
            self.total_redactions += 1

        return StreamingFilterResult(
            safe_content=safe_content,
            detections=detections,
            was_redacted=was_redacted,
        )

    def _scan_and_split(self) -> tuple[str, str]:
        """Scan buffer and split into safe content and hold buffer.

        Returns:
            Tuple of (safe_content, hold_buffer)
        """
        if not self.buffer:
            return "", ""

        # If buffer is smaller than window, hold everything
        if len(self.buffer) < self.window_size:
            # Check for complete matches
            safe, has_match = self._extract_complete_matches()
            if has_match:
                return safe, ""
            return "", self.buffer

        # Find all potential matches in buffer
        potential_matches = []
        for rule in self.rules:
            for match in rule.pattern.finditer(self.buffer):
                potential_matches.append((match, rule))

        if not potential_matches:
            # No matches found - can release most of the buffer
            # But keep window_size for boundary detection
            safe = self.buffer[: -self.window_size]
            hold = self.buffer[-self.window_size :]
            return safe, hold

        # Find the earliest match position
        earliest_start = min(m.start() for m, r in potential_matches)

        # Safe content is everything before the first match
        safe = self.buffer[:earliest_start]

        # Check for matches that might span boundaries
        hold = self.buffer[earliest_start:]

        # If a match is found near the end, it might be incomplete
        # Keep the hold buffer until we have enough context
        match_positions = [(m.start(), m.end(), r) for m, r in potential_matches]

        # Find complete matches (those that don't touch the end of buffer)
        complete_matches = [
            (s, e, r)
            for s, e, r in match_positions
            if e <= len(self.buffer) - self.window_size // 2
        ]

        if complete_matches:
            # Redact complete matches and release up to the end of last complete match
            last_complete_end = max(e for s, e, r in complete_matches)
            text_to_process = self.buffer[:last_complete_end]

            # Redact this portion
            redacted = self._redact(text_to_process)

            # Release redacted content up to the hold window
            release_end = max(0, len(redacted) - self.window_size)
            safe = redacted[:release_end]
            hold = redacted[release_end:] + self.buffer[last_complete_end:]

        return safe, hold

    def _extract_complete_matches(self) -> tuple[str, bool]:
        """Extract text with complete matches redacted.

        Returns:
            Tuple of (redacted_text, had_matches)
        """
        if not self.buffer:
            return "", False

        had_matches = False
        text = self.buffer

        for rule in self.rules:
            matches = list(rule.pattern.finditer(text))
            if matches:
                had_matches = True
                # Check if match extends to end (potential boundary span)
                for match in matches:
                    if match.end() == len(text):
                        # Match at end - might be incomplete
                        continue
                text = rule.pattern.sub(rule.replacement, text)

        return text, had_matches

    def _redact(self, text: str) -> str:
        """Apply all redaction rules to text."""
        result = text
        for rule in self.rules:
            result = rule.pattern.sub(rule.replacement, result)
        return result

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all detections made during the stream.

        Returns:
            Summary dict with total detections and redactions
        """
        return {
            "total_detections": len(self.total_detections),
            "total_redactions": self.total_redactions,
            "categories_detected": list(
                {d.get("category", "unknown") for d in self.total_detections}
            ),
        }

    def reset(self) -> None:
        """Reset the filter state for a new stream."""
        self.buffer = ""
        self.total_detections = []
        self.total_redactions = 0


class SSEStreamingFilter:
    """Streaming filter for Server-Sent Events (SSE) format.

    Parses SSE format, extracts content, filters, and rebuilds SSE.
    Designed for OpenAI-compatible streaming responses.
    """

    def __init__(
        self,
        window_size: int = 128,
        enable_pii: bool = True,
        enable_code: bool = True,
    ) -> None:
        """Initialize SSE streaming filter.

        Args:
            window_size: Sliding window buffer size
            enable_pii: Enable PII detection
            enable_code: Enable code/secret detection
        """
        self.output_filter = StreamingOutputFilter(
            window_size=window_size,
            enable_pii=enable_pii,
            enable_code=enable_code,
        )

    async def process_sse_stream(
        self,
        stream: AsyncIterator[str],
    ) -> AsyncIterator[str]:
        """Process SSE streaming response, filtering content.

        Args:
            stream: Async iterator of SSE-formatted strings

        Yields:
            Filtered SSE-formatted strings
        """
        import json  # noqa: PLC0415

        async for sse_line in stream:
            # Parse SSE line
            if not sse_line.startswith("data: "):
                yield sse_line
                continue

            data = sse_line[6:].strip()

            # Handle [DONE] marker
            if data == "[DONE]":
                # Flush any remaining buffer
                summary = self.output_filter.get_summary()
                if summary["total_detections"] > 0:
                    logger.warning(
                        "Streaming output filtered",
                        detections=summary["total_detections"],
                        redactions=summary["total_redactions"],
                    )
                yield sse_line
                continue

            # Parse JSON
            try:
                chunk_data = json.loads(data)
            except json.JSONDecodeError:
                # Pass through if not valid JSON
                yield sse_line
                continue

            # Extract content from OpenAI format
            content = self._extract_content(chunk_data)

            if content:
                # Filter the content
                result = self.output_filter.process_chunk(content)

                # Update chunk data with filtered content
                self._update_content(chunk_data, result.safe_content)

                # Yield filtered SSE
                yield f"data: {json.dumps(chunk_data)}\n\n"
            else:
                # No content to filter - pass through
                yield sse_line

    def _extract_content(self, chunk_data: dict[str, Any]) -> str:
        """Extract text content from OpenAI chunk format."""
        try:
            choices = chunk_data.get("choices", [])
            if not choices:
                return ""

            delta = choices[0].get("delta", {})
            return delta.get("content", "") or ""
        except (KeyError, IndexError, TypeError):
            return ""

    def _update_content(self, chunk_data: dict[str, Any], new_content: str) -> None:
        """Update content in OpenAI chunk format."""
        try:
            if chunk_data.get("choices"):
                chunk_data["choices"][0]["delta"]["content"] = new_content
        except (KeyError, IndexError, TypeError):
            pass


__all__ = [
    "SSEStreamingFilter",
    "StreamingFilterResult",
    "StreamingOutputFilter",
]
