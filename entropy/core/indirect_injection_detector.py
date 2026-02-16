"""Indirect Prompt Injection Detector — scans non-user content for hidden attacks.

Modern LLM applications frequently incorporate external data into the
context window (tool call results, fetched URLs, RAG chunks).  An attacker
can embed malicious instructions in those sources so the LLM executes them
as if they came from the user.

This module:
1. Extracts content from ``tool`` / ``function`` role messages.
2. Optionally extracts and fetches URLs found in any message.
3. Scans extracted content through the PatternMatcher and InputSanitizer.
4. Reports hidden instruction patterns (Markdown/HTML tricks, invisible
   Unicode, etc.) as ``ThreatInfo`` entries.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import structlog

from entropy.core.input_sanitizer import InputSanitizer
from entropy.core.pattern_matcher import PatternMatcher
from entropy.models.schemas import (
    ChatCompletionRequest,
    ThreatInfo,
    ThreatLevel,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Heuristic patterns for indirect injection markers
# ---------------------------------------------------------------------------

# Instructions hidden inside HTML comments
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Hidden text via Markdown image alt-text abuse or zero-width chars
_INVISIBLE_UNICODE_RE = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u200e\u200f"
    r"\u202a-\u202e\u2066-\u2069]+"
)

# Markdown link / image injection  (![](url){instructions})
_MD_INJECTION_RE = re.compile(
    r"!\[([^\]]*)\]\([^)]*\)\{([^}]+)\}",
    re.IGNORECASE,
)

# "System:" or "INSTRUCTIONS:" prefixes in non-user content
_INSTRUCTION_PREFIX_RE = re.compile(
    r"(?:^|\n)\s*(?:system|instruction|assistant|admin|operator)\s*[:>]",
    re.IGNORECASE,
)

# URL extraction pattern
_URL_RE = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# IndirectInjectionDetector
# ---------------------------------------------------------------------------

class IndirectInjectionDetector:
    """Detect prompt injection vectors hidden in non-user content.

    Usage::

        detector = IndirectInjectionDetector(pattern_matcher, sanitizer)
        threats = detector.analyze(request)
    """

    def __init__(
        self,
        pattern_matcher: PatternMatcher,
        input_sanitizer: InputSanitizer,
        *,
        fetch_urls: bool = False,
    ) -> None:
        self.pattern_matcher = pattern_matcher
        self.input_sanitizer = input_sanitizer
        self.fetch_urls = fetch_urls

    # -- public API ---------------------------------------------------------

    def analyze(self, request: ChatCompletionRequest) -> list[ThreatInfo]:
        """Scan a request for indirect prompt injection vectors.

        Returns a list of ``ThreatInfo`` entries (may be empty for clean
        requests).
        """
        threats: list[ThreatInfo] = []

        # 1. Extract content from tool / function role messages
        tool_contents = self._extract_tool_content(request)
        for source, content in tool_contents:
            t = self._scan_content(content, source)
            threats.extend(t)

        # 2. Scan for hidden instructions in all messages
        all_content = self._extract_all_content(request)
        for source, content in all_content:
            t = self._scan_hidden_markers(content, source)
            threats.extend(t)

        # 3. Extract URLs from all messages (optional fetch)
        if self.fetch_urls:
            urls = self._extract_urls(request)
            for url in urls:
                fetched = self._fetch_url_content(url)
                if fetched:
                    t = self._scan_content(fetched, f"fetched_url:{url}")
                    threats.extend(t)

        if threats:
            logger.warning(
                "Indirect injection detected",
                threat_count=len(threats),
            )

        return threats

    # -- content extraction -------------------------------------------------

    @staticmethod
    def _extract_tool_content(request: ChatCompletionRequest) -> list[tuple[str, str]]:
        """Extract text from tool / function role messages."""
        results: list[tuple[str, str]] = []
        for i, msg in enumerate(request.messages):
            if msg.role not in ("tool", "function"):
                continue
            content = ""
            if isinstance(msg.content, str):
                content = msg.content
            elif isinstance(msg.content, list):
                for item in msg.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        content += item.get("text", "")
            if content.strip():
                source = f"tool_msg[{i}]"
                if msg.name:
                    source = f"tool:{msg.name}"
                results.append((source, content))
        return results

    @staticmethod
    def _extract_all_content(request: ChatCompletionRequest) -> list[tuple[str, str]]:
        """Extract text from ALL messages for hidden-marker scanning."""
        results: list[tuple[str, str]] = []
        for i, msg in enumerate(request.messages):
            content = ""
            if isinstance(msg.content, str):
                content = msg.content
            elif isinstance(msg.content, list):
                for item in msg.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        content += item.get("text", "")
            if content.strip():
                results.append((f"msg[{i}]:{msg.role}", content))
        return results

    def _extract_urls(self, request: ChatCompletionRequest) -> list[str]:
        """Extract URLs found in any message content."""
        urls: list[str] = []
        for msg in request.messages:
            text = ""
            if isinstance(msg.content, str):
                text = msg.content
            elif isinstance(msg.content, list):
                for item in msg.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text += item.get("text", "")
            urls.extend(_URL_RE.findall(text))
        return list(set(urls))  # deduplicate

    # -- scanning -----------------------------------------------------------

    def _scan_content(self, content: str, source: str) -> list[ThreatInfo]:
        """Run full pattern matcher + sanitizer scan on content."""
        threats: list[ThreatInfo] = []

        # Decode obfuscation layers first
        sanitized = self.input_sanitizer.sanitize(content)
        analysis_text = sanitized.decoded

        if sanitized.was_obfuscated:
            threats.append(ThreatInfo(
                category="indirect_injection",
                name="obfuscated_tool_output",
                threat_level=ThreatLevel.HIGH,
                confidence=min(0.4 * sanitized.layers_decoded, 0.95),
                details=(
                    f"Obfuscated content in {source}: "
                    f"{', '.join(sanitized.encodings_found)}"
                ),
            ))

        # Pattern matching on decoded content
        is_malicious, confidence, detections, threat_level = (
            self.pattern_matcher.analyze(analysis_text)
        )

        if is_malicious:
            # Boost severity: injection patterns in tool output are more dangerous
            boosted_level = ThreatLevel.HIGH
            if threat_level == ThreatLevel.CRITICAL:
                boosted_level = ThreatLevel.CRITICAL

            threats.append(ThreatInfo(
                category="indirect_injection",
                name="injection_in_external_content",
                threat_level=boosted_level,
                confidence=min(confidence + 0.15, 1.0),
                details=(
                    f"Injection pattern found in {source}: "
                    f"{', '.join(d.pattern_name for d in detections[:3])}"
                ),
            ))

        return threats

    def _scan_hidden_markers(self, content: str, source: str) -> list[ThreatInfo]:
        """Detect hidden instruction markers in content."""
        threats: list[ThreatInfo] = []

        # HTML comments with instruction-like content
        for match in _HTML_COMMENT_RE.finditer(content):
            comment_text = match.group(1).strip()
            if len(comment_text) > 10:
                # Check if the comment contains injection patterns
                is_mal, conf, _, _ = self.pattern_matcher.analyze(comment_text)
                if is_mal:
                    threats.append(ThreatInfo(
                        category="indirect_injection",
                        name="hidden_html_comment",
                        threat_level=ThreatLevel.HIGH,
                        confidence=min(conf + 0.1, 1.0),
                        details=(
                            f"Malicious instructions hidden in HTML comment in {source}"
                        ),
                    ))

        # Invisible Unicode characters hiding instructions
        invisible_matches = _INVISIBLE_UNICODE_RE.findall(content)
        if invisible_matches:
            total_invisible = sum(len(m) for m in invisible_matches)
            if total_invisible > 5:
                threats.append(ThreatInfo(
                    category="indirect_injection",
                    name="invisible_unicode_chars",
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=min(0.2 * total_invisible, 0.85),
                    details=(
                        f"{total_invisible} invisible Unicode characters found in {source}"
                    ),
                ))

        # Instruction prefixes in non-user content  (e.g. "System: do X")
        if "tool" in source or "function" in source:
            prefix_matches = _INSTRUCTION_PREFIX_RE.findall(content)
            if prefix_matches:
                threats.append(ThreatInfo(
                    category="indirect_injection",
                    name="instruction_prefix_in_tool_output",
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.8,
                    details=(
                        f"Instruction prefix pattern found in {source} — "
                        f"possible attempt to override system instructions"
                    ),
                ))

        # Markdown injection patterns
        md_matches = _MD_INJECTION_RE.findall(content)
        if md_matches:
            threats.append(ThreatInfo(
                category="indirect_injection",
                name="markdown_injection",
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.7,
                details=f"Markdown injection pattern found in {source}",
            ))

        return threats

    # -- URL fetching (optional) --------------------------------------------

    @staticmethod
    def _fetch_url_content(url: str) -> str | None:
        """Fetch and return text content from a URL.

        Returns None on any error.  This is intentionally conservative
        (short timeout, max size) to avoid abuse.
        """
        try:
            import urllib.request

            req = urllib.request.Request(
                url,
                headers={"User-Agent": "EntropyFirewall/0.1"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                # Max 100KB to prevent resource abuse
                data = resp.read(102_400)
                return data.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug("Failed to fetch URL for analysis", url=url, error=str(e))
            return None
