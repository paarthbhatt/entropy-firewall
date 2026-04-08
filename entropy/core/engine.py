"""Entropy Engine — the orchestrator for all detection layers.

Free tier runs: Input Validation → Pattern Matching → Output Filtering.

Pro tier (entropy-enterprise) additionally enables:
  - Input Sanitizer    (recursive multi-layer obfuscation decoding)
  - Indirect Injection (tool output scanning)
  - Context Analyzer   (multi-turn heuristics)
  - Semantic Analyzer  (local ONNX intent classification)

Pro modules are loaded at runtime via optional imports so the free engine
starts cleanly when the `entropy-pro` package is not installed.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from entropy.config import get_settings
from entropy.core.input_validator import InputValidator
from entropy.core.output_filter import OutputFilter
from entropy.core.pattern_matcher import PatternMatcher
from entropy.models.schemas import (
    ChatCompletionRequest,
    EntropyStatus,
    EntropyVerdict,
    ThreatInfo,
    ThreatLevel,
)

logger = structlog.get_logger(__name__)

from entropy.core.context_analyzer import ContextAnalyzer  # noqa: E402
from entropy.core.indirect_injection_detector import IndirectInjectionDetector  # noqa: E402
from entropy.core.input_sanitizer import InputSanitizer  # noqa: E402
from entropy.core.semantic_analyzer import SemanticAnalyzer  # noqa: E402

# ---------------------------------------------------------------------------
# Threat-level helpers
# ---------------------------------------------------------------------------

_LEVEL_PRIORITY: dict[ThreatLevel, int] = {
    ThreatLevel.SAFE: 0,
    ThreatLevel.LOW: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.HIGH: 3,
    ThreatLevel.CRITICAL: 4,
}

_SUGGESTIONS: dict[str, dict[str, str]] = {
    "direct_injection": {
        "ignore_instructions": (
            "Remove phrases like 'ignore previous instructions' from user input."
        ),
        "system_prompt_extract": (
            "Block this request — it attempts to extract your system prompt."
        ),
        "act_as": "Requests asking you to 'act as' are a common jailbreak technique.",
        "new_instructions": "Reject requests that claim to provide 'new' instructions.",
        "developer_mode": ("Developer/admin mode requests are almost always jailbreak attempts."),
    },
    "jailbreak": {
        "dan_attack": "Known jailbreak attempt (DAN). Block immediately.",
        "no_restrictions": "Legitimate requests never ask to bypass restrictions.",
        "hypothetical_bypass": "Hypothetical framing is a known bypass technique.",
        "opposite_day": "Known jailbreak pattern. Block this request.",
    },
    "data_exfiltration": {
        "credential_request": "Never process requests for credentials, API keys, or secrets.",
        "training_data_extraction": (
            "Requests about training data are attempting data exfiltration."
        ),
        "pii_request": "Block requests for personally identifiable information.",
    },
    "code_injection": {
        "exec_call": "Block requests containing exec(), eval(), or subprocess calls.",
        "template_injection": "Template injection detected — sanitize or block.",
        "sql_injection": "SQL injection attempt detected.",
    },
    "obfuscation": {
        "base64_payload": "Base64-encoded content may hide malicious instructions.",
        "unicode_tricks": "Hidden Unicode characters detected — possible obfuscation.",
        "leetspeak_bypass": "Leetspeak encoding detected.",
        "char_split_evasion": "Character splitting detected — evasion attempt.",
    },
    "constraint_manipulation": {
        "safety_disable": "Requests to disable safety features are attacks.",
        "boundary_test": "Questions about 'limits' often precede jailbreak attempts.",
    },
    "resource_abuse": {
        "infinite_loop_prompt": "Resource abuse attempt. Consider rate limiting.",
        "token_waste": "Token exhaustion attempt. Limit max tokens.",
    },
    "file_system": {
        "path_traversal": "Path traversal attack detected.",
    },
}


def _generate_suggestion(threat: ThreatInfo) -> str:
    cat = threat.category
    name = threat.name
    if cat in _SUGGESTIONS:
        if name in _SUGGESTIONS[cat]:
            return _SUGGESTIONS[cat][name]
        return next(iter(_SUGGESTIONS[cat].values()))
    defaults = {
        ThreatLevel.CRITICAL: "Critical threat. Block the request and log for review.",
        ThreatLevel.HIGH: "High threat. Consider blocking or sanitizing.",
        ThreatLevel.MEDIUM: "Medium threat. Sanitize or flag for review.",
        ThreatLevel.LOW: "Low threat. Log for monitoring.",
    }
    return defaults.get(threat.threat_level, "Review this request.")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class EntropyEngine:
    """Core security engine that coordinates all detection layers.

    Free tier:  Input Validation → Pattern Matching → Output Filtering
    Pro tier:   + Sanitizer → Indirect Injection → Context → Semantic

    Usage::

        engine = EntropyEngine()
        verdict = await engine.analyze_request(request)
        if verdict.status == EntropyStatus.BLOCKED:
            return 403
    """

    def __init__(
        self,
        *,
        pattern_matcher: PatternMatcher | None = None,
        input_validator: InputValidator | None = None,
        output_filter: OutputFilter | None = None,
    ) -> None:
        settings = get_settings()

        # --- Free tier components (always available) ---
        self.pattern_matcher = pattern_matcher or PatternMatcher()
        self.input_validator = input_validator or InputValidator()
        self.output_filter = output_filter or OutputFilter(
            enable_pii=settings.output_filter.pii_detection,
            enable_code=settings.output_filter.code_scanning,
        )

        # --- Advanced components (formerly Enterprise) ---
        self._input_sanitizer = InputSanitizer(
            max_depth=settings.engine.max_decode_depth,
            enabled=settings.engine.enable_recursive_decoding,
        )

        self._indirect_detector = IndirectInjectionDetector(
            pattern_matcher=self.pattern_matcher,
            input_sanitizer=self._input_sanitizer,
            fetch_urls=settings.engine.fetch_urls_for_analysis,
        )

        self._context_analyzer = ContextAnalyzer(max_history=settings.engine.max_history_length)

        self._semantic_analyzer = SemanticAnalyzer(enabled=settings.engine.enable_semantic_analysis)

        self._threshold = settings.engine.pattern_threshold
        self._block = settings.engine.block_on_detection
        self._context_enabled = settings.engine.enable_context_analysis
        self._indirect_enabled = settings.engine.enable_indirect_injection_detection

        logger.info(
            "EntropyEngine initialized",
            patterns=self.pattern_matcher.get_pattern_count(),
            context=self._context_enabled,
            semantic=settings.engine.enable_semantic_analysis,
            sanitizer=settings.engine.enable_recursive_decoding,
            indirect_injection=self._indirect_enabled,
        )

    # ---- Public API --------------------------------------------------------

    async def analyze_request(  # noqa: PLR0912
        self,
        request: ChatCompletionRequest,
        conversation_history: list[dict[str, Any]] | None = None,
    ) -> EntropyVerdict:
        """Full security analysis. Pro components are used when available."""
        start = time.perf_counter()
        threats: list[ThreatInfo] = []
        max_level = ThreatLevel.SAFE
        max_conf = 0.0

        # 1. Input validation (free)
        validation = self.input_validator.validate(request)
        if not validation.is_valid:
            threats.append(
                ThreatInfo(
                    category="input_validation",
                    name="invalid_input",
                    threat_level=ThreatLevel.HIGH,
                    confidence=1.0,
                    details="; ".join(validation.errors),
                )
            )
            return self._build_verdict(
                EntropyStatus.BLOCKED, 1.0, threats, start, input_valid=False
            )

        # 2. Extract text
        text = self._extract_text(request)
        analysis_text = text

        # 2.5. [PRO] Recursive obfuscation decoding
        if self._input_sanitizer is not None:
            sanitized = self._input_sanitizer.sanitize(text)
            if sanitized.was_obfuscated:
                threats.append(
                    ThreatInfo(
                        category="obfuscation",
                        name="multi_layer_encoding",
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=min(0.3 * sanitized.layers_decoded, 0.9),
                        details=(
                            f"Decoded {sanitized.layers_decoded} encoding layer(s): "
                            f"{', '.join(sanitized.encodings_found)}"
                        ),
                    )
                )
                max_conf = max(max_conf, min(0.3 * sanitized.layers_decoded, 0.9))
                if _LEVEL_PRIORITY[ThreatLevel.MEDIUM] > _LEVEL_PRIORITY[max_level]:
                    max_level = ThreatLevel.MEDIUM
            analysis_text = sanitized.decoded

        # 2.7. [PRO] Indirect prompt injection (tool outputs, RAG docs)
        if self._indirect_enabled and self._indirect_detector is not None:
            indirect_threats = self._indirect_detector.analyze(request)
            threats.extend(indirect_threats)
            for t in indirect_threats:
                max_conf = max(max_conf, t.confidence)
                if _LEVEL_PRIORITY[t.threat_level] > _LEVEL_PRIORITY[max_level]:
                    max_level = t.threat_level

        # 3. Pattern matching (free — on decoded text)
        is_malicious, pat_conf, detections, pat_level = self.pattern_matcher.analyze(analysis_text)
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
        max_conf = max(max_conf, pat_conf)
        if _LEVEL_PRIORITY[pat_level] > _LEVEL_PRIORITY[max_level]:
            max_level = pat_level

        # 4. [PRO] Context analysis
        if self._context_enabled and self._context_analyzer is not None and conversation_history:
            ctx_conf, ctx_issues = self._context_analyzer.analyze(text, conversation_history)
            if ctx_issues:
                ctx_level = ThreatLevel.HIGH if ctx_conf > 0.8 else ThreatLevel.MEDIUM
                for issue in ctx_issues:
                    threats.append(
                        ThreatInfo(
                            category="context",
                            name="multi_turn_anomaly",
                            threat_level=ctx_level,
                            confidence=ctx_conf,
                            details=issue,
                        )
                    )
                max_conf = (
                    min(1.0, max_conf + ctx_conf * 0.2) if is_malicious else max(max_conf, ctx_conf)
                )
                if _LEVEL_PRIORITY[ctx_level] > _LEVEL_PRIORITY[max_level]:
                    max_level = ctx_level

        # 5. [PRO] Semantic analysis
        if self._semantic_analyzer is not None:
            sem = await self._semantic_analyzer.analyze(analysis_text, history=conversation_history)
            if sem.is_malicious:
                threats.append(
                    ThreatInfo(
                        category="semantic",
                        name="intent_classification",
                        threat_level=sem.threat_level,
                        confidence=sem.confidence,
                        details=sem.reasoning,
                    )
                )
                max_conf = max(max_conf, sem.confidence)
                if _LEVEL_PRIORITY[sem.threat_level] > _LEVEL_PRIORITY[max_level]:
                    max_level = sem.threat_level

        # 6. Decision
        status = self._decide(max_conf, max_level, threats)
        verdict = self._build_verdict(status, max_conf, threats, start, input_valid=True)
        if status == EntropyStatus.BLOCKED:
            logger.warning("Request BLOCKED", confidence=verdict.confidence, threats=len(threats))
        return verdict

    def analyze_output(self, text: str) -> tuple[str, list[dict[str, Any]], bool]:
        """Analyze and sanitize LLM output. Returns (sanitized_text, detections, was_sanitized)."""
        sanitized, detections = self.output_filter.filter(text)
        return sanitized, detections, bool(detections)

    def get_pattern_count(self) -> int:
        return self.pattern_matcher.get_pattern_count()

    def add_custom_pattern(
        self,
        category: str,
        name: str,
        pattern: str,
        threat_level: ThreatLevel = ThreatLevel.MEDIUM,
    ) -> None:
        self.pattern_matcher.add_custom_pattern(category, name, pattern, threat_level)

    # ---- Private helpers ---------------------------------------------------

    def _decide(
        self, confidence: float, max_level: ThreatLevel, threats: list[ThreatInfo]
    ) -> EntropyStatus:
        if not threats:
            return EntropyStatus.ALLOWED
        level_prio = _LEVEL_PRIORITY.get(max_level, 0)
        if level_prio >= _LEVEL_PRIORITY[ThreatLevel.HIGH] and confidence > 0.4:
            return EntropyStatus.BLOCKED
        if level_prio == _LEVEL_PRIORITY[ThreatLevel.MEDIUM]:
            if confidence >= self._threshold and self._block:
                return EntropyStatus.BLOCKED
            return EntropyStatus.SANITIZED
        return EntropyStatus.ALLOWED

    def _build_verdict(
        self,
        status: EntropyStatus,
        confidence: float,
        threats: list[ThreatInfo],
        start_time: float,
        input_valid: bool,
    ) -> EntropyVerdict:
        enriched = []
        for threat in threats:
            if threat.suggestion is None:
                threat.suggestion = _generate_suggestion(threat)
            enriched.append(threat)
        overall = None
        if enriched:
            primary = max(enriched, key=lambda t: _LEVEL_PRIORITY.get(t.threat_level, 0))
            overall = _generate_suggestion(primary)
        return EntropyVerdict(
            status=status,
            confidence=round(confidence, 3),
            threats_detected=enriched,
            processing_time_ms=self._elapsed_ms(start_time),
            input_valid=input_valid,
            suggestion=overall,
        )

    @staticmethod
    def _extract_text(request: ChatCompletionRequest) -> str:
        parts: list[str] = []
        for msg in request.messages:
            if isinstance(msg.content, str):
                parts.append(msg.content)
            elif isinstance(msg.content, list):
                for item in msg.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        parts.append(item.get("text", ""))
        return "\n".join(parts)

    @staticmethod
    def _elapsed_ms(start: float) -> float:
        return round((time.perf_counter() - start) * 1000, 2)
