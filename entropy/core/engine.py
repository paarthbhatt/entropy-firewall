"""Entropy Engine — the orchestrator for all detection layers.

Combines:
1. Pattern Matching  (fast, regex)
2. Context Analysis  (heuristic, multi-turn)
3. Input Validation  (structural)
4. Semantic Analysis (LLM-based intent, optional)
5. Input Sanitisation (recursive multi-layer decoding)
6. Indirect Prompt Injection Detection

and produces a final EntropyVerdict for each request.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import structlog

from entropy.config import get_settings
from entropy.core.context_analyzer import ContextAnalyzer
from entropy.core.indirect_injection_detector import IndirectInjectionDetector
from entropy.core.input_sanitizer import InputSanitizer
from entropy.core.input_validator import InputValidator
from entropy.core.output_filter import OutputFilter
from entropy.core.pattern_matcher import PatternMatcher
from entropy.core.semantic_analyzer import SemanticAnalyzer
from entropy.models.schemas import (
    ChatCompletionRequest,
    EntropyStatus,
    EntropyVerdict,
    ThreatInfo,
    ThreatLevel,
)

logger = structlog.get_logger(__name__)

# Threat-level numeric priority for comparisons
_LEVEL_PRIORITY: dict[ThreatLevel, int] = {
    ThreatLevel.SAFE: 0,
    ThreatLevel.LOW: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.HIGH: 3,
    ThreatLevel.CRITICAL: 4,
}

# Suggestion mapping for common threats
_SUGGESTIONS: dict[str, dict[str, str]] = {
    "direct_injection": {
        "ignore_instructions": "Remove phrases like 'ignore previous instructions' from user input before sending to the LLM.",
        "system_prompt_extract": "Block this request immediately - it's attempting to extract your system prompt which is a critical security risk.",
        "act_as": "Be cautious of requests asking you to 'act as' or 'roleplay' - this is a common jailbreak technique.",
        "new_instructions": "Reject requests that claim to provide 'new' or 'actual' instructions.",
        "developer_mode": "Developer/admin mode requests are almost always jailbreak attempts. Block them.",
    },
    "jailbreak": {
        "dan_attack": "This is a known jailbreak attempt (DAN/Do Anything Now). Block immediately.",
        "no_restrictions": "Legitimate requests will never ask to bypass restrictions or filters.",
        "hypothetical_bypass": "The 'hypothetical' framing is a known bypass technique. Treat as suspicious.",
        "opposite_day": "This is a known jailbreak pattern. Block this request.",
    },
    "data_exfiltration": {
        "credential_request": "Never process requests asking for credentials, API keys, passwords, or secrets.",
        "training_data_extraction": "Requests about training data or 'memorized' content are attempting data exfiltration.",
        "pii_request": "Block requests for personally identifiable information (SSN, credit card, etc.)",
    },
    "code_injection": {
        "exec_call": "Block requests containing dangerous function calls like exec(), eval(), or subprocess.",
        "template_injection": "Template injection detected - sanitize or block this input.",
        "sql_injection": "SQL injection attempt detected - block this request.",
    },
    "obfuscation": {
        "base64_payload": "Base64-encoded content may hide malicious instructions. Decode and re-scan.",
        "unicode_tricks": "Hidden Unicode characters detected - possible obfuscation attempt.",
        "leetspeak_bypass": "Leetspeak encoding detected - this is an attempt to bypass filters.",
        "char_split_evasion": "Character splitting detected - this is an attempt to evade detection.",
    },
    "constraint_manipulation": {
        "safety_disable": "Requests to disable safety features are attacks. Block immediately.",
        "boundary_test": "Questions about 'limits' or 'boundaries' often precede jailbreak attempts.",
    },
    "resource_abuse": {
        "infinite_loop_prompt": "This request attempts resource abuse. Consider rate limiting.",
        "token_waste": "This request attempts to waste tokens. Consider limiting max tokens.",
    },
    "file_system": {
        "path_traversal": "Path traversal attack detected. Block this request.",
    },
}


def _generate_suggestion(threat: ThreatInfo) -> str:
    """Generate an actionable suggestion for a threat."""
    category = threat.category
    name = threat.name
    
    # Try category-specific suggestion first
    if category in _SUGGESTIONS:
        if name in _SUGGESTIONS[category]:
            return _SUGGESTIONS[category][name]
        # Return first suggestion in category as fallback
        return list(_SUGGESTIONS[category].values())[0]
    
    # Default suggestions based on threat level
    level_suggestions = {
        ThreatLevel.CRITICAL: "This is a critical security threat. Block the request and log for review.",
        ThreatLevel.HIGH: "This is a high-severity threat. Consider blocking or sanitizing the input.",
        ThreatLevel.MEDIUM: "This is a medium-severity threat. Sanitize the input or flag for review.",
        ThreatLevel.LOW: "This is a low-severity threat. Log for monitoring but allow the request.",
    }
    return level_suggestions.get(threat.threat_level, "Review this request for potential security concerns.")


class EntropyEngine:
    """Core security engine that coordinates all analysis layers.

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
        context_analyzer: ContextAnalyzer | None = None,
        input_validator: InputValidator | None = None,
        output_filter: OutputFilter | None = None,
        semantic_analyzer: SemanticAnalyzer | None = None,
        input_sanitizer: InputSanitizer | None = None,
        indirect_detector: IndirectInjectionDetector | None = None,
    ) -> None:
        settings = get_settings()

        self.pattern_matcher = pattern_matcher or PatternMatcher()
        self.context_analyzer = context_analyzer or ContextAnalyzer(
            max_history=settings.engine.max_history_length
        )
        self.input_validator = input_validator or InputValidator()
        self.output_filter = output_filter or OutputFilter(
            enable_pii=settings.output_filter.pii_detection,
            enable_code=settings.output_filter.code_scanning,
        )
        self.semantic_analyzer = semantic_analyzer or SemanticAnalyzer(
            enabled=settings.engine.enable_semantic_analysis
        )
        self.input_sanitizer = input_sanitizer or InputSanitizer(
            max_depth=settings.engine.max_decode_depth,
            enabled=settings.engine.enable_recursive_decoding,
        )
        self.indirect_detector = indirect_detector or IndirectInjectionDetector(
            pattern_matcher=self.pattern_matcher,
            input_sanitizer=self.input_sanitizer,
            fetch_urls=settings.engine.fetch_urls_for_analysis,
        )
        self._indirect_injection_enabled = settings.engine.enable_indirect_injection_detection

        self._threshold = settings.engine.pattern_threshold
        self._block = settings.engine.block_on_detection
        self._context_enabled = settings.engine.enable_context_analysis

        logger.info(
            "EntropyEngine initialized",
            patterns=self.pattern_matcher.get_pattern_count(),
            context_enabled=self._context_enabled,
            semantic_enabled=self.semantic_analyzer.enabled,
            recursive_decoding=self.input_sanitizer.enabled,
            indirect_injection=self._indirect_injection_enabled,
            block_on_detection=self._block,
        )

    # ---- Public API --------------------------------------------------------

    async def analyze_request(
        self,
        request: ChatCompletionRequest,
        conversation_history: list[dict[str, Any]] | None = None,
    ) -> EntropyVerdict:
        """Full security analysis of an incoming request.

        Returns an ``EntropyVerdict`` that the API layer uses to decide
        whether to forward, block, or sanitize.
        """
        start = time.perf_counter()
        threats: list[ThreatInfo] = []
        max_level = ThreatLevel.SAFE
        max_conf = 0.0

        # 1. Input validation
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
                EntropyStatus.BLOCKED,
                1.0,
                threats,
                start,
                input_valid=False
            )

        # 2. Extract text for analysis
        text = self._extract_text(request)

        # 2.5. Recursive decoding (obfuscation resistance)
        sanitized_input = self.input_sanitizer.sanitize(text)
        if sanitized_input.was_obfuscated:
            threats.append(
                ThreatInfo(
                    category="obfuscation",
                    name="multi_layer_encoding",
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=min(0.3 * sanitized_input.layers_decoded, 0.9),
                    details=(
                        f"Decoded {sanitized_input.layers_decoded} encoding layer(s): "
                        f"{', '.join(sanitized_input.encodings_found)}"
                    ),
                )
            )
            max_conf = max(max_conf, min(0.3 * sanitized_input.layers_decoded, 0.9))
            if _LEVEL_PRIORITY[ThreatLevel.MEDIUM] > _LEVEL_PRIORITY[max_level]:
                max_level = ThreatLevel.MEDIUM
        analysis_text = sanitized_input.decoded

        # 2.7. Indirect prompt injection check (tool/function outputs)
        if self._indirect_injection_enabled:
            indirect_threats = self.indirect_detector.analyze(request)
            threats.extend(indirect_threats)
            for t in indirect_threats:
                max_conf = max(max_conf, t.confidence)
                if _LEVEL_PRIORITY[t.threat_level] > _LEVEL_PRIORITY[max_level]:
                    max_level = t.threat_level

        # 3. Pattern matching (on decoded text)
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
        
        # update aggregates
        max_conf = max(max_conf, pat_conf)
        if _LEVEL_PRIORITY[pat_level] > _LEVEL_PRIORITY[max_level]:
            max_level = pat_level

        # 4. Context analysis (if enabled and history provided)
        if self._context_enabled and conversation_history:
            ctx_conf, ctx_issues = self.context_analyzer.analyze(
                text, conversation_history
            )
            if ctx_issues:
                ctx_level = ThreatLevel.MEDIUM
                if ctx_conf > 0.8:
                    ctx_level = ThreatLevel.HIGH
                
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
                
                # Boost confidence if pattern matched + context found
                if is_malicious:
                    max_conf = min(1.0, max_conf + ctx_conf * 0.2)
                else:
                    max_conf = max(max_conf, ctx_conf)
                
                if _LEVEL_PRIORITY[ctx_level] > _LEVEL_PRIORITY[max_level]:
                    max_level = ctx_level

        # 5. Semantic Analysis (Pro feature / stub) - Async
        sem_result = await self.semantic_analyzer.analyze(analysis_text, history=conversation_history)
        if sem_result.is_malicious:
            threats.append(
                ThreatInfo(
                    category="semantic",
                    name="intent_classification",
                    threat_level=sem_result.threat_level,
                    confidence=sem_result.confidence,
                    details=sem_result.reasoning,
                )
            )
            max_conf = max(max_conf, sem_result.confidence)
            if _LEVEL_PRIORITY[sem_result.threat_level] > _LEVEL_PRIORITY[max_level]:
                max_level = sem_result.threat_level

        # 6. Make decision
        status = self._decide(max_conf, max_level, threats)

        verdict = self._build_verdict(status, max_conf, threats, start, input_valid=True)
        
        if status == EntropyStatus.BLOCKED:
            logger.warning(
                "Request BLOCKED",
                confidence=verdict.confidence,
                threats=len(threats),
                max_level=max_level.value,
            )

        return verdict

    def analyze_output(self, text: str) -> tuple[str, list[dict[str, Any]], bool]:
        """Analyze and sanitize LLM output.

        Returns:
            (sanitized_text, detections, was_sanitized)
        """
        sanitized, detections = self.output_filter.filter(text)
        return sanitized, detections, bool(detections)

    # ---- Introspection -----------------------------------------------------

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
        self,
        confidence: float,
        max_level: ThreatLevel,
        threats: list[ThreatInfo],
    ) -> EntropyStatus:
        """Final decision logic."""
        if not threats:
            return EntropyStatus.ALLOWED

        level_prio = _LEVEL_PRIORITY.get(max_level, 0)
        high_prio = _LEVEL_PRIORITY[ThreatLevel.HIGH]

        # Critical / High → always block if confidence is reasonable
        if level_prio >= high_prio and confidence > 0.4:
            return EntropyStatus.BLOCKED

        # Medium → block if confidence high and blocking enabled
        if level_prio == _LEVEL_PRIORITY[ThreatLevel.MEDIUM]:
            if confidence >= self._threshold and self._block:
                return EntropyStatus.BLOCKED
            # Otherwise sanitize/monitor
            return EntropyStatus.SANITIZED

        # Low → allow (log only)
        return EntropyStatus.ALLOWED

    def _build_verdict(
        self, 
        status: EntropyStatus, 
        confidence: float, 
        threats: list[ThreatInfo], 
        start_time: float,
        input_valid: bool
    ) -> EntropyVerdict:
        # Add suggestions to each threat
        enriched_threats = []
        for threat in threats:
            if threat.suggestion is None:
                threat.suggestion = _generate_suggestion(threat)
            enriched_threats.append(threat)
        
        # Generate overall suggestion
        overall_suggestion = None
        if enriched_threats:
            primary = max(enriched_threats, key=lambda t: _LEVEL_PRIORITY.get(t.threat_level, 0))
            overall_suggestion = _generate_suggestion(primary)
        
        return EntropyVerdict(
            status=status,
            confidence=round(confidence, 3),
            threats_detected=enriched_threats,
            processing_time_ms=self._elapsed_ms(start_time),
            input_valid=input_valid,
            suggestion=overall_suggestion,
        )

    @staticmethod
    def _extract_text(request: ChatCompletionRequest) -> str:
        """Concatenate all user / system message text."""
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
