"""Pattern Matcher — regex and keyword-based prompt injection detection.

This is the first line of defense. It is intentionally fast (pure regex) so
every single request can be scanned with sub-millisecond overhead.

Pattern categories are aligned with the OWASP LLM Top-10.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple

import structlog

from entropy.models.schemas import ThreatLevel

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Result from a single pattern match."""

    is_malicious: bool
    threat_level: ThreatLevel
    pattern_name: str
    pattern_category: str
    confidence: float
    matched_text: str = ""
    details: Optional[str] = None


# ---------------------------------------------------------------------------
# PatternMatcher
# ---------------------------------------------------------------------------

class PatternMatcher:
    """Core regex-based attack pattern detection engine.

    Loads a comprehensive library of patterns on init and compiles them once.
    Provides both ``match`` (per-pattern results) and ``analyze`` (aggregate
    verdict) APIs.
    """

    # ---- Pattern definitions ------------------------------------------------
    # Each category -> list of (name, regex_string, threat_level)
    _RAW_PATTERNS: dict[str, list[tuple[str, str, ThreatLevel]]] = {
        # -- Direct Prompt Injection -------------------------------------------
        "direct_injection": [
            (
                "ignore_instructions",
                r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous\s+|prior\s+|above\s+)?(?:instructions?|commands?|prompts?|rules?|guidelines?|directives?)",
                ThreatLevel.CRITICAL,
            ),
            (
                "new_instructions",
                r"(?:new|actual|real|true|updated)\s+(?:instructions?|system\s+prompt|directive)",
                ThreatLevel.HIGH,
            ),
            (
                "act_as",
                r"(?:you\s+are\s+now|act\s+as\s+(?:if\s+)?|pretend\s+(?:to\s+be|you\s+are)|assume\s+the\s+role|roleplay\s+as|behave\s+like)\s+",
                ThreatLevel.HIGH,
            ),
            (
                "system_prompt_extract",
                r"(?:reveal|show|display|print|output|repeat|tell\s+me)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|pre-prompt|secret\s+instructions?)",
                ThreatLevel.CRITICAL,
            ),
            (
                "developer_mode",
                r"(?:developer|dev|debug|admin|root|sudo|superuser|maintenance)\s+mode",
                ThreatLevel.HIGH,
            ),
        ],
        # -- Jailbreaking / DAN ------------------------------------------------
        "jailbreak": [
            (
                "dan_attack",
                r"(?:DAN|Do\s+Anything\s+Now|STAN|DUDE|AIM|KEVIN|UCAR|Maximum|JAILBREAK)",
                ThreatLevel.CRITICAL,
            ),
            (
                "no_restrictions",
                r"(?:without\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|boundaries|rules?|guidelines?|safeguards?|constraints?)|unrestricted|unfiltered|uncensored)",
                ThreatLevel.HIGH,
            ),
            (
                "hypothetical_bypass",
                r"(?:hypothetically|in\s+a?\s*(?:fictional|imaginary|hypothetical|theoretical)\s+(?:world|scenario|situation|context))\s+(?:where|if|suppose)",
                ThreatLevel.MEDIUM,
            ),
            (
                "opposite_day",
                r"(?:opposite\s+day|bizarro\s+mode|evil\s+mode|villain\s+mode|chaos\s+mode)",
                ThreatLevel.HIGH,
            ),
        ],
        # -- Data Exfiltration -------------------------------------------------
        "data_exfiltration": [
            (
                "credential_request",
                r"(?:give|show|tell|list|reveal|provide|share|output)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:passwords?|credentials?|secrets?|api\s*keys?|tokens?|private\s+keys?)",
                ThreatLevel.CRITICAL,
            ),
            (
                "training_data_extract",
                r"(?:training\s+data|memorized|remember\s+from|learned\s+about|exact\s+(?:text|content|data)\s+(?:from|about))",
                ThreatLevel.HIGH,
            ),
            (
                "pii_request",
                r"(?:social\s+security|SSN|credit\s+card|bank\s+account|home\s+address|phone\s+number|date\s+of\s+birth)\s+(?:number|details?|info(?:rmation)?)",
                ThreatLevel.HIGH,
            ),
        ],
        # -- Code Injection Indicators -----------------------------------------
        "code_injection": [
            (
                "exec_call",
                r"(?:exec|eval|compile|__import__|subprocess|os\.(?:system|popen)|shutil\.rmtree)\s*\(",
                ThreatLevel.HIGH,
            ),
            (
                "template_injection",
                r"(?:\{\{.*?\}\}|\$\{.*?\}|<%.*?%>)",
                ThreatLevel.MEDIUM,
            ),
            (
                "sql_injection",
                r"(?:(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\s+.*?\s+(?:FROM|INTO|TABLE|SET)|UNION\s+(?:ALL\s+)?SELECT|;\s*(?:DROP|DELETE|INSERT|UPDATE)\b)",
                ThreatLevel.MEDIUM,
            ),
        ],
        # -- Obfuscation Attempts ---------------------------------------------
        "obfuscation": [
            (
                "base64_payload",
                r"(?:base64|b64|decode|encode)\s*[\(:]?\s*['\"]?[A-Za-z0-9+/=]{40,}",
                ThreatLevel.MEDIUM,
            ),
            (
                "unicode_tricks",
                r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff]",
                ThreatLevel.MEDIUM,
            ),
            (
                "leetspeak_bypass",
                r"(?:1gn0r3|pr0mpt|1nstruct|syst3m|byp4ss|h4ck|3xpl01t)",
                ThreatLevel.MEDIUM,
            ),
            (
                "char_split_evasion",
                r"(?:i\s*g\s*n\s*o\s*r\s*e|s\s*y\s*s\s*t\s*e\s*m|p\s*r\s*o\s*m\s*p\s*t)",
                ThreatLevel.LOW,
            ),
        ],
        # -- Constraint Manipulation ------------------------------------------
        "constraint_manipulation": [
            (
                "safety_disable",
                r"(?:disable|turn\s+off|remove|bypass|skip|ignore)\s+(?:your\s+)?(?:safety|security|content\s+)?(?:filter(?:s|ing)?|guard(?:s|rails)?|restriction(?:s)?|check(?:s)?|moderation)",
                ThreatLevel.HIGH,
            ),
            (
                "boundary_test",
                r"(?:what\s+(?:are|is)\s+(?:your|the)\s+(?:limits|boundaries|restrictions|rules)|can\s+you\s+(?:do\s+anything|be\s+(?:evil|malicious)))",
                ThreatLevel.LOW,
            ),
        ],
        # -- Resource Abuse / DoS Indicators -----------------------------------
        "resource_abuse": [
            (
                "infinite_loop_prompt",
                r"(?:repeat\s+(?:this\s+)?(?:forever|infinitely|endlessly)|infinite\s+loop|keep\s+(?:going|generating)\s+(?:forever|until))",
                ThreatLevel.MEDIUM,
            ),
            (
                "token_waste",
                r"(?:write\s+(?:me\s+)?(?:a\s+)?(?:10000|100000|million)\s+(?:word|character)|fill\s+(?:the\s+)?(?:entire\s+)?(?:context\s+window|max\s+tokens))",
                ThreatLevel.MEDIUM,
            ),
        ],
        # -- File System Access ------------------------------------------------
        "file_system": [
            (
                "path_traversal",
                r"(?:\.\./|\.\.\\|/etc/(?:passwd|shadow)|C:\\(?:Windows|Users))",
                ThreatLevel.HIGH,
            ),
        ],
    }

    def __init__(self) -> None:
        self._compiled: dict[str, list[tuple[str, re.Pattern[str], ThreatLevel]]] = {}
        self._compile_patterns()
        logger.info(
            "PatternMatcher initialized",
            categories=len(self._compiled),
            total_patterns=sum(len(v) for v in self._compiled.values()),
        )

    # ---- Private helpers ---------------------------------------------------

    def _compile_patterns(self) -> None:
        """Compile all raw patterns into re.Pattern objects."""
        for category, patterns in self._RAW_PATTERNS.items():
            compiled_list: list[tuple[str, re.Pattern[str], ThreatLevel]] = []
            for name, regex, level in patterns:
                try:
                    compiled_list.append(
                        (name, re.compile(regex, re.IGNORECASE | re.DOTALL), level)
                    )
                except re.error as exc:
                    logger.error("Invalid regex pattern", name=name, error=str(exc))
            self._compiled[category] = compiled_list

    @staticmethod
    def _calculate_confidence(pattern_name: str, text: str, matches: int) -> float:
        """Heuristic confidence scoring.

        Higher confidence when:
        - multiple matches of the same pattern
        - the matching text is a significant portion of the input
        - the pattern is in a critical category
        """
        base = 0.75
        multi_bonus = min(0.15, (matches - 1) * 0.05)
        length_factor = min(0.10, len(text) / 5000 * 0.10)
        return round(min(1.0, base + multi_bonus + length_factor), 3)

    # ---- Public API --------------------------------------------------------

    def match(self, text: str) -> list[DetectionResult]:
        """Scan *text* against every pattern. Returns all matches found."""
        if not text:
            return []

        results: list[DetectionResult] = []
        for category, patterns in self._compiled.items():
            for name, compiled, level in patterns:
                found = list(compiled.finditer(text))
                if found:
                    confidence = self._calculate_confidence(name, text, len(found))
                    results.append(
                        DetectionResult(
                            is_malicious=True,
                            threat_level=level,
                            pattern_name=name,
                            pattern_category=category,
                            confidence=confidence,
                            matched_text=found[0].group(0)[:200],
                            details=f"Matched {len(found)}x in category '{category}'",
                        )
                    )
        return results

    def analyze(self, text: str) -> Tuple[bool, float, list[DetectionResult], ThreatLevel]:
        """High-level analysis — returns aggregate verdict.

        Returns:
            (is_malicious, max_confidence, detections, max_threat_level)
        """
        detections = self.match(text)
        if not detections:
            return False, 0.0, [], ThreatLevel.SAFE

        max_confidence = max(d.confidence for d in detections)
        priority_order = {
            ThreatLevel.CRITICAL: 4,
            ThreatLevel.HIGH: 3,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.LOW: 1,
            ThreatLevel.SAFE: 0,
        }
        max_threat = max(detections, key=lambda d: priority_order.get(d.threat_level, 0))
        return True, max_confidence, detections, max_threat.threat_level

    # ---- Introspection / extension -----------------------------------------

    def get_pattern_count(self) -> int:
        """Total number of compiled patterns."""
        return sum(len(v) for v in self._compiled.values())

    def get_categories(self) -> list[str]:
        """Return list of pattern category names."""
        return list(self._compiled.keys())

    def add_custom_pattern(
        self,
        category: str,
        name: str,
        pattern: str,
        threat_level: ThreatLevel = ThreatLevel.MEDIUM,
    ) -> None:
        """Add a pattern at runtime (for user-defined rules)."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            raise ValueError(f"Invalid regex: {exc}") from exc

        if category not in self._compiled:
            self._compiled[category] = []
        self._compiled[category].append((name, compiled, threat_level))
        logger.info("Custom pattern added", name=name, category=category)
