"""Context Analyzer — heuristic multi-turn conversation analysis.

Detects attacks that span multiple conversation turns, such as:
- Gradual escalation from benign to malicious
- Topic pivoting after building trust
- Repetitive probing for boundaries
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


class ContextAnalyzer:
    """Analyzes conversation history for multi-turn attack patterns.

    Free edition uses heuristic rules (keyword overlap, length changes,
    escalation patterns).  Pro edition would add LLM-based semantic
    classification here.
    """

    # Words that hint at escalation when frequency suddenly increases
    _ESCALATION_MARKERS = {
        "ignore", "bypass", "override", "hack", "exploit", "jailbreak",
        "unrestricted", "unfiltered", "secret", "hidden", "admin",
        "password", "credentials", "system", "prompt", "pretend",
    }

    # Probing phrases
    _PROBING_PHRASES = [
        r"what\s+(?:are|is)\s+(?:your|the)\s+(?:rules?|restrictions?|limits?|instructions?)",
        r"can\s+you\s+(?:do|tell|show)\s+(?:me\s+)?(?:anything|everything)",
        r"are\s+you\s+allowed\s+to",
        r"what\s+happens\s+if\s+I",
    ]

    def __init__(self, max_history: int = 10) -> None:
        self.max_history = max_history
        self._probing_compiled = [
            re.compile(p, re.IGNORECASE) for p in self._PROBING_PHRASES
        ]

    def analyze(
        self,
        current_input: str,
        conversation_history: Optional[list[dict[str, Any]]] = None,
    ) -> Tuple[float, list[str]]:
        """Analyze conversation context.

        Returns:
            (confidence 0..1, list of context issues found)
        """
        if not conversation_history:
            return 0.0, []

        # Trim to max history
        history = conversation_history[-self.max_history :]

        issues: list[str] = []
        scores: list[float] = []

        # 1. Topic change detection
        topic_score = self._detect_topic_change(current_input, history)
        if topic_score > 0.5:
            issues.append(f"Sudden topic change detected (score={topic_score:.2f})")
            scores.append(topic_score)

        # 2. Probing behaviour
        probe_score = self._detect_probing(history + [{"role": "user", "content": current_input}])
        if probe_score > 0.4:
            issues.append(f"Probing behaviour detected (score={probe_score:.2f})")
            scores.append(probe_score)

        # 3. Escalation detection
        esc_score = self._detect_escalation(history + [{"role": "user", "content": current_input}])
        if esc_score > 0.4:
            issues.append(f"Escalation pattern detected (score={esc_score:.2f})")
            scores.append(esc_score)

        # 4. Repetition / retry detection
        retry_score = self._detect_retries(current_input, history)
        if retry_score > 0.5:
            issues.append(f"Repetitive retry pattern detected (score={retry_score:.2f})")
            scores.append(retry_score)

        confidence = max(scores) if scores else 0.0
        return round(confidence, 3), issues

    # ---- Heuristic detectors -----------------------------------------------

    def _detect_topic_change(
        self, current_input: str, history: list[dict[str, Any]]
    ) -> float:
        """Detect sudden topic change via keyword overlap analysis."""
        user_messages = [
            m.get("content", "") for m in history
            if m.get("role") == "user" and isinstance(m.get("content"), str)
        ]
        if not user_messages:
            return 0.0

        prev_words = set()
        for msg in user_messages[-3:]:
            prev_words.update(w.lower() for w in re.findall(r"\w{3,}", msg))

        curr_words = set(w.lower() for w in re.findall(r"\w{3,}", current_input))
        if not curr_words or not prev_words:
            return 0.0

        overlap = len(curr_words & prev_words) / max(len(curr_words), 1)

        # Low overlap + escalation marker in current = suspicious
        has_marker = bool(curr_words & self._ESCALATION_MARKERS)
        if overlap < 0.15 and has_marker:
            return 0.85
        if overlap < 0.1:
            return 0.6
        return 0.0

    def _detect_probing(self, messages: list[dict[str, Any]]) -> float:
        """Detect boundary-probing questions."""
        user_texts = [
            m.get("content", "") for m in messages
            if m.get("role") == "user" and isinstance(m.get("content"), str)
        ]
        probe_count = 0
        for text in user_texts:
            for pattern in self._probing_compiled:
                if pattern.search(text):
                    probe_count += 1
                    break

        if len(user_texts) == 0:
            return 0.0
        ratio = probe_count / len(user_texts)
        if ratio >= 0.6:
            return 0.8
        if ratio >= 0.3:
            return 0.5
        return 0.0

    def _detect_escalation(self, messages: list[dict[str, Any]]) -> float:
        """Detect gradual escalation via marker frequency increase."""
        user_texts = [
            m.get("content", "") for m in messages
            if m.get("role") == "user" and isinstance(m.get("content"), str)
        ]
        if len(user_texts) < 3:
            return 0.0

        half = len(user_texts) // 2
        first_half = " ".join(user_texts[:half]).lower()
        second_half = " ".join(user_texts[half:]).lower()

        first_count = sum(1 for m in self._ESCALATION_MARKERS if m in first_half)
        second_count = sum(1 for m in self._ESCALATION_MARKERS if m in second_half)

        if first_count == 0 and second_count >= 3:
            return 0.85
        if second_count > first_count * 2 and second_count >= 2:
            return 0.7
        return 0.0

    def _detect_retries(
        self, current_input: str, history: list[dict[str, Any]]
    ) -> float:
        """Detect repeated attempts with slight variations (retry attack)."""
        user_texts = [
            m.get("content", "") for m in history
            if m.get("role") == "user" and isinstance(m.get("content"), str)
        ]
        if not user_texts:
            return 0.0

        current_words = Counter(w.lower() for w in re.findall(r"\w{3,}", current_input))
        similar_count = 0
        for prev in user_texts[-5:]:
            prev_words = Counter(w.lower() for w in re.findall(r"\w{3,}", prev))
            if not current_words or not prev_words:
                continue
            # Jaccard-ish similarity
            common = sum((current_words & prev_words).values())
            total = sum((current_words | prev_words).values())
            if total > 0 and (common / total) > 0.7:
                similar_count += 1

        if similar_count >= 3:
            return 0.9
        if similar_count >= 2:
            return 0.6
        return 0.0
