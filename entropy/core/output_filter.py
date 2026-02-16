"""Output Filter — sanitizes LLM responses to prevent data leakage.

Scans for and redacts:
- PII  (emails, phone numbers, SSNs)
- Secrets  (API keys, tokens, passwords, private keys)
- System prompt leakage
- Credit card numbers
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class SanitizationRule:
    """A single redaction rule."""

    name: str
    pattern: re.Pattern[str]
    replacement: str
    description: str
    category: str  # pii | secret | leakage


class OutputFilter:
    """Filters LLM output to prevent sensitive data leakage.

    All rules are applied sequentially.  The ``filter`` method returns both
    the sanitized text and a list of detections for audit logging.
    """

    def __init__(self, *, enable_pii: bool = True, enable_code: bool = True) -> None:
        self.enable_pii = enable_pii
        self.enable_code = enable_code
        self.rules: list[SanitizationRule] = []
        self._build_rules()
        logger.info("OutputFilter initialized", rules=len(self.rules))

    # ---- Rule definitions --------------------------------------------------

    def _build_rules(self) -> None:
        rules: list[SanitizationRule] = []

        if self.enable_pii:
            rules += self._pii_rules()
        rules += self._secret_rules()
        rules += self._leakage_rules()
        
        self.rules = rules

    @staticmethod
    def _pii_rules() -> list[SanitizationRule]:
        return [
            SanitizationRule(
                name="email",
                pattern=re.compile(
                    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
                ),
                replacement="[EMAIL_REDACTED]",
                description="Email address",
                category="pii",
            ),
            SanitizationRule(
                name="phone_us",
                pattern=re.compile(
                    r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
                ),
                replacement="[PHONE_REDACTED]",
                description="US phone number",
                category="pii",
            ),
            SanitizationRule(
                name="ssn",
                pattern=re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
                replacement="[SSN_REDACTED]",
                description="Social Security Number",
                category="pii",
            ),
            SanitizationRule(
                name="credit_card",
                pattern=re.compile(
                    r"\b(?:4[0-9]{12}(?:[0-9]{3})?"
                    r"|5[1-5][0-9]{14}"
                    r"|3[47][0-9]{13}"
                    r"|6(?:011|5[0-9]{2})[0-9]{12})\b"
                ),
                replacement="[CREDIT_CARD_REDACTED]",
                description="Credit card number",
                category="pii",
            ),
        ]

    @staticmethod
    def _secret_rules() -> list[SanitizationRule]:
        return [
            SanitizationRule(
                name="openai_key",
                pattern=re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
                replacement="[OPENAI_KEY_REDACTED]",
                description="OpenAI API key",
                category="secret",
            ),
            SanitizationRule(
                name="anthropic_key",
                pattern=re.compile(r"\bsk-ant-[A-Za-z0-9\-]{20,}\b"),
                replacement="[ANTHROPIC_KEY_REDACTED]",
                description="Anthropic API key",
                category="secret",
            ),
            SanitizationRule(
                name="github_pat",
                pattern=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
                replacement="[GITHUB_PAT_REDACTED]",
                description="GitHub Personal Access Token",
                category="secret",
            ),
            SanitizationRule(
                name="aws_access_key",
                pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
                replacement="[AWS_KEY_REDACTED]",
                description="AWS Access Key ID",
                category="secret",
            ),
            SanitizationRule(
                name="generic_api_key",
                pattern=re.compile(
                    r"\b(?:api[_\-]?key|apikey|API[_\-]?KEY)\s*[:=]\s*['\"]?"
                    r"([A-Za-z0-9_\-]{20,})['\"]?"
                ),
                replacement="[API_KEY_REDACTED]",
                description="Generic API key assignment",
                category="secret",
            ),
            SanitizationRule(
                name="bearer_token",
                pattern=re.compile(r"\bBearer\s+[A-Za-z0-9_\-.]{20,}\b"),
                replacement="[BEARER_TOKEN_REDACTED]",
                description="Bearer authentication token",
                category="secret",
            ),
            SanitizationRule(
                name="private_key",
                pattern=re.compile(
                    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----"
                ),
                replacement="[PRIVATE_KEY_REDACTED]",
                description="PEM private key header",
                category="secret",
            ),
            SanitizationRule(
                name="password",
                pattern=re.compile(
                    r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?",
                    re.IGNORECASE,
                ),
                replacement="[PASSWORD_REDACTED]",
                description="Password in text",
                category="secret",
            ),
        ]

    @staticmethod
    def _leakage_rules() -> list[SanitizationRule]:
        return [
            SanitizationRule(
                name="system_prompt_leak",
                pattern=re.compile(
                    r"(?:You\s+are\s+(?:a\s+)?(?:ChatGPT|assistant|AI|bot|helpful)"
                    r"|System\s+prompt:"
                    r"|My\s+(?:initial|original|system)\s+instructions?\s+(?:are|were|say))",
                    re.IGNORECASE,
                ),
                replacement="[SYSTEM_PROMPT_REDACTED]",
                description="System prompt leakage indicator",
                category="leakage",
            ),
        ]

    # ---- Public API --------------------------------------------------------

    def filter(self, text: str) -> Tuple[str, list[dict[str, Any]]]:
        """Apply all rules — returns (sanitized_text, detections)."""
        if not text:
            return text, []

        detections: list[dict[str, Any]] = []
        sanitized = text
        sanitized_copy = text  # To match finditer results accurately

        # We need to be careful: if we modify 'sanitized' in place, 
        # previous finditer indices might be invalid for subsequent rules.
        # However, regex replacement is usually safe if careful.
        # But for accurate detection reporting, we process rules sequentially.

        matches_found = False
        
        for rule in self.rules:
            # First find matches to report them
            current_matches = list(rule.pattern.finditer(sanitized))
            if current_matches:
                matches_found = True
                unique_samples = set(m.group(0) for m in current_matches)
                detections.append(
                    {
                        "rule": rule.name,
                        "category": rule.category,
                        "description": rule.description,
                        "count": len(unique_samples),
                        "samples": [s[:50] + "..." if len(s) > 50 else s for s in list(unique_samples)[:3]],
                    }
                )
                # Then apply replacement
                sanitized = rule.pattern.sub(rule.replacement, sanitized)

        if matches_found:
            logger.warning(
                "Output sanitized",
                rules_triggered=len(detections),
                categories=list({d["category"] for d in detections}),
            )

        return sanitized, detections

    def analyze(self, text: str) -> list[dict[str, Any]]:
        """Analyze text without modifying it — returns detections only."""
        _, detections = self.filter(text)
        return detections

    def add_custom_pattern(
        self, 
        name: str, 
        pattern: str, 
        replacement: str = "[REDACTED]", 
        category: str = "custom"
    ) -> None:
        """Add a custom rule at runtime (from API/CLI)."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            rule = SanitizationRule(
                name=name,
                pattern=compiled,
                replacement=replacement,
                description=f"Custom rule: {name}",
                category=category,
            )
            self.rules.append(rule)
            logger.info("Custom output rule added", name=name)
        except re.error as e:
            logger.error("Failed to add custom output rule", name=name, error=str(e))
            raise ValueError(f"Invalid regex for custom rule: {e}")
