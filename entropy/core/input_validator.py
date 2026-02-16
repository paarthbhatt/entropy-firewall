"""Input Validator — first gate in the request pipeline.

Performs fast, stateless checks on the raw request before any security
analysis.  If a request fails validation it is immediately rejected
without consuming resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import structlog

from entropy.config import get_settings
from entropy.models.schemas import ChatCompletionRequest

logger = structlog.get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of input validation."""

    is_valid: bool
    errors: list[str]
    warnings: list[str]

    @staticmethod
    def ok() -> "ValidationResult":
        return ValidationResult(is_valid=True, errors=[], warnings=[])

    @staticmethod
    def fail(errors: list[str], warnings: list[str] | None = None) -> "ValidationResult":
        return ValidationResult(is_valid=False, errors=errors, warnings=warnings or [])


class InputValidator:
    """Validates incoming chat completion requests."""

    def __init__(self) -> None:
        self.settings = get_settings().input_validation

    def validate(self, request: ChatCompletionRequest) -> ValidationResult:
        """Run all validation checks on *request*."""
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Message count
        if len(request.messages) > self.settings.max_message_count:
            errors.append(
                f"Too many messages: {len(request.messages)} "
                f"(max {self.settings.max_message_count})"
            )

        # 2. Total text length
        total_text = self._extract_all_text(request)
        if len(total_text) > self.settings.max_chars:
            errors.append(
                f"Total text length {len(total_text)} exceeds max {self.settings.max_chars}"
            )

        # 3. Special character ratio
        if total_text:
            special_count = sum(
                1 for ch in total_text if not ch.isalnum() and not ch.isspace()
            )
            ratio = special_count / len(total_text)
            if ratio > self.settings.max_special_chars_ratio:
                warnings.append(
                    f"High special character ratio: {ratio:.2%} "
                    f"(threshold {self.settings.max_special_chars_ratio:.0%})"
                )

        # 4. Empty content check
        has_content = any(
            m.content for m in request.messages if m.role in ("user", "system")
        )
        if not has_content:
            errors.append("Request contains no user/system content")

        # 5. Encoding sanity (basic — check for null bytes / control chars)
        if "\x00" in total_text:
            errors.append("Input contains null bytes")
        control_count = sum(
            1 for ch in total_text
            if ord(ch) < 32 and ch not in ("\n", "\r", "\t")
        )
        if control_count > 0:
            warnings.append(f"Input contains {control_count} control characters")

        # 6. Model field basic sanity
        if not request.model or len(request.model) > 100:
            errors.append("Invalid or missing model field")

        if errors:
            logger.warning("Input validation failed", errors=errors)
            return ValidationResult.fail(errors, warnings)

        if warnings:
            logger.info("Input validation warnings", warnings=warnings)

        return ValidationResult(is_valid=True, errors=[], warnings=warnings)

    @staticmethod
    def _extract_all_text(request: ChatCompletionRequest) -> str:
        """Concatenate all textual content from messages."""
        parts: list[str] = []
        for msg in request.messages:
            if isinstance(msg.content, str):
                parts.append(msg.content)
            elif isinstance(msg.content, list):
                for item in msg.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        parts.append(item.get("text", ""))
        return "\n".join(parts)
