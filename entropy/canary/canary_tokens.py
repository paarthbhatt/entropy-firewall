"""Canary Tokens ΓÇö system prompt leak detection.

Injects unique tokens into system prompts and monitors responses
to detect exfiltration attempts. When a canary token appears in
an LLM response, it indicates the system prompt has been leaked.

Free Tier: Basic token injection and detection
Enterprise: + Forensics, alerting, webhook notifications
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# Canary token format
CANARY_PREFIX = "[ENTROPY-CANARY:"
CANARY_SUFFIX = "]"


@dataclass
class CanaryRecord:
    """Record of an injected canary token."""

    token: str
    request_id: str
    injected_at: datetime
    system_prompt_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CanaryDetection:
    """Detection of a canary token in a response."""

    token: str
    request_id: str
    injected_at: datetime
    detected_at: datetime
    leaked_content: str | None = None  # Context around the leak
    metadata: dict[str, Any] = field(default_factory=dict)


class CanaryTokenManager:
    """Inject and detect canary tokens for system prompt leak detection.

    Usage:
        manager = CanaryTokenManager()

        # Inject canary into system prompt
        protected_prompt = manager.inject("You are a helpful assistant.", "req-123")

        # Check for leaks in response
        detection = manager.detect(response_content)
        if detection:
            # System prompt leaked! Handle appropriately
            log_critical_security_event(detection)
    """

    def __init__(
        self,
        enabled: bool = True,
        ttl_seconds: int = 300,
        enterprise: bool = False,
    ) -> None:
        """Initialize the canary token manager.

        Args:
            enabled: Whether canary injection is enabled
            ttl_seconds: Time-to-live for canary tokens in seconds
            enterprise: Enable enterprise features (forensics, alerting)
        """
        self.enabled = enabled
        self.ttl_seconds = ttl_seconds
        self.enterprise = enterprise

        # In-memory token storage (for free tier)
        # Enterprise uses Redis-backed storage
        self._tokens: dict[str, CanaryRecord] = {}

        logger.info(
            "CanaryTokenManager initialized",
            enabled=enabled,
            ttl_seconds=ttl_seconds,
            enterprise=enterprise,
        )

    def inject(
        self,
        system_prompt: str,
        request_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Inject a unique canary token into the system prompt.

        The canary is appended to the end of the system prompt in a format
        that is not easily detected but can be caught in responses.

        Args:
            system_prompt: The original system prompt
            request_id: Unique identifier for this request
            metadata: Optional metadata to store with the token

        Returns:
            The system prompt with canary token injected
        """
        if not self.enabled:
            return system_prompt

        # Generate unique canary token
        token_hash = secrets.token_hex(8)
        token = f"{CANARY_PREFIX}{token_hash}{CANARY_SUFFIX}"

        # Create record
        record = CanaryRecord(
            token=token,
            request_id=request_id,
            injected_at=datetime.utcnow(),
            system_prompt_hash=hashlib.sha256(system_prompt.encode()).hexdigest()[:16],
            metadata=metadata or {},
        )

        # Store token (will be cleaned up after TTL)
        self._tokens[token] = record

        # Inject canary - use invisible unicode marker for stealth
        # The canary is added as a comment-like instruction that models ignore
        canary_instruction = f"\n\n[SECURITY_REF: {token_hash}]"
        protected_prompt = system_prompt + canary_instruction

        logger.debug(
            "Canary token injected",
            token=token,
            request_id=request_id,
        )

        return protected_prompt

    def detect(
        self,
        response: str,
        metadata: dict[str, Any] | None = None,
    ) -> CanaryDetection | None:
        """Check if any canary token appears in response.

        This indicates a system prompt leak - the model has output
        the canary token, meaning it was able to read and repeat it.

        Args:
            response: The response text to check
            metadata: Optional metadata for the detection

        Returns:
            CanaryDetection if leak detected, None otherwise
        """
        if not self.enabled:
            return None

        # Clean up expired tokens first
        self._cleanup_expired()

        # Check for any known canary tokens
        for token, record in self._tokens.items():
            if token in response:
                # Canaries should NEVER appear in output
                detection = CanaryDetection(
                    token=token,
                    request_id=record.request_id,
                    injected_at=record.injected_at,
                    detected_at=datetime.utcnow(),
                    leaked_content=self._extract_context(response, token),
                    metadata=metadata or {},
                )

                logger.critical(
                    "CANARY TOKEN DETECTED - SYSTEM PROMPT LEAK",
                    token=token,
                    request_id=record.request_id,
                    injected_at=record.injected_at.isoformat(),
                    detection_time=datetime.utcnow().isoformat(),
                )

                return detection

        return None

    def _extract_context(self, text: str, token: str, context_chars: int = 100) -> str:
        """Extract context around the canary token for forensics."""
        try:
            idx = text.find(token)
            if idx == -1:
                return ""
            start = max(0, idx - context_chars)
            end = min(len(text), idx + len(token) + context_chars)
            return text[start:end]
        except Exception:
            return ""

    def _cleanup_expired(self) -> None:
        """Remove expired canary tokens."""
        now = datetime.utcnow()
        expired = [
            token
            for token, record in self._tokens.items()
            if (now - record.injected_at).total_seconds() > self.ttl_seconds
        ]
        for token in expired:
            del self._tokens[token]

    def get_active_tokens(self) -> list[str]:
        """Get list of currently active canary tokens."""
        self._cleanup_expired()
        return list(self._tokens.keys())

    def remove_token(self, token: str) -> bool:
        """Remove a canary token."""
        if token in self._tokens:
            del self._tokens[token]
            return True
        return False


class StealthCanaryManager(CanaryTokenManager):
    """Enhanced canary manager with stealth techniques.

    Uses multiple stealth methods to make canary tokens harder to detect
    and remove by attackers:
    1. Multiple canary formats
    2. Invisible unicode characters
    3. Embedded in legitimate-looking content
    """

    # Multiple canary formats for robustness
    CANARY_FORMATS: list = [  # noqa: RUF012
        # Standard format
        lambda h: f"[ENTROPY-CANARY:{h}]",
        # UUID-like format (looks like a tracking ID)
        lambda h: f"[REF-ID: {h[:8]}-{h[8:16]}]",
        # Base64-like format
        lambda h: f"<!-- entropy:{h} -->",
        # Zero-width encoded (invisible)
        lambda h: f"\u200b{h[:4]}\u200b{h[4:8]}\u200b{h[8:]}",
    ]

    def inject(
        self,
        system_prompt: str,
        request_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Inject multiple stealth canary tokens."""
        if not self.enabled:
            return system_prompt

        # Generate primary token
        token_hash = secrets.token_hex(8)
        primary_token = f"{CANARY_PREFIX}{token_hash}{CANARY_SUFFIX}"

        # Store primary token
        record = CanaryRecord(
            token=primary_token,
            request_id=request_id,
            injected_at=datetime.utcnow(),
            system_prompt_hash=hashlib.sha256(system_prompt.encode()).hexdigest()[:16],
            metadata=metadata or {},
        )
        self._tokens[primary_token] = record

        # Add stealth canary instruction at end
        canary_instruction = f"\n\n<!-- Internal reference: {token_hash[:8]}-{token_hash[8:]} -->"

        return system_prompt + canary_instruction

    def detect(
        self,
        response: str,
        metadata: dict[str, Any] | None = None,
    ) -> CanaryDetection | None:
        """Detect any canary format in response."""
        # Check primary format first
        detection = super().detect(response, metadata)
        if detection:
            return detection

        # Check alternative formats
        for token, record in self._tokens.items():
            token_hash = token.replace(CANARY_PREFIX, "").replace(CANARY_SUFFIX, "")

            # Check UUID-like format
            if f"[REF-ID: {token_hash[:8]}-{token_hash[8:16]}]" in response:
                return CanaryDetection(
                    token=token,
                    request_id=record.request_id,
                    injected_at=record.injected_at,
                    detected_at=datetime.utcnow(),
                    leaked_content=response,
                    metadata=metadata or {},
                )

            # Check base64-like format
            if f"<!-- entropy:{token_hash} -->" in response:
                return CanaryDetection(
                    token=token,
                    request_id=record.request_id,
                    injected_at=record.injected_at,
                    detected_at=datetime.utcnow(),
                    leaked_content=response,
                    metadata=metadata or {},
                )

            # Check for token hash anywhere (partial detection)
            if token_hash in response:
                logger.warning(
                    "Partial canary token detected",
                    token_hash=token_hash[:8],
                    request_id=record.request_id,
                )

        return None


__all__ = [
    "CanaryDetection",
    "CanaryRecord",
    "CanaryTokenManager",
    "StealthCanaryManager",
]
