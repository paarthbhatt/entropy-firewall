"""Pydantic V2 schemas for API request / response contracts."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Chat Completion — Request
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    """A single chat message."""

    role: Literal["system", "user", "assistant", "tool", "function"] = Field(
        ..., description="Role of the message author"
    )
    content: Optional[Union[str, list[Any]]] = Field(
        None, description="Message content (text or multipart)"
    )
    name: Optional[str] = None
    tool_calls: Optional[list[dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible chat completion request."""

    model: str = Field(..., description="Model to use")
    messages: list[ChatMessage] = Field(..., min_length=1)
    temperature: Optional[float] = Field(None, ge=0, le=2)
    top_p: Optional[float] = Field(None, ge=0, le=1)
    max_tokens: Optional[int] = Field(None, ge=1)
    stream: bool = Field(default=False)
    stop: Optional[Union[str, list[str]]] = None
    presence_penalty: Optional[float] = Field(None, ge=-2, le=2)
    frequency_penalty: Optional[float] = Field(None, ge=-2, le=2)
    user: Optional[str] = None

    # Extra kwargs forwarded to the provider
    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# Entropy verdict
# ---------------------------------------------------------------------------

class ThreatLevel(str, Enum):
    """Severity of a detected threat."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntropyStatus(str, Enum):
    """Overall security status of a request/response."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    SANITIZED = "sanitized"


class ThreatInfo(BaseModel):
    """Details of a single detected threat."""

    category: str
    name: str
    threat_level: ThreatLevel
    confidence: float = Field(ge=0, le=1)
    details: Optional[str] = None
    suggestion: Optional[str] = Field(
        default=None,
        description="Actionable suggestion to fix the issue"
    )


class EntropyVerdict(BaseModel):
    """Security verdict attached to every Entropy response."""

    status: EntropyStatus
    confidence: float = Field(ge=0, le=1)
    threats_detected: list[ThreatInfo] = Field(default_factory=list)
    processing_time_ms: float = 0.0
    input_valid: bool = True
    output_sanitized: bool = False
    
    # New fields for better analysis
    sanitized_content: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Actionable suggestion for the developer/user
    suggestion: Optional[str] = Field(
        default=None,
        description="Overall actionable suggestion to handle this verdict"
    )

    def get_primary_threat(self) -> Optional[ThreatInfo]:
        """Get the highest severity threat."""
        if not self.threats_detected:
            return None
        priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}
        return max(
            self.threats_detected,
            key=lambda t: priority.get(t.threat_level.value, 0)
        )


# ---------------------------------------------------------------------------
# Chat Completion — Response
# ---------------------------------------------------------------------------

class ChatCompletionChoice(BaseModel):
    """A single completion choice."""

    index: int = 0
    message: ChatMessage
    finish_reason: Optional[str] = None


class CompletionUsage(BaseModel):
    """Token usage information."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    """OpenAI-compatible chat completion response with Entropy metadata."""

    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: Optional[CompletionUsage] = None
    entropy: EntropyVerdict = Field(
        description="Entropy security verdict for this request/response"
    )

# ---------------------------------------------------------------------------
# Streaming Models
# ---------------------------------------------------------------------------

class DeltaMessage(BaseModel):
    """A partial message delta."""
    role: Optional[Literal["system", "user", "assistant", "tool", "function"]] = None
    content: Optional[str] = None

class StreamingChoice(BaseModel):
    """A single streaming choice."""
    index: int
    delta: DeltaMessage
    finish_reason: Optional[str] = None

class ChatCompletionChunk(BaseModel):
    """OpenAI-compatible chat completion chunk."""
    id: str
    object: str = "chat.completion.chunk"
    created: int
    model: str
    choices: list[StreamingChoice]
    entropy: Optional[EntropyVerdict] = None


# ---------------------------------------------------------------------------
# Error response
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    """Standardized error response."""

    error: str
    detail: Optional[str] = None
    entropy: Optional[EntropyVerdict] = None
    action_suggestion: Optional[str] = Field(
        default=None,
        description="Actionable suggestion to fix the error"
    )


# ---------------------------------------------------------------------------
# Health / Admin / Rules
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str
    environment: str
    patterns_loaded: int = 0
    uptime_seconds: float = 0.0


class APIKeyCreateRequest(BaseModel):
    """Request body for creating a new API key."""

    name: str = Field(..., min_length=1, max_length=255)
    user_id: Optional[str] = None
    rate_limit_rpm: Optional[int] = Field(None, ge=1)


class APIKeyCreateResponse(BaseModel):
    """Response after creating a new API key. Contains the raw key ONCE."""

    id: str
    key: str = Field(description="Full API key — save this, it won't be shown again")
    key_prefix: str
    name: str
    created_at: str

# New Rule Management Schemas
class FirewallRule(BaseModel):
    """A dynamic firewall rule."""
    id: str
    name: str
    category: str
    pattern: str
    threat_level: ThreatLevel
    enabled: bool = True
    created_at: str

class FirewallRuleCreate(BaseModel):
    """Schema for creating a new firewall rule."""
    name: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1)
    pattern: str = Field(..., min_length=1, description="Regex pattern")
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    enabled: bool = True

class ModelInfo(BaseModel):
    """Information about an available model."""
    id: str
    object: str = "model"
    created: int = 0
    owned_by: str = "entropy"

class ModelListResponse(BaseModel):
    """List of available models."""
    object: str = "list"
    data: list[ModelInfo]
