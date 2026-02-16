"""Abstract LLM provider interface.

All provider adapters must implement this interface so the API layer
can route to any backend without coupling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Dict, Optional


class BaseProvider(ABC):
    """Abstract base class for LLM provider adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name (e.g. 'openai', 'anthropic')."""
        ...

    @abstractmethod
    async def chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Non-streaming chat completion.

        Returns the provider's raw JSON response dict.
        """
        ...

    @abstractmethod
    async def chat_completion_stream(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Streaming chat completion.

        Yields SSE-formatted strings (``data: {...}\\n\\n``).
        """
        ...

    @abstractmethod
    async def close(self) -> None:
        """Release any resources held by the provider."""
        ...
