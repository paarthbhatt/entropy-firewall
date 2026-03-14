"""Groq provider adapter.

Wraps the Groq API which is OpenAI-compatible but with different base URL
and available models (Llama, Mixtral, Gemma).
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator, Optional

import structlog

from entropy.providers.base import BaseProvider

logger = structlog.get_logger(__name__)

# Groq API base URL
GROQ_BASE_URL = "https://api.groq.com/openai/v1"


class GroqProvider(BaseProvider):
    """Adapter for Groq API.

    Groq uses an OpenAI-compatible API, so this adapter primarily
    changes the base URL and handles Groq-specific differences.
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
    ) -> None:
        """Initialize Groq provider.

        Args:
            api_key: Groq API key
            base_url: Optional base URL override
        """
        try:
            import openai
        except ImportError as e:
            raise ImportError(
                "openai package not installed. "
                "Install it with: pip install openai"
            ) from e

        # Use Groq's OpenAI-compatible endpoint
        self._base_url = base_url or GROQ_BASE_URL
        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=self._base_url,
        )

    @property
    def name(self) -> str:
        return "groq"

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
        """Call Groq chat completions (non-streaming).

        Since Groq is OpenAI-compatible, this is mostly passthrough.
        """
        params: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }

        if temperature is not None:
            params["temperature"] = temperature
        if max_tokens is not None:
            params["max_tokens"] = max_tokens

        # Forward common kwargs
        for k in ("top_p", "presence_penalty", "frequency_penalty", "stop", "user"):
            if k in kwargs and kwargs[k] is not None:
                params[k] = kwargs[k]

        # Groq-specific: handle seed for deterministic outputs
        if "seed" in kwargs and kwargs["seed"] is not None:
            params["seed"] = kwargs["seed"]

        start = time.perf_counter()

        try:
            response = await self._client.chat.completions.create(**params)
        except Exception as exc:
            logger.error(
                "Groq API error",
                error=str(exc),
                model=model,
            )
            raise

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("Groq call complete", model=model, elapsed_ms=elapsed_ms)

        return response.model_dump()

    async def chat_completion_stream(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Streaming chat completion — yields SSE lines."""
        params: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": True,
        }

        if temperature is not None:
            params["temperature"] = temperature
        if max_tokens is not None:
            params["max_tokens"] = max_tokens

        for k in ("top_p", "presence_penalty", "frequency_penalty", "stop", "user"):
            if k in kwargs and kwargs[k] is not None:
                params[k] = kwargs[k]

        try:
            stream = await self._client.chat.completions.create(**params)
            async for chunk in stream:
                data = chunk.model_dump()
                yield f"data: {json.dumps(data)}\n\n"
            yield "data: [DONE]\n\n"

        except Exception as exc:
            logger.error("Groq stream error", error=str(exc))
            yield f'data: {{"error": "{str(exc)}"}}\n\n'

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.close()


__all__ = ["GroqProvider"]