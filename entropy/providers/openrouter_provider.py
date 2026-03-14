"""OpenRouter provider adapter.

OpenRouter is a unified gateway to multiple LLM providers.
Uses OpenAI-compatible API with additional routing headers.
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator, Optional

import structlog

from entropy.providers.base import BaseProvider

logger = structlog.get_logger(__name__)

# OpenRouter API base URL
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenRouterProvider(BaseProvider):
    """Adapter for OpenRouter API.

    OpenRouter provides access to many models through a single API.
    It's OpenAI-compatible but with additional features:
    - Model routing (e.g., "anthropic/claude-3-opus", "openai/gpt-4")
    - Fallback providers
    - Cost tracking
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        site_url: Optional[str] = None,
        provider_name: Optional[str] = None,
    ) -> None:
        """Initialize OpenRouter provider.

        Args:
            api_key: OpenRouter API key
            base_url: Optional base URL override
            site_url: Optional site URL for rankings (OpenRouter header)
            provider_name: Optional provider name for rankings
        """
        try:
            import openai
        except ImportError as e:
            raise ImportError(
                "openai package not installed. "
                "Install it with: pip install openai"
            ) from e

        self._base_url = base_url or OPENROUTER_BASE_URL
        self._site_url = site_url
        self._provider_name = provider_name

        # Build extra headers for OpenRouter
        default_headers: dict[str, str] = {}
        if site_url:
            default_headers["HTTP-Referer"] = site_url
        if provider_name:
            default_headers["X-Title"] = provider_name

        self._client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=self._base_url,
            default_headers=default_headers if default_headers else None,
        )

    @property
    def name(self) -> str:
        return "openrouter"

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
        """Call OpenRouter chat completions (non-streaming).

        OpenRouter uses OpenAI-compatible API, so this is mostly passthrough.
        The model parameter includes the provider prefix (e.g., "anthropic/claude-3-opus").
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

        # OpenRouter-specific: provider routing and fallbacks
        if "provider" in kwargs and kwargs["provider"] is not None:
            params["provider"] = kwargs["provider"]

        if "transforms" in kwargs and kwargs["transforms"] is not None:
            params["transforms"] = kwargs["transforms"]

        # Route options
        if "route" in kwargs and kwargs["route"] is not None:
            params["route"] = kwargs["route"]

        start = time.perf_counter()

        try:
            response = await self._client.chat.completions.create(**params)
        except Exception as exc:
            logger.error(
                "OpenRouter API error",
                error=str(exc),
                model=model,
            )
            raise

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("OpenRouter call complete", model=model, elapsed_ms=elapsed_ms)

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
            logger.error("OpenRouter stream error", error=str(exc))
            yield f'data: {{"error": "{str(exc)}"}}\n\n'

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.close()


__all__ = ["OpenRouterProvider"]