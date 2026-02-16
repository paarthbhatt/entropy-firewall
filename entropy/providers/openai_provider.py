"""OpenAI provider adapter.

Wraps the official ``openai`` Python SDK and normalises the response
into the format expected by the Entropy API layer.
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator, Optional

import openai
import structlog

from entropy.providers.base import BaseProvider

logger = structlog.get_logger(__name__)


class OpenAIProvider(BaseProvider):
    """Adapter for the OpenAI Chat Completions API."""

    def __init__(self, api_key: str) -> None:
        self._client = openai.AsyncOpenAI(api_key=api_key)

    @property
    def name(self) -> str:
        return "openai"

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
        """Call OpenAI chat completions (non-streaming)."""
        params: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }
        if temperature is not None:
            params["temperature"] = temperature
        if max_tokens is not None:
            params["max_tokens"] = max_tokens
        # Forward any extra kwargs supported by the OpenAI SDK
        for k in ("top_p", "presence_penalty", "frequency_penalty", "stop", "user"):
            if k in kwargs and kwargs[k] is not None:
                params[k] = kwargs[k]

        start = time.perf_counter()
        try:
            response = await self._client.chat.completions.create(**params)
        except openai.APIStatusError as exc:
            logger.error(
                "OpenAI API error",
                status=exc.status_code,
                message=str(exc.message),
            )
            raise

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("OpenAI call complete", model=model, elapsed_ms=elapsed_ms)

        # Convert to dict (Pydantic model → dict)
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
        except openai.APIStatusError as exc:
            logger.error("OpenAI stream error", status=exc.status_code)
            yield f'data: {{"error": "{exc.message}"}}\n\n'

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.close()
