"""Anthropic (Claude) provider adapter.

Wraps the Anthropic API and normalizes responses to OpenAI-compatible format.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, AsyncIterator, Optional

import structlog

from entropy.providers.base import BaseProvider

logger = structlog.get_logger(__name__)


class AnthropicProvider(BaseProvider):
    """Adapter for Anthropic Claude API.

    Translates between OpenAI-compatible request format and Anthropic's
    Messages API format, then converts responses back to OpenAI format.
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
    ) -> None:
        """Initialize Anthropic provider.

        Args:
            api_key: Anthropic API key
            base_url: Optional base URL (for proxies)
        """
        try:
            import anthropic
        except ImportError as e:
            raise ImportError(
                "anthropic package not installed. "
                "Install it with: pip install anthropic"
            ) from e

        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            base_url=base_url,
        )
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "anthropic"

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
        """Call Anthropic Messages API (non-streaming).

        Converts OpenAI-format messages to Anthropic format, calls the API,
        and converts the response back to OpenAI format.
        """
        # Convert messages to Anthropic format
        system_prompt, anthropic_messages = self._convert_messages(messages)

        # Build request params
        params: dict[str, Any] = {
            "model": model,
            "messages": anthropic_messages,
        }

        if system_prompt:
            params["system"] = system_prompt

        if max_tokens:
            params["max_tokens"] = max_tokens
        else:
            # Anthropic requires max_tokens
            params["max_tokens"] = 4096

        if temperature is not None:
            params["temperature"] = temperature

        # Handle stop sequences
        if "stop" in kwargs and kwargs["stop"]:
            params["stop_sequences"] = (
                kwargs["stop"] if isinstance(kwargs["stop"], list)
                else [kwargs["stop"]]
            )

        start = time.perf_counter()

        try:
            response = await self._client.messages.create(**params)
        except Exception as exc:
            logger.error(
                "Anthropic API error",
                error=str(exc),
                model=model,
            )
            raise

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("Anthropic call complete", model=model, elapsed_ms=elapsed_ms)

        # Convert to OpenAI format
        return self._convert_response(response, model)

    async def chat_completion_stream(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Streaming chat completion — yields SSE lines in OpenAI format."""
        system_prompt, anthropic_messages = self._convert_messages(messages)

        params: dict[str, Any] = {
            "model": model,
            "messages": anthropic_messages,
        }

        if system_prompt:
            params["system"] = system_prompt

        if max_tokens:
            params["max_tokens"] = max_tokens
        else:
            params["max_tokens"] = 4096

        if temperature is not None:
            params["temperature"] = temperature

        if "stop" in kwargs and kwargs["stop"]:
            params["stop_sequences"] = (
                kwargs["stop"] if isinstance(kwargs["stop"], list)
                else [kwargs["stop"]]
            )

        completion_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created = int(time.time())

        try:
            async with self._client.messages.stream(**params) as stream:
                async for event in stream:
                    if event.type == "content_block_delta":
                        delta = event.delta
                        if hasattr(delta, "text"):
                            # Convert to OpenAI streaming format
                            chunk = {
                                "id": completion_id,
                                "object": "chat.completion.chunk",
                                "created": created,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": {"content": delta.text},
                                    "finish_reason": None,
                                }],
                            }
                            yield f"data: {json.dumps(chunk)}\n\n"

                    elif event.type == "message_stop":
                        # Send final chunk
                        final_chunk = {
                            "id": completion_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {},
                                "finish_reason": "stop",
                            }],
                        }
                        yield f"data: {json.dumps(final_chunk)}\n\n"

            yield "data: [DONE]\n\n"

        except Exception as exc:
            logger.error("Anthropic stream error", error=str(exc))
            yield f'data: {{"error": "{str(exc)}"}}\n\n'

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.close()

    def _convert_messages(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[Optional[str], list[dict[str, Any]]]:
        """Convert OpenAI-format messages to Anthropic format.

        Anthropic uses separate 'system' param and 'user'/'assistant' roles.
        Returns (system_prompt, anthropic_messages).
        """
        system_prompt: Optional[str] = None
        anthropic_messages: list[dict[str, Any]] = []

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            # Handle system messages separately
            if role == "system":
                system_prompt = content
                continue

            # Anthropic only supports user and assistant roles
            if role in ("user", "assistant"):
                anthropic_msg = {
                    "role": role,
                    "content": content,
                }
                anthropic_messages.append(anthropic_msg)

            # Handle tool messages (for function calling)
            elif role == "tool":
                # Convert to user message with tool result
                anthropic_msg = {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.get("tool_call_id", ""),
                            "content": content,
                        }
                    ],
                }
                anthropic_messages.append(anthropic_msg)

            # Handle assistant messages with tool calls
            elif role == "assistant" and "tool_calls" in msg:
                # Convert tool calls to Anthropic format
                content_blocks = []
                if content:
                    content_blocks.append({"type": "text", "text": content})

                for tool_call in msg.get("tool_calls", []):
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tool_call.get("id", ""),
                        "name": tool_call.get("function", {}).get("name", ""),
                        "input": json.loads(
                            tool_call.get("function", {}).get("arguments", "{}")
                        ),
                    })

                anthropic_messages.append({
                    "role": "assistant",
                    "content": content_blocks,
                })

        return system_prompt, anthropic_messages

    def _convert_response(
        self,
        response: Any,
        model: str,
    ) -> dict[str, Any]:
        """Convert Anthropic response to OpenAI format."""
        # Extract text content
        text_content = ""
        for block in response.content:
            if hasattr(block, "text"):
                text_content += block.text

        # Build OpenAI-compatible response
        completion_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"

        openai_response = {
            "id": completion_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text_content,
                },
                "finish_reason": "stop" if response.stop_reason == "end_turn"
                                 else response.stop_reason,
            }],
            "usage": {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            },
        }

        return openai_response


__all__ = ["AnthropicProvider"]