"""Google (Gemini) provider adapter.

Wraps the Google Generative AI API and normalizes responses to
OpenAI-compatible format.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import TYPE_CHECKING, Any

import structlog

from entropy.providers.base import BaseProvider

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = structlog.get_logger(__name__)


class GoogleProvider(BaseProvider):
    """Adapter for Google Gemini API.

    Translates between OpenAI-compatible request format and Google's
    Generative AI format, then converts responses back to OpenAI format.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
    ) -> None:
        """Initialize Google provider.

        Args:
            api_key: Google API key
            base_url: Optional base URL (for Vertex AI or other proxies)
        """
        try:
            import google.generativeai as genai  # noqa: PLC0415
        except ImportError as e:
            raise ImportError(
                "google-generativeai package not installed. "
                "Install it with: pip install google-generativeai"
            ) from e

        self._api_key = api_key
        self._base_url = base_url
        genai.configure(api_key=api_key)
        self._genai = genai

    @property
    def name(self) -> str:
        return "google"

    async def chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Call Google Gemini API (non-streaming).

        Converts OpenAI-format messages to Google format, calls the API,
        and converts the response back to OpenAI format.
        """
        # Convert messages to Google format
        system_instruction, contents = self._convert_messages(messages)

        # Build generation config
        generation_config = self._build_generation_config(
            temperature=temperature, max_tokens=max_tokens, **kwargs
        )

        # Create model instance
        model_instance = self._genai.GenerativeModel(
            model_name=model,
            system_instruction=system_instruction,
        )

        start = time.perf_counter()

        try:
            response = await model_instance.generate_content_async(
                contents,
                generation_config=generation_config,
            )
        except Exception as exc:
            logger.error(
                "Google API error",
                error=str(exc),
                model=model,
            )
            raise

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info("Google call complete", model=model, elapsed_ms=elapsed_ms)

        # Convert to OpenAI format
        return self._convert_response(response, model)

    async def chat_completion_stream(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Streaming chat completion — yields SSE lines in OpenAI format."""
        system_instruction, contents = self._convert_messages(messages)

        generation_config = self._build_generation_config(
            temperature=temperature, max_tokens=max_tokens, **kwargs
        )

        model_instance = self._genai.GenerativeModel(
            model_name=model,
            system_instruction=system_instruction,
        )

        completion_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created = int(time.time())

        try:
            response = await model_instance.generate_content_async(
                contents,
                generation_config=generation_config,
                stream=True,
            )

            async for chunk in response:
                # Extract text from chunk
                text = ""
                if hasattr(chunk, "text"):
                    text = chunk.text
                elif hasattr(chunk, "candidates") and chunk.candidates:
                    candidate = chunk.candidates[0]
                    if hasattr(candidate, "content") and hasattr(candidate.content, "parts"):
                        for part in candidate.content.parts:
                            if hasattr(part, "text"):
                                text += part.text

                if text:
                    openai_chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": text},
                                "finish_reason": None,
                            }
                        ],
                    }
                    yield f"data: {json.dumps(openai_chunk)}\n\n"

            # Send final chunk
            final_chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "stop",
                    }
                ],
            }
            yield f"data: {json.dumps(final_chunk)}\n\n"
            yield "data: [DONE]\n\n"

        except Exception as exc:
            logger.error("Google stream error", error=str(exc))
            yield f'data: {{"error": "{exc!s}"}}\n\n'

    async def close(self) -> None:
        """Close any resources."""
        # Google client doesn't require explicit cleanup
        pass

    def _convert_messages(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[str | None, list[dict[str, Any]]]:
        """Convert OpenAI-format messages to Google Gemini format.

        Returns (system_instruction, contents).
        """
        system_instruction: str | None = None
        contents: list[dict[str, Any]] = []

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            # Handle system messages
            if role == "system":
                system_instruction = content
                continue

            # Map roles to Google format
            # Google uses "user" and "model" (not "assistant")
            google_role = "user" if role == "user" else "model"

            # Handle multi-modal content
            if isinstance(content, str):
                parts = [{"text": content}]
            elif isinstance(content, list):
                parts = self._convert_content_parts(content)
            else:
                parts = [{"text": str(content)}]

            contents.append(
                {
                    "role": google_role,
                    "parts": parts,
                }
            )

        return system_instruction, contents

    def _convert_content_parts(self, parts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert OpenAI content parts to Google format."""
        google_parts = []

        for part in parts:
            part_type = part.get("type", "")

            if part_type == "text":
                google_parts.append({"text": part.get("text", "")})
            elif part_type == "image_url":
                # Convert image URL to Google format
                image_url = part.get("image_url", {})
                url = image_url.get("url", "")
                if url.startswith("data:"):
                    # Base64 encoded image
                    import base64  # noqa: PLC0415
                    import re  # noqa: PLC0415

                    # Extract mime type and data
                    match = re.match(r"data:([^;]+);base64,(.+)", url)
                    if match:
                        mime_type, data = match.groups()
                        image_bytes = base64.b64decode(data)
                        google_parts.append(
                            {
                                "inline_data": {
                                    "mime_type": mime_type,
                                    "data": image_bytes,
                                }
                            }
                        )
                else:
                    # URL - Google Gemini may need to fetch it
                    # This is a simplified handling; production code would
                    # download and encode the image
                    logger.warning("External image URLs may not be supported", url=url)
            elif part_type == "image":
                # Already in compatible format
                google_parts.append(part)

        return google_parts

    def _build_generation_config(
        self,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Build Google generation config from kwargs."""
        config: dict[str, Any] = {}

        if temperature is not None:
            config["temperature"] = temperature

        if max_tokens is not None:
            config["max_output_tokens"] = max_tokens

        # Handle top_p, top_k
        if "top_p" in kwargs and kwargs["top_p"] is not None:
            config["top_p"] = kwargs["top_p"]

        if "top_k" in kwargs and kwargs["top_k"] is not None:
            config["top_k"] = kwargs["top_k"]

        # Handle stop sequences
        if kwargs.get("stop"):
            stops = kwargs["stop"] if isinstance(kwargs["stop"], list) else [kwargs["stop"]]
            config["stop_sequences"] = stops

        return config

    def _convert_response(
        self,
        response: Any,
        model: str,
    ) -> dict[str, Any]:
        """Convert Google response to OpenAI format."""
        # Extract text from candidates
        text_content = ""
        prompt_tokens = 0
        completion_tokens = 0

        if hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]

            # Extract text from parts
            if hasattr(candidate, "content") and hasattr(candidate.content, "parts"):
                for part in candidate.content.parts:
                    if hasattr(part, "text"):
                        text_content += part.text

            # Get token counts
            if hasattr(candidate, "token_count"):
                prompt_tokens = getattr(candidate.token_count, "prompt_token_count", 0)
                completion_tokens = getattr(candidate.token_count, "candidates_token_count", 0)

        # Try to get usage metadata
        if hasattr(response, "usage_metadata"):
            usage = response.usage_metadata
            prompt_tokens = getattr(usage, "prompt_token_count", prompt_tokens)
            completion_tokens = getattr(usage, "candidates_token_count", completion_tokens)

        completion_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"

        openai_response = {
            "id": completion_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text_content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }

        return openai_response


__all__ = ["GoogleProvider"]
