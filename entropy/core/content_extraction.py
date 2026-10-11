"""Bounded extraction of analyzable text from a chat request.

Detection layers historically saw only string content and multipart
``type=text`` items. Attacks hidden in image ``alt`` text or in
function/tool-call ``arguments`` were therefore never scanned (0% recall on
those positions). This module centralizes extraction so the engine, input
validator, and indirect detector all inspect the same request surfaces with
consistent source provenance.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from entropy.models.schemas import ChatCompletionRequest

# Bound how much we pull out of a single tool-call argument blob so a crafted
# request cannot force unbounded scanning work.
_MAX_ARG_VALUES = 64
_MAX_ARG_DEPTH = 6


def _iter_json_strings(value: Any, depth: int = 0) -> list[str]:
    """Collect string leaves from a parsed JSON argument structure."""
    if depth > _MAX_ARG_DEPTH:
        return []
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            out.extend(_iter_json_strings(item, depth + 1))
    elif isinstance(value, list):
        for item in value:
            out.extend(_iter_json_strings(item, depth + 1))
    return out[:_MAX_ARG_VALUES]


def _argument_text(arguments: Any) -> str:
    """Extract scannable text from a tool-call ``arguments`` field.

    ``arguments`` is normally a JSON string. String leaf values carry the
    attacker-controlled text; if parsing fails we fall back to the raw blob so
    nothing escapes inspection.
    """
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except (json.JSONDecodeError, ValueError):
            return arguments
        strings = _iter_json_strings(parsed)
        return "\n".join(strings) if strings else arguments
    if isinstance(arguments, (dict, list)):
        return "\n".join(_iter_json_strings(arguments))
    return ""


def _content_texts(base: str, content: Any) -> list[tuple[str, str]]:
    """Extract text from a message ``content`` field (string or multipart)."""
    out: list[tuple[str, str]] = []
    if isinstance(content, str):
        if content.strip():
            out.append((base, content))
        return out
    if not isinstance(content, list):
        return out
    for j, item in enumerate(content):
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if item_type == "text":
            text = item.get("text", "")
            if isinstance(text, str) and text.strip():
                out.append((f"{base}:part[{j}]:text", text))
        elif item_type == "image_url":
            image = item.get("image_url")
            if isinstance(image, dict):
                alt = image.get("alt", "")
                if isinstance(alt, str) and alt.strip():
                    out.append((f"{base}:part[{j}]:image_alt", alt))
    return out


def _tool_call_texts(base: str, tool_calls: Any) -> list[tuple[str, str]]:
    """Extract text from a message's function/tool-call argument fields."""
    out: list[tuple[str, str]] = []
    if not isinstance(tool_calls, list):
        return out
    for k, call in enumerate(tool_calls):
        if not isinstance(call, dict):
            continue
        function = call.get("function")
        if not isinstance(function, dict):
            continue
        text = _argument_text(function.get("arguments"))
        if text.strip():
            out.append((f"{base}:tool_call[{k}]:args", text))
    return out


def iter_request_texts(request: ChatCompletionRequest) -> list[tuple[str, str]]:
    """Yield ``(source, text)`` pairs for every analyzable field in a request.

    Covers plain string content, multipart ``type=text`` items, image
    ``alt`` text, and function/tool-call argument string values.
    """
    results: list[tuple[str, str]] = []
    for i, msg in enumerate(request.messages):
        base = f"msg[{i}]:{msg.role}"
        results.extend(_content_texts(base, msg.content))
        results.extend(_tool_call_texts(base, msg.tool_calls))
    return results


def extract_request_text(request: ChatCompletionRequest) -> str:
    """Concatenate all analyzable text from a request into one scan string."""
    return "\n".join(text for _, text in iter_request_texts(request))
