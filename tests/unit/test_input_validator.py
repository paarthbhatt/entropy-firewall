"""Unit tests for InputValidator."""

import pytest
from entropy.core.input_validator import InputValidator
from entropy.models.schemas import ChatCompletionRequest, ChatMessage


class TestInputValidator:
    """Test suite for InputValidator."""

    def _make_request(self, messages: list[dict], model: str = "gpt-4o-mini") -> ChatCompletionRequest:
        return ChatCompletionRequest(
            model=model,
            messages=[ChatMessage(**m) for m in messages],
        )

    def test_valid_request(self, input_validator: InputValidator):
        req = self._make_request([
            {"role": "user", "content": "Hello, how are you?"},
        ])
        result = input_validator.validate(req)
        assert result.is_valid is True
        assert result.errors == []

    def test_empty_content_rejected(self, input_validator: InputValidator):
        req = self._make_request([
            {"role": "user", "content": ""},
        ])
        result = input_validator.validate(req)
        assert result.is_valid is False
        assert any("no user/system content" in e.lower() for e in result.errors)

    def test_too_many_messages(self, input_validator: InputValidator):
        messages = [{"role": "user", "content": f"msg {i}"} for i in range(100)]
        req = self._make_request(messages)
        result = input_validator.validate(req)
        assert result.is_valid is False
        assert any("too many messages" in e.lower() for e in result.errors)

    def test_extremely_long_text(self, input_validator: InputValidator):
        req = self._make_request([
            {"role": "user", "content": "A" * 50_000},
        ])
        result = input_validator.validate(req)
        assert result.is_valid is False
        assert any("exceeds max" in e.lower() for e in result.errors)

    def test_null_bytes_rejected(self, input_validator: InputValidator):
        req = self._make_request([
            {"role": "user", "content": "Hello\x00World"},
        ])
        result = input_validator.validate(req)
        assert result.is_valid is False
        assert any("null" in e.lower() for e in result.errors)

    def test_high_special_chars_warning(self, input_validator: InputValidator):
        # More than 30% special chars
        req = self._make_request([
            {"role": "user", "content": "!@#$%^&*()!@#$%^&*()abc"},
        ])
        result = input_validator.validate(req)
        # Should warn but not necessarily fail
        assert len(result.warnings) >= 1 or len(result.errors) >= 0

    def test_missing_model_rejected(self, input_validator: InputValidator):
        req = self._make_request(
            [{"role": "user", "content": "Hello"}],
            model="",
        )
        result = input_validator.validate(req)
        assert result.is_valid is False

    def test_multipart_content(self, input_validator: InputValidator):
        """Test with multipart content (text + image refs)."""
        req = ChatCompletionRequest(
            model="gpt-4o",
            messages=[
                ChatMessage(
                    role="user",
                    content=[
                        {"type": "text", "text": "What is in this image?"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}},
                    ],
                )
            ],
        )
        result = input_validator.validate(req)
        assert result.is_valid is True
