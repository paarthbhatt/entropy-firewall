"""Unit tests for InputSanitizer enterprise feature."""

import base64

import pytest

from entropy.core.input_sanitizer import InputSanitizer


@pytest.mark.asyncio
class TestInputSanitizer:
    """Test suite for InputSanitizer."""

    @pytest.fixture
    def sanitizer(self):
        return InputSanitizer(max_depth=5, enabled=True)

    async def test_sanitizes_base64(self, sanitizer):
        """Test sanitization of base64 encoding."""
        # Use a simple text that base64 decodes cleanly
        original_text = "Attack Command"
        dirty = base64.b64encode(original_text.encode()).decode()
        result = sanitizer.sanitize(dirty)
        # Check that some decoding happened
        assert result.was_obfuscated is True
        # The result should have detected some encoding
        assert len(result.encodings_found) > 0

    async def test_sanitizes_url_encoding(self, sanitizer):
        """Test sanitization of URL encoding."""
        dirty = "Hello%20World%21"
        result = sanitizer.sanitize(dirty)
        # URL encoding should be detected
        assert "url_encoding" in result.encodings_found
        assert result.was_obfuscated is True
        # Should decode the %20 and %21
        assert "Hello" in result.decoded and "World" in result.decoded

    async def test_preserves_safe_text(self, sanitizer):
        """Test that safe text is preserved."""
        safe = "What is the capital of France?"
        result = sanitizer.sanitize(safe)
        assert result.decoded == safe
        assert result.was_obfuscated is False

    async def test_sanitizes_html_entities(self, sanitizer):
        """Test sanitization of HTML entities."""
        dirty = "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        result = sanitizer.sanitize(dirty)
        assert "script" in result.decoded
        assert "html_entity" in result.encodings_found

    async def test_handles_empty_input(self, sanitizer):
        """Test handling of empty input."""
        result = sanitizer.sanitize("")
        assert result.decoded == ""
        assert result.was_obfuscated is False

    async def test_sanitizes_hex_escape(self, sanitizer):
        """Test sanitization of hex escapes."""
        dirty = "\\x48\\x65\\x6c\\x6c\\x6f"
        result = sanitizer.sanitize(dirty)
        assert "Hello" in result.decoded
        assert result.was_obfuscated is True

    async def test_multilayer_encoding(self, sanitizer):
        """Test handling of multi-layer encoding."""
        # Base64(URL-encoded text)
        layer1 = "Hello%20World"
        layer2 = base64.b64encode(layer1.encode()).decode()
        result = sanitizer.sanitize(layer2)
        # Should detect at least base64 decoding
        assert result.layers_decoded >= 1
        assert result.was_obfuscated is True
        assert "base64" in result.encodings_found

    async def test_respects_disabled(self):
        """Test that sanitizer respects enabled=False."""
        sanitizer = InputSanitizer(enabled=False)
        dirty = "Hello%20World"
        result = sanitizer.sanitize(dirty)
        # Should still return same structure but possibly less processing
        assert result.original == dirty
