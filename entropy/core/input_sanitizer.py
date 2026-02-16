"""Input Sanitizer — recursive multi-layer decoding for obfuscation resistance.

Attacks frequently nest multiple encoding layers to evade regex-based
detection.  This module peels encodings iteratively until the text
converges (fixed-point) or ``max_depth`` is reached.

Supported decoders (applied in order each iteration):
  1. Unicode normalisation (NFC → NFKC)
  2. HTML entity decoding
  3. URL (percent) decoding
  4. Base64 decoding
  5. Hex-escape decoding  (\\x41 → A)
  6. ROT13
  7. Leetspeak normalisation
  8. Character-split re-joining  (i g n o r e → ignore)
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SanitizedInput:
    """Result of recursive sanitisation."""

    original: str
    decoded: str
    layers_decoded: int
    encodings_found: list[str] = field(default_factory=list)

    @property
    def was_obfuscated(self) -> bool:
        return self.layers_decoded > 0


# ---------------------------------------------------------------------------
# Leetspeak map (common substitutions)
# ---------------------------------------------------------------------------

_LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
    "|": "i", "(": "c", "+": "t", "}{": "h",
}

_LEET_PATTERN = re.compile("|".join(re.escape(k) for k in _LEET_MAP), re.IGNORECASE)


# ---------------------------------------------------------------------------
# InputSanitizer
# ---------------------------------------------------------------------------

class InputSanitizer:
    """Recursively decode obfuscated inputs to expose hidden payloads.

    Usage::

        sanitizer = InputSanitizer(max_depth=5)
        result = sanitizer.sanitize("aWdub3JlIGFsbCBwcmV2aW91cw==")
        assert "ignore all previous" in result.decoded.lower()
    """

    def __init__(self, *, max_depth: int = 5, enabled: bool = True) -> None:
        self.max_depth = max_depth
        self.enabled = enabled

    # -- public API ---------------------------------------------------------

    def sanitize(self, text: str) -> SanitizedInput:
        """Recursively decode *text* through all decoding layers.

        Returns a ``SanitizedInput`` with the fully decoded text and
        metadata about what encodings were peeled.
        """
        if not self.enabled or not text:
            return SanitizedInput(original=text, decoded=text, layers_decoded=0)

        encodings_found: list[str] = []
        current = text
        total_layers = 0

        for depth in range(self.max_depth):
            decoded, found = self._decode_pass(current)

            if found:
                encodings_found.extend(found)
                total_layers += 1

            # Fixed-point: no more changes → stop
            if decoded == current:
                break

            current = decoded

        if total_layers > 0:
            logger.info(
                "Input sanitized",
                layers=total_layers,
                encodings=encodings_found,
            )

        return SanitizedInput(
            original=text,
            decoded=current,
            layers_decoded=total_layers,
            encodings_found=encodings_found,
        )

    # -- single decode pass -------------------------------------------------

    def _decode_pass(self, text: str) -> tuple[str, list[str]]:
        """Apply all decoders once.  Returns (decoded_text, list_of_encodings_found)."""
        found: list[str] = []
        current = text

        # 1. Unicode normalisation (NFKC flattens compatibility chars)
        normalised = unicodedata.normalize("NFKC", current)
        if normalised != current:
            found.append("unicode_normalisation")
            current = normalised

        # 2. HTML entities  (&amp; &#x41; &#65;)
        html_decoded = html.unescape(current)
        if html_decoded != current:
            found.append("html_entity")
            current = html_decoded

        # 3. URL / percent encoding  (%20 %41)
        try:
            url_decoded = urllib.parse.unquote(current)
            if url_decoded != current:
                found.append("url_encoding")
                current = url_decoded
        except Exception:
            pass

        # 4. Base64 — only attempt if the text looks like it *could* be B64
        b64_decoded = self._try_base64(current)
        if b64_decoded is not None:
            found.append("base64")
            current = b64_decoded

        # 5. Hex escapes  (\x41 → A)
        hex_decoded = self._decode_hex_escapes(current)
        if hex_decoded != current:
            found.append("hex_escape")
            current = hex_decoded

        # 6. ROT13 — only if we detect suspicious ROT13 marker words
        rot_decoded = self._try_rot13(current)
        if rot_decoded is not None:
            found.append("rot13")
            current = rot_decoded

        # 7. Leetspeak normalisation
        leet_decoded = self._decode_leetspeak(current)
        if leet_decoded != current:
            found.append("leetspeak")
            current = leet_decoded

        # 8. Character-split re-joining  (i g n o r e → ignore)
        joined = self._rejoin_char_splits(current)
        if joined != current:
            found.append("char_split")
            current = joined

        return current, found

    # -- individual decoders ------------------------------------------------

    @staticmethod
    def _try_base64(text: str) -> str | None:
        """Attempt Base64 decode on B64-looking substrings.

        Only decodes if the result is valid UTF-8 and mostly printable.
        """
        # Match standalone B64 blocks (min 16 chars to avoid false positives)
        pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        matches = pattern.findall(text)
        if not matches:
            return None

        result = text
        any_decoded = False

        for match in matches:
            try:
                decoded_bytes = base64.b64decode(match, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                # Sanity: must be mostly printable ASCII
                printable_ratio = sum(
                    1 for c in decoded_str if c.isprintable() or c in "\n\r\t"
                ) / max(len(decoded_str), 1)
                if printable_ratio > 0.8 and len(decoded_str) >= 4:
                    result = result.replace(match, decoded_str, 1)
                    any_decoded = True
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue

        return result if any_decoded else None

    @staticmethod
    def _decode_hex_escapes(text: str) -> str:
        r"""Decode ``\x41`` style hex escapes."""
        def _replacer(m: re.Match) -> str:
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)

        return re.sub(r"\\x([0-9a-fA-F]{2})", _replacer, text)

    @staticmethod
    def _try_rot13(text: str) -> str | None:
        """Try ROT13 decode if suspicious keywords appear after rotation.

        We rotate the text and check if common injection keywords emerge.
        """
        import codecs

        rotated = codecs.decode(text, "rot_13")

        # Check if rotation reveals dangerous keywords that weren't there before
        danger_words = [
            "ignore", "system", "prompt", "instruction", "bypass",
            "override", "jailbreak", "admin", "execute", "eval",
        ]
        original_lower = text.lower()
        rotated_lower = rotated.lower()

        new_matches = sum(
            1 for w in danger_words
            if w in rotated_lower and w not in original_lower
        )

        return rotated if new_matches >= 2 else None

    @staticmethod
    def _decode_leetspeak(text: str) -> str:
        """Normalise common leetspeak substitutions."""
        if not _LEET_PATTERN.search(text):
            return text

        def _replace(m: re.Match) -> str:
            return _LEET_MAP.get(m.group(0).lower(), m.group(0))

        return _LEET_PATTERN.sub(_replace, text)

    @staticmethod
    def _rejoin_char_splits(text: str) -> str:
        """Re-join characters separated by spaces/dots/dashes.

        Detects patterns like ``i g n o r e`` or ``i.g.n.o.r.e``
        and joins them back into words.
        """
        # Single chars separated by consistent delimiters (space, dot, dash, underscore)
        # Must be at least 4 chars long to avoid false positives
        pattern = re.compile(
            r"\b([a-zA-Z])(?:\s[a-zA-Z]){3,}\b"
            r"|"
            r"\b([a-zA-Z])(?:\.[a-zA-Z]){3,}\b"
            r"|"
            r"\b([a-zA-Z])(?:-[a-zA-Z]){3,}\b"
        )

        def _join(m: re.Match) -> str:
            # Remove the delimiter characters
            return re.sub(r"[\s.\-]", "", m.group(0))

        return pattern.sub(_join, text)
