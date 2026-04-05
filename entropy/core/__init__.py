"""Core security engine package."""

from entropy.core.engine import EntropyEngine
from entropy.core.input_validator import InputValidator
from entropy.core.output_filter import OutputFilter
from entropy.core.pattern_matcher import PatternMatcher

try:
    from entropy_pro.core.context_analyzer import ContextAnalyzer  # type: ignore[import]
except ImportError:  # pragma: no cover
    ContextAnalyzer = None  # type: ignore[assignment]

try:
    from entropy_pro.core.indirect_injection_detector import (
        IndirectInjectionDetector,  # type: ignore[import]
    )
except ImportError:  # pragma: no cover
    IndirectInjectionDetector = None  # type: ignore[assignment]

try:
    from entropy_pro.core.input_sanitizer import InputSanitizer  # type: ignore[import]
except ImportError:  # pragma: no cover
    InputSanitizer = None  # type: ignore[assignment]

try:
    from entropy_pro.core.semantic_analyzer import SemanticAnalyzer  # type: ignore[import]
except ImportError:  # pragma: no cover
    SemanticAnalyzer = None  # type: ignore[assignment]

__all__ = [
    "ContextAnalyzer",
    "EntropyEngine",
    "IndirectInjectionDetector",
    "InputSanitizer",
    "InputValidator",
    "OutputFilter",
    "PatternMatcher",
    "SemanticAnalyzer",
]
