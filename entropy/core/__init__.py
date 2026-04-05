"""Core security engine package."""

from __future__ import annotations

from typing import Any

from entropy.core.engine import EntropyEngine
from entropy.core.input_validator import InputValidator
from entropy.core.output_filter import OutputFilter
from entropy.core.pattern_matcher import PatternMatcher

ContextAnalyzer: Any = None
IndirectInjectionDetector: Any = None
InputSanitizer: Any = None
SemanticAnalyzer: Any = None

try:
    from entropy_pro.core.context_analyzer import ContextAnalyzer as _CA

    if _CA is not None:
        ContextAnalyzer = _CA
except ImportError:
    pass

try:
    from entropy_pro.core.indirect_injection_detector import (
        IndirectInjectionDetector as _IID,
    )

    if _IID is not None:
        IndirectInjectionDetector = _IID
except ImportError:
    pass

try:
    from entropy_pro.core.input_sanitizer import InputSanitizer as _IS

    if _IS is not None:
        InputSanitizer = _IS
except ImportError:
    pass

try:
    from entropy_pro.core.semantic_analyzer import SemanticAnalyzer as _SA

    if _SA is not None:
        SemanticAnalyzer = _SA
except ImportError:
    pass

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
