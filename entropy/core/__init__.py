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
    from entropy_pro.core.context_analyzer import ContextAnalyzer as ContextAnalyzerPro

    if ContextAnalyzerPro is not None:
        ContextAnalyzer = ContextAnalyzerPro
except ImportError:
    pass

try:
    from entropy_pro.core.indirect_injection_detector import (
        IndirectInjectionDetector as IndirectInjectionDetectorPro,
    )

    if IndirectInjectionDetectorPro is not None:
        IndirectInjectionDetector = IndirectInjectionDetectorPro
except ImportError:
    pass

try:
    from entropy_pro.core.input_sanitizer import InputSanitizer as InputSanitizerPro

    if InputSanitizerPro is not None:
        InputSanitizer = InputSanitizerPro
except ImportError:
    pass

try:
    from entropy_pro.core.semantic_analyzer import SemanticAnalyzer as SemanticAnalyzerPro

    if SemanticAnalyzerPro is not None:
        SemanticAnalyzer = SemanticAnalyzerPro
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
