"""Framework auto-detection and patching for LangChain, LlamaIndex, AutoGen.

This module provides zero-code integration with popular LLM frameworks.
Run `entropy add langchain` or use the programmatic API to auto-patch
your existing framework usage.

Usage:
    # Auto-detect and patch installed frameworks
    from entropy.integrations import auto_patch

    # Patches any detected frameworks
    auto_patch()

    # Or patch specific framework
    from entropy.integrations.langchain import patch_langchain
    patch_langchain(entropy_url="http://localhost:8000")
"""

from __future__ import annotations

import importlib
from typing import Any

FRAMEWORKS: dict[str, type[FrameworkIntegration]] = {}


def register_framework(cls: type[FrameworkIntegration]) -> type[FrameworkIntegration]:
    """Decorator to register a framework integration."""
    FRAMEWORKS[cls.name] = cls
    return cls


class FrameworkIntegration:
    """Base class for framework integrations."""

    name: str = ""
    package_name: str = ""
    description: str = ""

    @classmethod
    def is_installed(cls) -> bool:
        """Check if the framework is installed."""
        return importlib.util.find_spec(cls.package_name) is not None  # type: ignore[attr-defined]

    @classmethod
    def patch(cls, **kwargs: Any) -> bool:
        """Patch the framework to use Entropy. Returns True if successful."""
        raise NotImplementedError


@register_framework
class LangChainIntegration(FrameworkIntegration):
    """Integration for LangChain."""

    name = "langchain"
    package_name = "langchain"
    description = "Patch LangChain to route through Entropy firewall"

    @classmethod
    def patch(cls, **kwargs: Any) -> bool:
        """Patch LangChain's ChatOpenAI to use Entropy."""
        entropy_url = kwargs.get("entropy_url", "http://localhost:8000")
        entropy_api_key = kwargs.get("entropy_api_key")

        try:
            from langchain_openai import (  # noqa: PLC0415
                ChatOpenAI,  # type: ignore[import-not-found]
            )

            original_class: type = ChatOpenAI

            class SecuredChatOpenAI(original_class):
                """ChatOpenAI wrapper that routes through Entropy."""

                def __init__(self, **init_kwargs: Any):
                    init_kwargs["base_url"] = entropy_url
                    if entropy_api_key:
                        init_kwargs["api_key"] = entropy_api_key
                    super().__init__(**init_kwargs)

            import langchain_openai as langchain_openai_module  # noqa: PLC0415

            langchain_openai_module.ChatOpenAI = SecuredChatOpenAI

            return True
        except ImportError:
            return False


@register_framework
class LlamaIndexIntegration(FrameworkIntegration):
    """Integration for LlamaIndex."""

    name = "llama-index"
    package_name = "llama_index"
    description = "Patch LlamaIndex to route through Entropy firewall"

    @classmethod
    def patch(cls, **kwargs: Any) -> bool:
        """Patch LlamaIndex's OpenAI wrapper."""
        entropy_url = kwargs.get("entropy_url", "http://localhost:8000")
        entropy_api_key = kwargs.get("entropy_api_key")

        try:
            from llama_index.llms.openai import (  # noqa: PLC0415
                OpenAI,  # type: ignore[import-not-found]
            )

            original_class: type = OpenAI

            class SecuredOpenAI(original_class):
                """OpenAI wrapper that routes through Entropy."""

                def __init__(self, **init_kwargs: Any):
                    init_kwargs["base_url"] = entropy_url
                    if entropy_api_key:
                        init_kwargs["api_key"] = entropy_api_key
                    super().__init__(**init_kwargs)

            import llama_index.llms.openai as llama_index_llms  # noqa: PLC0415

            llama_index_llms.OpenAI = SecuredOpenAI

            return True
        except ImportError:
            return False


@register_framework
class AutoGenIntegration(FrameworkIntegration):
    """Integration for AutoGen."""

    name = "autogen"
    package_name = "autogen"
    description = "Patch AutoGen to route through Entropy firewall"

    @classmethod
    def patch(cls, **kwargs: Any) -> bool:
        """Patch AutoGen's OpenAI wrapper."""
        entropy_url = kwargs.get("entropy_url", "http://localhost:8000")
        entropy_api_key = kwargs.get("entropy_api_key")

        try:
            from autogen import OpenAI  # type: ignore[import-not-found]  # noqa: PLC0415

            original_class: type = OpenAI

            class SecuredOpenAI(original_class):
                """OpenAI wrapper that routes through Entropy."""

                def __init__(self, **init_kwargs: Any):
                    init_kwargs["base_url"] = entropy_url
                    if entropy_api_key:
                        init_kwargs["api_key"] = entropy_api_key
                    super().__init__(**init_kwargs)

            import autogen as autogen_module  # noqa: PLC0415

            autogen_module.OpenAI = SecuredOpenAI

            return True
        except ImportError:
            return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def auto_patch(
    entropy_url: str = "http://localhost:8000",
    entropy_api_key: str | None = None,
) -> dict[str, bool]:
    """Auto-detect and patch all installed frameworks.

    Args:
        entropy_url: URL of Entropy firewall
        entropy_api_key: Entropy API key (optional)

    Returns:
        Dict mapping framework name to patch success status

    Example:
        from entropy.integrations import auto_patch

        results = auto_patch(
            entropy_url="http://localhost:8000",
            entropy_api_key="ent-..."
        )
        # {'langchain': True, 'llama-index': True, 'autogen': False}
    """
    results = {}

    for name, integration in FRAMEWORKS.items():
        if integration.is_installed():
            try:
                results[name] = integration.patch(
                    entropy_url=entropy_url,
                    entropy_api_key=entropy_api_key,
                )
            except Exception:
                results[name] = False
        else:
            results[name] = False

    return results


def detect_frameworks() -> dict[str, bool]:
    """Detect which frameworks are installed.

    Returns:
        Dict mapping framework name to whether it's installed
    """
    return {name: integration.is_installed() for name, integration in FRAMEWORKS.items()}


def patch_framework(
    framework: str,
    **kwargs: Any,
) -> bool:
    """Patch a specific framework.

    Args:
        framework: Framework name (langchain, llama-index, autogen)
        **kwargs: Additional arguments (entropy_url, entropy_api_key)

    Returns:
        True if patch successful, False otherwise
    """
    integration = FRAMEWORKS.get(framework)
    if not integration:
        return False

    if not integration.is_installed():
        return False

    return integration.patch(**kwargs)


__all__ = [
    "FrameworkIntegration",
    "auto_patch",
    "detect_frameworks",
    "patch_framework",
    "register_framework",
]
