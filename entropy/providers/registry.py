"""Provider registry and factory for multi-provider support.

This module provides a unified interface for routing requests to different
LLM providers based on model name prefixes or explicit configuration.
"""

from __future__ import annotations

from typing import Any

import structlog

from entropy.config import get_settings
from entropy.providers.base import BaseProvider  # noqa: TC001
from entropy.providers.openai_provider import OpenAIProvider

logger = structlog.get_logger(__name__)

# Model prefix to provider mapping
# These prefixes are used to automatically route requests to the correct provider
MODEL_PREFIX_MAP: dict[str, str] = {
    # OpenAI models
    "gpt-": "openai",
    "o1-": "openai",
    "o3-": "openai",
    "chatgpt-": "openai",
    # Anthropic models
    "claude-": "anthropic",
    "claude2-": "anthropic",
    "claude3-": "anthropic",
    # Google models
    "gemini-": "google",
    "gemini": "google",
    "palm-": "google",
    # Groq models
    "llama-": "groq",
    "mixtral-": "groq",
    "gemma-": "groq",
    # OpenRouter (catch-all, requires explicit header)
    # OpenRouter uses the model name as the full path
}

# Provider class registry (lazy-loaded to avoid import errors)
_PROVIDER_CLASSES: dict[str, type[BaseProvider]] = {
    "openai": OpenAIProvider,
}


def _load_anthropic_provider() -> type[BaseProvider] | None:
    """Lazily load Anthropic provider."""
    try:
        from entropy.providers.anthropic_provider import AnthropicProvider  # noqa: PLC0415

        return AnthropicProvider
    except ImportError:
        logger.warning("AnthropicProvider not available - install anthropic package")
        return None


def _load_google_provider() -> type[BaseProvider] | None:
    """Lazily load Google provider."""
    try:
        from entropy.providers.google_provider import GoogleProvider  # noqa: PLC0415

        return GoogleProvider
    except ImportError:
        logger.warning("GoogleProvider not available - install google-generativeai package")
        return None


def _load_groq_provider() -> type[BaseProvider] | None:
    """Lazily load Groq provider."""
    try:
        from entropy.providers.groq_provider import GroqProvider  # noqa: PLC0415

        return GroqProvider
    except ImportError:
        logger.warning("GroqProvider not available - install groq package")
        return None


def _load_openrouter_provider() -> type[BaseProvider] | None:
    """Lazily load OpenRouter provider."""
    try:
        from entropy.providers.openrouter_provider import OpenRouterProvider  # noqa: PLC0415

        return OpenRouterProvider
    except ImportError:
        logger.warning("OpenRouterProvider not available")
        return None


def _load_google_provider() -> type[BaseProvider] | None:
    """Lazily load Google provider."""
    try:
        from entropy.providers.google_provider import (  # noqa: PLC0415
            GoogleProvider,
        )

        return GoogleProvider
    except ImportError:
        logger.warning("GoogleProvider not available - install google-generativeai package")
        return None


def _load_groq_provider() -> type[BaseProvider] | None:
    """Lazily load Groq provider."""
    try:
        from entropy.providers.groq_provider import GroqProvider  # noqa: PLC0415

        return GroqProvider
    except ImportError:
        logger.warning("GroqProvider not available - install groq package")
        return None


def _load_openrouter_provider() -> type[BaseProvider] | None:
    """Lazily load OpenRouter provider."""
    try:
        from entropy.providers.openrouter_provider import (  # noqa: PLC0415
            OpenRouterProvider,
        )

        return OpenRouterProvider
    except ImportError:
        logger.warning("OpenRouterProvider not available")
        return None


def get_provider_class(name: str) -> type[BaseProvider] | None:
    """Get a provider class by name with lazy loading.

    Args:
        name: Provider name (e.g., 'openai', 'anthropic', 'google')

    Returns:
        Provider class or None if not available
    """
    # Check cache first
    if name in _PROVIDER_CLASSES:
        return _PROVIDER_CLASSES[name]

    # Lazy load providers
    loaders = {
        "anthropic": _load_anthropic_provider,
        "google": _load_google_provider,
        "groq": _load_groq_provider,
        "openrouter": _load_openrouter_provider,
    }

    if name in loaders:
        provider_class = loaders[name]()
        if provider_class:
            _PROVIDER_CLASSES[name] = provider_class
        return provider_class

    return None


class ProviderRegistry:
    """Registry for managing LLM providers.

    Handles provider instantiation, caching, and request routing.

    Usage:
        registry = ProviderRegistry()
        provider = registry.get_provider("claude-3-opus", api_key="...")
        response = await provider.chat_completion(...)
    """

    def __init__(self) -> None:
        self._instances: dict[str, BaseProvider] = {}
        self._settings = get_settings()

    def detect_provider(self, model: str, override: str | None = None) -> str:
        """Detect which provider should handle a given model.

        Detection order:
        1. Explicit override (from header/config)
        2. Model prefix matching
        3. Default provider from config
        4. Fallback to OpenAI

        Args:
            model: Model name (e.g., 'gpt-4', 'claude-3-opus')
            override: Explicit provider override

        Returns:
            Provider name
        """
        if override:
            return override.lower()

        # Check model prefixes
        model_lower = model.lower()
        for prefix, provider in MODEL_PREFIX_MAP.items():
            if model_lower.startswith(prefix):
                return provider

        # Check config for default provider
        provider_config = getattr(self._settings, "provider", None)
        if provider_config and hasattr(provider_config, "default"):
            default = provider_config.default
            if default:
                return default

        # Fallback to OpenAI
        return "openai"

    def get_provider(
        self,
        model: str,
        provider_override: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> BaseProvider:
        """Get or create a provider instance for the given model.

        Args:
            model: Model name
            provider_override: Explicit provider name override
            api_key: Optional API key (falls back to settings)
            base_url: Optional base URL override

        Returns:
            Provider instance

        Raises:
            ValueError: If provider is not available or misconfigured
        """
        provider_name = self.detect_provider(model, provider_override)

        # Check cache (include API key in cache key for multi-tenant scenarios)
        cache_key = f"{provider_name}:{api_key or 'default'}:{base_url or 'default'}"
        if cache_key in self._instances:
            return self._instances[cache_key]

        # Get provider class
        provider_class = get_provider_class(provider_name)
        if provider_class is None:
            raise ValueError(
                f"Provider '{provider_name}' is not available. "
                f"Check that required dependencies are installed."
            )

        # Get API key from settings if not provided
        if api_key is None:
            api_key = self._get_api_key(provider_name)

        if api_key is None:
            raise ValueError(
                f"No API key configured for provider '{provider_name}'. "
                f"Set the appropriate environment variable (e.g., ANTHROPIC_API_KEY)."
            )

        # Get base URL from settings if not provided
        if base_url is None:
            base_url = self._get_base_url(provider_name)

        # Create provider instance
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url

        # Some providers may need extra config
        extra_config = self._get_extra_config(provider_name)
        kwargs.update(extra_config)

        instance = provider_class(**kwargs)
        self._instances[cache_key] = instance

        logger.info(
            "Provider instantiated",
            provider=provider_name,
            model=model,
            has_base_url=bool(base_url),
        )

        return instance

    def _get_api_key(self, provider_name: str) -> str | None:
        """Get API key for provider from settings."""
        key_map = {
            "openai": "openai_api_key",
            "anthropic": "anthropic_api_key",
            "google": "google_api_key",
            "groq": "groq_api_key",
            "openrouter": "openrouter_api_key",
        }

        settings_key = key_map.get(provider_name)
        if settings_key:
            # Try settings first, then env var
            key = getattr(self._settings, settings_key, None)
            if key:
                return key

            # Try environment variable
            import os  # noqa: PLC0415

            env_key = provider_name.upper() + "_API_KEY"
            return os.environ.get(env_key)

        return None

    def _get_base_url(self, provider_name: str) -> str | None:
        """Get base URL for provider from settings."""
        url_map = {
            "openai": "openai_base_url",
            "anthropic": "anthropic_base_url",
            "google": "google_base_url",
            "groq": "groq_base_url",
            "openrouter": "openrouter_base_url",
        }

        settings_key = url_map.get(provider_name)
        if settings_key:
            return getattr(self._settings, settings_key, None)

        return None

    def _get_extra_config(self, provider_name: str) -> dict[str, Any]:
        """Get extra provider-specific configuration."""
        # Providers can have custom settings
        config: dict[str, Any] = {}

        # OpenRouter needs a default site URL header
        if provider_name == "openrouter":
            provider_settings = getattr(self._settings, "provider", None)
            if provider_settings:
                if hasattr(provider_settings, "openrouter_site_url"):
                    config["site_url"] = provider_settings.openrouter_site_url
                if hasattr(provider_settings, "openrouter_provider_name"):
                    config["provider_name"] = provider_settings.openrouter_provider_name

        return config

    async def close_all(self) -> None:
        """Close all cached provider connections."""
        for name, instance in self._instances.items():
            try:
                await instance.close()
            except Exception as e:
                logger.warning("Failed to close provider", provider=name, error=str(e))

        self._instances.clear()
        logger.info("All providers closed")

    def list_available_providers(self) -> list[str]:
        """List all available providers based on installed dependencies."""
        available = []

        for name in ["openai", "anthropic", "google", "groq", "openrouter"]:
            if get_provider_class(name):
                available.append(name)

        return available


# Singleton registry instance
_registry: ProviderRegistry | None = None


def get_registry() -> ProviderRegistry:
    """Get the singleton provider registry."""
    global _registry  # noqa: PLW0603
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry


__all__ = [
    "MODEL_PREFIX_MAP",
    "ProviderRegistry",
    "get_provider_class",
    "get_registry",
]
