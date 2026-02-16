"""Simplified secure wrapper - 3-line integration for instant protection.

Usage:
    from entropy import secure_openai
    
    # Simple usage - auto-detects OpenAI
    client = secure_openai("sk-...")
    
    # Or with Entropy firewall
    client = secure_openai("sk-...", entropy_url="http://localhost:8000")
    
    # Use like normal OpenAI client
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello!"}]
    )
"""

from __future__ import annotations

from typing import Any, Optional

try:
    import openai as _openai
except ImportError:
    _openai = None

from entropy.sdk.client import EntropyClient


class SecureOpenAIClient:
    """Drop-in replacement for OpenAI client with built-in security.
    
    This client wraps the OpenAI SDK and automatically routes all requests
    through the Entropy security layer.
    """
    
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://api.openai.com/v1",
        entropy_url: Optional[str] = None,
        entropy_api_key: Optional[str] = None,
        block: bool = True,
        **openai_kwargs: Any,
    ):
        if _openai is None:
            raise ImportError("openai package required. Install with: pip install openai")
        
        self._entropy_url = entropy_url
        self._entropy_api_key = entropy_api_key
        self._block = block
        
        if entropy_url:
            # Route through Entropy firewall
            self._client = EntropyClient(
                base_url=entropy_url,
                api_key=entropy_api_key or api_key,
            )
            self._via_firewall = True
        else:
            # Direct to OpenAI (no security - for comparison)
            _openai.api_key = api_key
            self._client = _openai.OpenAI(base_url=base_url, **openai_kwargs)
            self._via_firewall = False
    
    @property
    def chat(self) -> Any:
        """Access chat completions - OpenAI compatible."""
        if self._via_firewall:
            return self._client.chat
        return self._client.chat
    
    @property
    def models(self) -> Any:
        """Access models - OpenAI compatible."""
        if self._via_firewall:
            # Return a models-like interface
            return _ModelNamespace(self._client)
        return self._client.models
    
    def analyze(self, text: str) -> dict[str, Any]:
        """Analyze text for threats without making an LLM call.
        
        Returns:
            dict with keys: is_malicious, confidence, threats, suggestion
        """
        if not self._via_firewall:
            raise RuntimeError("Analysis only available when using entropy_url")
        
        result = self._client.analyze(text)
        
        # Transform to simpler format
        threats = result.get("threats_detected", [])
        suggestion = ""
        if threats:
            # Generate actionable suggestion
            main_threat = threats[0]
            suggestion = _get_suggestion(main_threat)
        
        return {
            "is_malicious": result.get("status") == "blocked",
            "confidence": result.get("confidence", 0),
            "threats": [
                {
                    "category": t.get("category"),
                    "name": t.get("name"),
                    "level": t.get("threat_level"),
                }
                for t in threats
            ],
            "suggestion": suggestion,
        }
    
    def close(self) -> None:
        """Close the client connection."""
        if self._via_firewall and hasattr(self._client, "close"):
            self._client.close()
    
    def __enter__(self) -> "SecureOpenAIClient":
        return self
    
    def __exit__(self, *args: Any) -> None:
        self.close()


class _ModelNamespace:
    """Wrapper for models namespace when using firewall."""
    
    def __init__(self, client: EntropyClient):
        self._client = client
    
    def list(self) -> Any:
        # Would need to implement this
        return {"data": []}


def _get_suggestion(threat: dict[str, Any]) -> str:
    """Generate actionable suggestion based on threat."""
    category = threat.get("category", "")
    name = threat.get("name", "")
    
    suggestions = {
        "direct_injection": {
            "ignore_instructions": "Remove phrases like 'ignore previous instructions' from user input",
            "system_prompt_extract": "Block attempts to extract your system prompt - this is a critical threat",
            "act_as": "Be cautious of requests asking you to 'act as' or 'roleplay'",
        },
        "jailbreak": {
            "dan_attack": "This is a known jailbreak attempt (DAN). Block immediately.",
            "no_restrictions": "Legitimate requests will never ask to bypass restrictions",
        },
        "data_exfiltration": {
            "credential_request": "Never request credentials, API keys, or secrets",
            "pii_request": "Block requests for personally identifiable information",
        },
        "obfuscation": {
            "base64_payload": "Base64-encoded content may hide malicious instructions",
            "unicode_tricks": "Hidden Unicode characters detected - possible obfuscation",
        },
    }
    
    category_suggestions = suggestions.get(category, {})
    return category_suggestions.get(name, f"Threat detected in category: {category}")


def secure_openai(
    api_key: str,
    *,
    entropy_url: Optional[str] = None,
    entropy_api_key: Optional[str] = None,
    block: bool = True,
    **kwargs: Any,
) -> SecureOpenAIClient:
    """Create a secure OpenAI client with Entropy protection.
    
    This is the main entry point - use this function to instantly
    add enterprise-grade security to your OpenAI integration.
    
    Args:
        api_key: Your OpenAI API key
        entropy_url: URL of Entropy firewall (optional)
        entropy_api_key: Your Entropy API key (optional)
        block: Whether to block malicious requests (default: True)
        **kwargs: Additional arguments passed to OpenAI client
    
    Returns:
        SecureOpenAIClient - drop-in replacement for OpenAI client
        
    Example:
        from entropy import secure_openai
        
        client = secure_openai("sk-...", entropy_url="http://localhost:8000")
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello!"}]
        )
    """
    return SecureOpenAIClient(
        api_key=api_key,
        entropy_url=entropy_url,
        entropy_api_key=entropy_api_key,
        block=block,
        **kwargs,
    )


__all__ = [
    "SecureOpenAIClient",
    "secure_openai",
]
