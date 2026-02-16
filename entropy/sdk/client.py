"""Entropy Python SDK — secure wrapper for OpenAI interaction.

Supports both synchronous and asynchronous usage with an OpenAI-compatible interface.

Usage::

    from entropy.sdk.client import EntropyClient

    # Synchronous usage
    client = EntropyClient(base_url="http://localhost:8000", api_key="ent-...")
    
    # 1. Standard approach
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello!"}]
    )
    
    # 2. Direct analysis
    verdict = client.analyze("Is this safe?")
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union, Generator, AsyncGenerator

import httpx

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class EntropyError(Exception):
    """Base exception for Entropy SDK errors."""
    def __init__(self, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.data = data or {}

class EntropyBlockedError(EntropyError):
    """Raised when a request is blocked by the firewall (403)."""

class EntropyRateLimitError(EntropyError):
    """Raised when rate limits are exceeded (429)."""

class EntropyConnectionError(EntropyError):
    """Raised when connection to Entropy server fails."""

# ---------------------------------------------------------------------------
# Namespace proxies (OpenAI compatibility)
# ---------------------------------------------------------------------------

class CompletionsNamespace:
    def __init__(self, client: "EntropyClient"):
        self._client = client

    def create(self, **kwargs) -> Dict[str, Any]:
        return self._client._post_chat_completions(**kwargs)

class AsyncCompletionsNamespace:
    def __init__(self, client: "AsyncEntropyClient"):
        self._client = client

    async def create(self, **kwargs) -> Dict[str, Any]:
        return await self._client._post_chat_completions(**kwargs)

class ChatNamespace:
    def __init__(self, client: "EntropyClient"):
        self.completions = CompletionsNamespace(client)

class AsyncChatNamespace:
    def __init__(self, client: "AsyncEntropyClient"):
        self.completions = AsyncCompletionsNamespace(client)

# ---------------------------------------------------------------------------
# Synchronous Client
# ---------------------------------------------------------------------------

class EntropyClient:
    """Synchronous Python SDK for Entropy LLM Firewall."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._http = httpx.Client(
            base_url=self.base_url,
            headers={
                "X-API-Key": self.api_key or "",
                "Content-Type": "application/json"
            },
            timeout=timeout,
        )
        
        # OpenAI-compatible namespaces
        self.chat = ChatNamespace(self)

    def analyze(self, text: str, history: List[Dict[str, Any]] = []) -> Dict[str, Any]:
        """Analyze content directly without forwarding to LLM."""
        resp = self._request("POST", "/v1/analyze", json={"text": text, "history": history})
        return resp

    def health(self) -> Dict[str, Any]:
        """Check server health."""
        return self._request("GET", "/health")

    def _post_chat_completions(self, **kwargs) -> Dict[str, Any]:
        """Internal handler for chat completions."""
        # Check for stream
        stream = kwargs.get("stream", False)
        if stream:
            # For streaming, we return a generator
            return self._stream_request("POST", "/v1/chat/completions", json=kwargs)
        
        return self._request("POST", "/v1/chat/completions", json=kwargs)

    def _request(self, method: str, path: str, **kwargs) -> Any:
        try:
            resp = self._http.request(method, path, **kwargs)
            if resp.status_code == 403:
                raise EntropyBlockedError("Request blocked by Entropy", resp.json())
            if resp.status_code == 429:
                raise EntropyRateLimitError("Rate limit exceeded", resp.json())
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError as e:
            raise EntropyConnectionError(f"Connection error: {e}")

    def _stream_request(self, method: str, path: str, **kwargs) -> Generator[str, None, None]:
        try:
            with self._http.stream(method, path, **kwargs) as resp:
                if resp.status_code == 403:
                    # Try to read body for error details
                    try:
                        data = resp.read()
                        import json
                        err = json.loads(data)
                    except:
                        err = {}
                    raise EntropyBlockedError("Request blocked by Entropy", err)
                
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if line:
                        yield line
        except httpx.RequestError as e:
            raise EntropyConnectionError(f"Connection error: {e}")

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "EntropyClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Asynchronous Client
# ---------------------------------------------------------------------------

class AsyncEntropyClient:
    """Asynchronous Python SDK for Entropy LLM Firewall."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "X-API-Key": self.api_key or "",
                "Content-Type": "application/json"
            },
            timeout=timeout,
        )
        
        # OpenAI-compatible namespaces
        self.chat = AsyncChatNamespace(self)

    async def analyze(self, text: str, history: List[Dict[str, Any]] = []) -> Dict[str, Any]:
        """Analyze content directly without forwarding to LLM."""
        return await self._request("POST", "/v1/analyze", json={"text": text, "history": history})

    async def health(self) -> Dict[str, Any]:
        """Check server health."""
        return await self._request("GET", "/health")

    async def _post_chat_completions(self, **kwargs) -> Any:
        stream = kwargs.get("stream", False)
        if stream:
            return self._stream_request("POST", "/v1/chat/completions", json=kwargs)
        return await self._request("POST", "/v1/chat/completions", json=kwargs)

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        try:
            resp = await self._http.request(method, path, **kwargs)
            if resp.status_code == 403:
                raise EntropyBlockedError("Request blocked by Entropy", resp.json())
            if resp.status_code == 429:
                raise EntropyRateLimitError("Rate limit exceeded", resp.json())
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError as e:
            raise EntropyConnectionError(f"Connection error: {e}")

    async def _stream_request(self, method: str, path: str, **kwargs) -> AsyncGenerator[str, None]:
        try:
            async with self._http.stream(method, path, **kwargs) as resp:
                if resp.status_code == 403:
                    data = await resp.read() # Read the error response
                    import json
                    try:
                        err = json.loads(data)
                    except:
                        err = {}
                    raise EntropyBlockedError("Request blocked by Entropy", err)
                
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line:
                        yield line
        except httpx.RequestError as e:
            raise EntropyConnectionError(f"Connection error: {e}")

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncEntropyClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
