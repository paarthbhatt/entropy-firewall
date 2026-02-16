"""Entropy LLM Firewall — Ordering the chaos.

A universal, cloud-based security layer that sits between users/applications
and Large Language Model APIs. Sanitizes inputs to prevent prompt injection
and filters outputs to protect sensitive data.

Quick Start:
    from entropy import secure_openai
    
    # Protect your OpenAI calls with 3 lines
    client = secure_openai("sk-...", entropy_url="http://localhost:8000")
    response = client.chat.completions.create(model="gpt-4", messages=[...])
"""

from entropy.sdk.secure import secure_openai, SecureOpenAIClient
from entropy.sdk.client import EntropyClient, AsyncEntropyClient

__version__ = "0.1.0"
__app_name__ = "Entropy LLM Firewall"

__all__ = [
    "secure_openai",
    "SecureOpenAIClient",
    "EntropyClient",
    "AsyncEntropyClient",
]
