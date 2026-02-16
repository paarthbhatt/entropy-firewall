"""Guardrails-as-Code configuration system.

This module allows security rules to be defined in a YAML file that can be
version-controlled, code-reviewed, and deployed alongside your application.

Usage:
    # entropy.yaml (in your project root)
    version: 1
    rules:
      - name: protect-system-prompt
        action: block
        confidence: 0.6
      - name: redact-pii
        mode: sanitize
    learning:
      enabled: true
      feedback-webhook: https://yourapp.com/entropy/feedback
    
    # In your code:
    from entropy.guardrails import load_guardrails
    
    config = load_guardrails("entropy.yaml")
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Schema Models
# ---------------------------------------------------------------------------

# Type alias for rule actions
RuleAction = Literal["block", "sanitize", "allow", "log"]


class Rule(BaseModel):
    """Individual guardrail rule."""
    
    name: str = Field(..., description="Unique rule identifier")
    action: RuleAction = Field(default="block", description="Action to take")
    confidence: float = Field(
        default=0.7,
        description="Minimum confidence threshold (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Threat categories to match (empty = all)",
    )
    channels: list[str] = Field(
        default_factory=list,
        description="Channel names to apply rule to (empty = all)",
    )
    mode: Optional[str] = Field(
        default=None,
        description="Mode for sanitize action (redact, mask, escape)",
    )
    enabled: bool = Field(default=True, description="Whether rule is active")


class LearningConfig(BaseModel):
    """Learning mode configuration."""
    
    enabled: bool = Field(default=False, description="Enable learning mode")
    feedback_webhook: Optional[str] = Field(
        default=None,
        description="Webhook URL for sending feedback",
    )
    auto_update_patterns: bool = Field(
        default=False,
        description="Auto-update patterns based on feedback",
    )


class GuardrailsConfig(BaseModel):
    """Complete guardrails configuration."""
    
    version: int = Field(default=1, description="Config version")
    rules: list[Rule] = Field(default_factory=list, description="Guardrail rules")
    learning: LearningConfig = Field(
        default_factory=LearningConfig,
        description="Learning configuration",
    )
    defaults: dict[str, Any] = Field(
        default_factory=dict,
        description="Default settings",
    )
    
    def get_rule(self, name: str) -> Optional[Rule]:
        """Get rule by name."""
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None
    
    def get_applicable_rules(self, channel: Optional[str] = None) -> list[Rule]:
        """Get rules applicable to a channel."""
        applicable = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if channel and rule.channels and channel not in rule.channels:
                continue
            applicable.append(rule)
        return applicable


# ---------------------------------------------------------------------------
# Default Configuration
# ---------------------------------------------------------------------------

DEFAULT_GUARDRAILS = GuardrailsConfig(
    version=1,
    rules=[
        Rule(
            name="block-critical-injection",
            action="block",
            confidence=0.8,
            categories=["direct_injection", "jailbreak"],
        ),
        Rule(
            name="block-credential-theft",
            action="block",
            confidence=0.7,
            categories=["data_exfiltration"],
        ),
        Rule(
            name="sanitize-pii",
            action="sanitize",
            confidence=0.5,
            categories=["output_filter"],
            mode="redact",
        ),
        Rule(
            name="log-obfuscation",
            action="log",
            confidence=0.6,
            categories=["obfuscation"],
        ),
    ],
)


# ---------------------------------------------------------------------------
# Loader Functions
# ---------------------------------------------------------------------------

def load_guardrails(
    config_path: Optional[str] = None,
    search_dirs: Optional[list[str]] = None,
) -> GuardrailsConfig:
    """Load guardrails configuration from YAML file.
    
    Args:
        config_path: Specific path to config file
        search_dirs: Directories to search for entropy.yaml
    
    Returns:
        GuardrailsConfig object with loaded rules
        
    Example:
        config = load_guardrails()  # Auto-searches
        config = load_guardrails("my-security-rules.yaml")
    """
    # If explicit path provided, load it
    if config_path:
        path = Path(config_path)
        if path.exists():
            return _load_from_path(path)
        return DEFAULT_GUARDRAILS
    
    # Otherwise search common locations
    search_dirs = search_dirs or [
        ".",
        os.getcwd(),
        Path.cwd().parent,
        Path.home() / ".entropy",
    ]
    
    # Also check ENV var
    env_path = os.environ.get("ENTROPY_GUARDRAILS_PATH")
    if env_path:
        search_dirs.insert(0, env_path)
    
    filenames = [
        "entropy.yaml",
        "entropy.yml",
        "entropy_guardrails.yaml",
        "guardrails.yaml",
        ".entropy.yaml",
    ]
    
    for directory in search_dirs:
        dir_path = Path(directory)
        if not dir_path.exists():
            continue
        for filename in filenames:
            full_path = dir_path / filename
            if full_path.exists():
                return _load_from_path(full_path)
    
    # Return defaults if no config found
    return DEFAULT_GUARDRAILS


def _load_from_path(path: Path) -> GuardrailsConfig:
    """Load configuration from a specific file path."""
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        if not isinstance(data, dict):
            return DEFAULT_GUARDRAILS
        
        return GuardrailsConfig(**data)
    except Exception:
        return DEFAULT_GUARDRAILS


def create_sample_config(path: str = "entropy.yaml") -> None:
    """Create a sample guardrails configuration file.
    
    Args:
        path: Where to write the sample config
    """
    sample = """# Entropy Guardrails Configuration
# Version: 1
# 
# This file defines your security rules. Commit this to your repo
# and version-control your security alongside your code.
#
# Learn more: https://docs.entropy.security/guardrails

version: 1

# Define your security rules
rules:
  # Block critical prompt injection attempts
  - name: block-critical-injection
    action: block
    confidence: 0.8
    categories:
      - direct_injection
      - jailbreak
  
  # Block attempts to steal credentials
  - name: block-credential-theft
    action: block
    confidence: 0.7
    categories:
      - data_exfiltration
  
  # Sanitize PII from LLM responses
  - name: sanitize-pii
    action: sanitize
    confidence: 0.5
    categories:
      - output_filter
    mode: redact
  
  # Log obfuscation attempts but don't block
  - name: log-obfuscation
    action: log
    confidence: 0.6
    categories:
      - obfuscation

# Learning mode - improve rules based on feedback
learning:
  enabled: false
  # Send feedback to improve detection
  # feedback_webhook: https://yourapp.com/api/entropy/feedback
  # Auto-update patterns based on community feedback
  # auto_update_patterns: true

# Default settings
defaults:
  block_on_detection: true
  enable_context_analysis: true
"""
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(sample)
    
    print(f"Created sample guardrails config at: {path}")


__all__ = [
    "GuardrailsConfig",
    "Rule",
    "RuleAction",
    "LearningConfig",
    "load_guardrails",
    "create_sample_config",
    "DEFAULT_GUARDRAILS",
]
