"""Entropy configuration management.

Loads settings from (in priority order):
1. Environment variables (highest)
2. .env file
3. entropy_config.yaml (if exists)
4. Default values (lowest)
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, List, Optional, Union

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------

class InputValidationSettings(BaseSettings):
    """Input validation thresholds."""

    model_config = SettingsConfigDict(env_prefix="ENTROPY_INPUT_")

    max_tokens: int = Field(default=4096, description="Maximum tokens per request")
    max_chars: int = Field(default=32000, description="Maximum characters per request")
    allowed_encodings: List[str] = Field(
        default=["utf-8"], description="Allowed text encodings"
    )
    max_special_chars_ratio: float = Field(
        default=0.3, description="Max ratio of special characters to total"
    )
    max_message_count: int = Field(default=50, description="Max messages in a request")


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration."""

    model_config = SettingsConfigDict(env_prefix="ENTROPY_RATE_LIMIT_")

    rpm: int = Field(default=60, description="Requests per minute per user")
    window: int = Field(default=60, description="Sliding window in seconds")
    burst: int = Field(default=10, description="Burst capacity above base limit")
    per_ip_rpm: int = Field(default=120, description="Requests per minute per IP")
    global_rpm: int = Field(default=1000, description="Global requests per minute")


class EngineSettings(BaseSettings):
    """Entropy engine detection settings."""

    model_config = SettingsConfigDict(env_prefix="ENTROPY_")
    
    # Engine toggles
    enable_semantic_analysis: bool = Field(
        default=False, description="Enable Pro LLM-based semantic analysis"
    )
    enable_context_analysis: bool = Field(
        default=True, description="Enable multi-turn context analysis"
    )
    
    # Thresholds
    pattern_threshold: float = Field(
        default=0.7, description="Minimum confidence to flag a pattern match"
    )
    block_on_detection: bool = Field(
        default=True, description="Block requests on HIGH/CRITICAL threats"
    )
    max_history_length: int = Field(
        default=10, description="Max conversation turns for context analysis"
    )

    @field_validator("pattern_threshold")
    @classmethod
    def _validate_threshold(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("pattern_threshold must be between 0.0 and 1.0")
        return v


class OutputFilterSettings(BaseSettings):
    """Output filtering configuration."""

    model_config = SettingsConfigDict(env_prefix="ENTROPY_OUTPUT_")

    pii_detection: bool = Field(default=True, description="Enable PII detection")
    code_scanning: bool = Field(default=True, description="Enable code injection scanning")
    system_prompt_protection: bool = Field(
        default=True, description="Detect system prompt leakage"
    )
    redact_mode: bool = Field(
        default=True, description="Redact sensitive data (True) or block entirely (False)"
    )


class DatabaseSettings(BaseSettings):
    """PostgreSQL database configuration."""

    model_config = SettingsConfigDict(env_prefix="ENTROPY_DB_")

    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, description="Database port")
    name: str = Field(default="entropy", description="Database name")
    user: str = Field(default="entropy", description="Database user")
    password: str = Field(default="entropy_password", description="Database password")
    min_connections: int = Field(default=2, description="Minimum pool connections")
    max_connections: int = Field(default=10, description="Maximum pool connections")

    @property
    def dsn(self) -> str:
        """Build PostgreSQL DSN string."""
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )


class RedisSettings(BaseSettings):
    """Redis configuration."""

    model_config = SettingsConfigDict(env_prefix="ENTROPY_REDIS_")

    url: str = Field(default="redis://localhost:6379/0", description="Redis URL")
    socket_timeout: int = Field(default=5, description="Socket timeout seconds")


class LoggingSettings(BaseSettings):
    """Logging configuration."""

    model_config = SettingsConfigDict(env_prefix="ENTROPY_LOG_")

    level: str = Field(default="INFO", description="Log level")
    json_format: bool = Field(default=True, description="Use JSON log format")
    log_blocked: bool = Field(default=True, description="Log blocked requests")
    log_suspicious: bool = Field(default=True, description="Log suspicious patterns")


# ---------------------------------------------------------------------------
# Main Settings
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    """Root application settings."""

    model_config = SettingsConfigDict(
        env_prefix="ENTROPY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="Entropy LLM Firewall")
    version: str = Field(default="0.1.0")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)

    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
    )

    # Security
    master_api_key: str = Field(
        default="ent-change-this-in-production",
        description="Master API key for bootstrap. CHANGE IN PRODUCTION.",
    )

    # LLM Provider
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    openai_base_url: Optional[str] = Field(default=None, alias="OPENAI_BASE_URL", description="Optional custom base URL for Azure/LocalAI")

    # Sub-configs
    input_validation: InputValidationSettings = Field(
        default_factory=InputValidationSettings
    )
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    engine: EngineSettings = Field(default_factory=EngineSettings)
    output_filter: OutputFilterSettings = Field(default_factory=OutputFilterSettings)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    @field_validator("environment")
    @classmethod
    def _validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "testing"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {sorted(allowed)}")
        return v


# ---------------------------------------------------------------------------
# YAML config support
# ---------------------------------------------------------------------------

def _load_yaml_config() -> dict[str, Any]:
    """Attempt to load entropy_config.yaml from common locations."""
    search_paths = [
        Path("config.local.yaml"),
        Path("config.yaml"),
        Path("entropy_config.yaml"),
        Path("entropy_config.yml"),
        Path.home() / ".entropy" / "config.yaml",
    ]
    for path in search_paths:
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
            except Exception:
                pass # Silently ignore config load failures to fallback to defaults
    return {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get application settings (singleton, cached).

    Merges YAML config (if found) with env vars. Env vars always win.
    """
    yaml_data = _load_yaml_config()
    # Pydantic Settings priority: __init__ kwargs > env vars > env_file > field default
    # So we pass yaml_data as kwargs
    return Settings(**yaml_data)
