from __future__ import annotations

from entropy.config.settings import Settings


def test_settings_accepts_entropy_openai_api_key_alias(monkeypatch) -> None:
    monkeypatch.setenv("ENTROPY_OPENAI_API_KEY", "entropy-alias-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = Settings(_env_file=None)
    assert settings.openai_api_key == "entropy-alias-key"


def test_settings_accepts_entropy_openai_base_url_alias(monkeypatch) -> None:
    monkeypatch.setenv("ENTROPY_OPENAI_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    settings = Settings(_env_file=None)
    assert settings.openai_base_url == "http://localhost:11434/v1"
