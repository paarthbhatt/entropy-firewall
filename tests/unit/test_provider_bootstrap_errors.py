from __future__ import annotations

import pytest
from fastapi import HTTPException

from entropy.api.dependencies import get_provider
from entropy.config.settings import get_settings


def test_get_provider_missing_keys_has_actionable_message(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ENTROPY_ENVIRONMENT", "development")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ENTROPY_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("ENTROPY_OPENAI_BASE_URL", raising=False)
    get_settings.cache_clear()

    with pytest.raises(HTTPException) as exc_info:
        get_provider()

    assert exc_info.value.status_code == 503
    detail = str(exc_info.value.detail)
    assert "OPENAI_API_KEY" in detail
    assert "OPENAI_BASE_URL" in detail

    get_settings.cache_clear()
