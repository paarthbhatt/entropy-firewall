from __future__ import annotations

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from entropy.cli.main import (
    _load_env_value,
    _normalize_choice,
    _resolve_master_key,
    _upsert_env_file,
    app,
)


def test_upsert_env_file_add_and_update(tmp_path) -> None:
    env_path = tmp_path / ".env"
    changed = _upsert_env_file(env_path, {"OPENAI_API_KEY": "first-key"})
    assert changed == ["added OPENAI_API_KEY"]
    assert "OPENAI_API_KEY=first-key" in env_path.read_text(encoding="utf-8")

    changed = _upsert_env_file(
        env_path,
        {"OPENAI_API_KEY": "second-key", "ENTROPY_MASTER_API_KEY": "ent-test"},
    )
    assert "updated OPENAI_API_KEY" in changed
    assert "added ENTROPY_MASTER_API_KEY" in changed
    content = env_path.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=second-key" in content
    assert "ENTROPY_MASTER_API_KEY=ent-test" in content


def test_load_env_value_reads_value(tmp_path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("ENTROPY_MASTER_API_KEY=ent-abc123\n", encoding="utf-8")
    assert _load_env_value(env_path, "ENTROPY_MASTER_API_KEY") == "ent-abc123"
    assert _load_env_value(env_path, "MISSING") is None


def test_normalize_choice_validates_values() -> None:
    assert _normalize_choice("Docker", {"docker", "local"}) == "docker"
    with pytest.raises(typer.BadParameter):
        _normalize_choice("bad-mode", {"docker", "local"})


def test_resolve_master_key_prefers_explicit_value(tmp_path, monkeypatch) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("ENTROPY_MASTER_API_KEY=ent-from-file\n", encoding="utf-8")
    monkeypatch.setenv("ENTROPY_MASTER_API_KEY", "ent-from-env")
    assert _resolve_master_key("ent-explicit", env_path) == "ent-explicit"


def test_resolve_master_key_uses_process_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ENTROPY_MASTER_API_KEY", "ent-from-env")
    assert _resolve_master_key(None, tmp_path / ".env") == "ent-from-env"


def test_resolve_master_key_uses_dotenv_fallback(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ENTROPY_MASTER_API_KEY", raising=False)
    env_path = tmp_path / ".env"
    env_path.write_text("ENTROPY_MASTER_API_KEY=ent-from-file\n", encoding="utf-8")
    assert _resolve_master_key(None, env_path) == "ent-from-file"


def test_resolve_master_key_prefers_process_env_over_dotenv(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ENTROPY_MASTER_API_KEY", "ent-from-env")
    env_path = tmp_path / ".env"
    env_path.write_text("ENTROPY_MASTER_API_KEY=ent-from-file\n", encoding="utf-8")
    assert _resolve_master_key(None, env_path) == "ent-from-env"


def test_quickstart_non_interactive_writes_env(tmp_path) -> None:
    env_path = tmp_path / ".env"
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "quickstart",
            "--mode",
            "local",
            "--provider",
            "openai-compatible-local",
            "--env-file",
            str(env_path),
            "--openai-api-key",
            "dummy-local-key",
            "--openai-base-url",
            "http://localhost:11434/v1",
            "--master-api-key",
            "ent-test-master",
            "--yes",
        ],
    )

    assert result.exit_code == 0
    content = env_path.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=dummy-local-key" in content
    assert "OPENAI_BASE_URL=http://localhost:11434/v1" in content
    assert "ENTROPY_MASTER_API_KEY=ent-test-master" in content
    assert "Do not use OPENAI_API_KEY as Entropy X-API-Key." in result.output
    assert "PowerShell-safe quick check" in result.output
    assert "Local model hint" in result.output


def test_quickstart_prefers_process_env_master_key_over_env_file(tmp_path, monkeypatch) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("ENTROPY_MASTER_API_KEY=ent-from-file\n", encoding="utf-8")
    monkeypatch.setenv("ENTROPY_MASTER_API_KEY", "ent-from-env")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "quickstart",
            "--mode",
            "local",
            "--provider",
            "openai-compatible-local",
            "--env-file",
            str(env_path),
            "--openai-api-key",
            "dummy-local-key",
            "--openai-base-url",
            "http://localhost:11434/v1",
            "--yes",
        ],
    )

    assert result.exit_code == 0
    content = env_path.read_text(encoding="utf-8")
    assert "ENTROPY_MASTER_API_KEY=ent-from-env" in content


def test_create_api_key_uses_dotenv_master_key(tmp_path, monkeypatch) -> None:
    class DummyResponse:
        status_code = 200
        text = ""

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"key": "ent-app-key"}

    captured: dict[str, str] = {}

    def fake_post(
        url: str, headers: dict[str, str], json: dict[str, str], timeout: int
    ) -> DummyResponse:
        captured["url"] = url
        captured["auth"] = headers["X-API-Key"]
        captured["name"] = json["name"]
        return DummyResponse()

    monkeypatch.setattr("entropy.cli.main.httpx.post", fake_post)
    monkeypatch.delenv("ENTROPY_MASTER_API_KEY", raising=False)

    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path(".env").write_text("ENTROPY_MASTER_API_KEY=ent-from-dotenv\n", encoding="utf-8")
        result = runner.invoke(app, ["create-api-key", "demo-app"])

    assert result.exit_code == 0
    assert captured["url"].endswith("/admin/api-keys")
    assert captured["auth"] == "ent-from-dotenv"
    assert captured["name"] == "demo-app"


def test_create_api_key_explicit_master_key_overrides_other_sources_and_prints_hints(
    tmp_path, monkeypatch
) -> None:
    class DummyResponse:
        status_code = 200
        text = ""

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"key": "ent-app-key"}

    captured: dict[str, str] = {}

    def fake_post(
        url: str, headers: dict[str, str], json: dict[str, str], timeout: int
    ) -> DummyResponse:
        captured["url"] = url
        captured["auth"] = headers["X-API-Key"]
        captured["name"] = json["name"]
        return DummyResponse()

    monkeypatch.setattr("entropy.cli.main.httpx.post", fake_post)
    monkeypatch.setenv("ENTROPY_MASTER_API_KEY", "ent-from-env")

    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path(".env").write_text("ENTROPY_MASTER_API_KEY=ent-from-dotenv\n", encoding="utf-8")
        result = runner.invoke(
            app,
            ["create-api-key", "demo-app", "--master-key", "ent-explicit"],
        )

    assert result.exit_code == 0
    assert captured["url"].endswith("/admin/api-keys")
    assert captured["auth"] == "ent-explicit"
    assert captured["name"] == "demo-app"
    assert "Use ENTROPY_MASTER_API_KEY only for /admin/* endpoints." in result.output
    assert "Do not use your upstream provider key for Entropy authentication." in result.output


def test_smoke_uses_dotenv_master_key(tmp_path, monkeypatch) -> None:
    class DummyResponse:
        def __init__(self, payload: dict[str, object]) -> None:
            self.status_code = 200
            self.text = ""
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self._payload

    captured: dict[str, str] = {}

    def fake_get(url: str, timeout: int) -> DummyResponse:
        assert url.endswith("/health")
        return DummyResponse({"status": "ok"})

    def fake_post(
        url: str,
        headers: dict[str, str],
        json: dict[str, object],
        timeout: int,
    ) -> DummyResponse:
        if url.endswith("/admin/api-keys"):
            captured["master"] = headers["X-API-Key"]
            return DummyResponse({"key": "ent-app-for-smoke"})
        captured["app"] = headers["X-API-Key"]
        return DummyResponse(
            {"entropy": {"status": "safe"}, "choices": [{"message": {"content": "hello"}}]}
        )

    monkeypatch.setattr("entropy.cli.main.httpx.get", fake_get)
    monkeypatch.setattr("entropy.cli.main.httpx.post", fake_post)
    monkeypatch.delenv("ENTROPY_MASTER_API_KEY", raising=False)

    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path(".env").write_text("ENTROPY_MASTER_API_KEY=ent-smoke-master\n", encoding="utf-8")
        result = runner.invoke(app, ["smoke"])

    assert result.exit_code == 0
    assert captured["master"] == "ent-smoke-master"
    assert captured["app"] == "ent-app-for-smoke"
