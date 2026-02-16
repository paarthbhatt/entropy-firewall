"""Model Downloader — fetch ONNX classifier model on first use.

Usage::

    from entropy.core.model_downloader import ensure_model

    path = ensure_model()  # Downloads if not present, returns path

CLI::

    entropy download-model
"""

from __future__ import annotations

import hashlib
import os
import urllib.request
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_MODEL_DIR = Path.home() / ".entropy" / "models"
DEFAULT_MODEL_NAME = "entropy-classifier.onnx"


def get_model_path(model_dir: Path | None = None) -> Path:
    """Return the expected model file path."""
    d = model_dir or DEFAULT_MODEL_DIR
    return d / DEFAULT_MODEL_NAME


def ensure_model(
    url: str = "",
    model_dir: Path | None = None,
    expected_sha256: str = "",
) -> Path | None:
    """Ensure the ONNX model file exists locally.

    If the model is already downloaded, returns its path.
    If a URL is configured, downloads and verifies the model.
    If no URL and no model, returns None.

    Args:
        url: Download URL for the ONNX model.
        model_dir: Directory to store the model (default: ``~/.entropy/models``).
        expected_sha256: Optional SHA256 hex digest for integrity check.

    Returns:
        Path to the model file, or None if unavailable.
    """
    target = get_model_path(model_dir)

    # Already downloaded
    if target.exists():
        logger.info("Model already present", path=str(target))
        return target

    # No URL configured — cannot download
    if not url:
        logger.info(
            "No model URL configured and model not found locally",
            expected_path=str(target),
        )
        return None

    # Download
    logger.info("Downloading ONNX model", url=url, target=str(target))
    target.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = target.with_suffix(".onnx.tmp")

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "EntropyFirewall/0.1"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            sha = hashlib.sha256()

            with open(tmp_path, "wb") as f:
                while True:
                    chunk = resp.read(1024 * 256)  # 256KB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    sha.update(chunk)
                    downloaded += len(chunk)

                    if total > 0:
                        pct = downloaded / total * 100
                        if int(pct) % 10 == 0:
                            logger.debug("Download progress", percent=f"{pct:.0f}%")

        # Verify integrity
        if expected_sha256:
            actual = sha.hexdigest()
            if actual != expected_sha256:
                tmp_path.unlink(missing_ok=True)
                logger.error(
                    "Model integrity check failed",
                    expected=expected_sha256[:16] + "...",
                    actual=actual[:16] + "...",
                )
                return None

        # Atomic rename
        tmp_path.rename(target)
        logger.info(
            "Model downloaded successfully",
            path=str(target),
            size_mb=f"{downloaded / 1_048_576:.1f}",
        )
        return target

    except Exception as e:
        tmp_path.unlink(missing_ok=True)
        logger.error("Model download failed", error=str(e))
        return None


def download_model_cli() -> None:
    """CLI entry point for ``entropy download-model``."""
    from entropy.config import get_settings

    settings = get_settings()
    url = settings.engine.semantic_model_url
    model_path = settings.engine.semantic_model_path

    if not url:
        print("No model URL configured.")
        print(f"Set ENTROPY_SEMANTIC_MODEL_URL or configure in config.yaml")
        print(f"Expected model location: {os.path.expanduser(model_path)}")
        return

    result = ensure_model(
        url=url,
        model_dir=Path(os.path.expanduser(model_path)).parent,
    )

    if result:
        print(f"✅ Model ready at: {result}")
    else:
        print("❌ Model download failed. Check logs for details.")
