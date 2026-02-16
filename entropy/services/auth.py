"""Authentication service — API key verification.

Keys are stored hashed with passlib/bcrypt.  On each request the incoming
key is matched by prefix, then verified against the stored hash.
"""

from __future__ import annotations

import secrets
from typing import Any, Optional

import structlog
from passlib.hash import bcrypt

from entropy.config import get_settings
from entropy.db.repository import APIKeyRepository

logger = structlog.get_logger(__name__)


def generate_api_key() -> str:
    """Generate a new API key in the format ``ent-<48 hex chars>``."""
    return f"ent-{secrets.token_hex(24)}"


def hash_api_key(raw_key: str) -> str:
    """Hash an API key for storage."""
    return bcrypt.using(rounds=12).hash(raw_key)


def verify_api_key(raw_key: str, hashed: str) -> bool:
    """Verify a raw key against a stored hash."""
    return bcrypt.verify(raw_key, hashed)


def key_prefix(raw_key: str) -> str:
    """Extract the prefix used for DB lookup (first 12 chars)."""
    return raw_key[:12]


class AuthService:
    """Stateless authentication service backed by the APIKeyRepository."""

    def __init__(self, repo: APIKeyRepository) -> None:
        self.repo = repo
        self._master_key = get_settings().master_api_key

    async def authenticate(self, raw_key: str) -> Optional[dict[str, Any]]:
        """Authenticate an API key.

        Returns the key record dict if valid, ``None`` otherwise.
        Handles the master key bypass for bootstrapping.
        """
        if not raw_key:
            return None

        # Master key bypass (for initial setup / admin ops)
        if raw_key == self._master_key:
            logger.info("Master API key used")
            return {
                "id": "master",
                "name": "master",
                "user_id": "admin",
                "is_active": True,
                "rate_limit_rpm": None,
            }

        prefix = key_prefix(raw_key)
        record = await self.repo.find_by_prefix(prefix)
        if record is None:
            logger.warning("API key not found", prefix=prefix)
            return None

        if not verify_api_key(raw_key, record["key_hash"]):
            logger.warning("API key hash mismatch", prefix=prefix)
            return None

        # Check expiry
        if record.get("expires_at") is not None:
            from datetime import datetime, timezone

            if record["expires_at"] < datetime.now(timezone.utc):
                logger.warning("API key expired", prefix=prefix)
                return None

        return record

    async def create_key(
        self,
        name: str,
        user_id: Optional[str] = None,
        rate_limit_rpm: Optional[int] = None,
    ) -> tuple[str, str]:
        """Create a new API key. Returns (key_id, raw_key)."""
        raw = generate_api_key()
        hashed = hash_api_key(raw)
        prefix = key_prefix(raw)

        key_id = await self.repo.create(
            key_hash=hashed,
            key_prefix=prefix,
            name=name,
            user_id=user_id,
            rate_limit_rpm=rate_limit_rpm,
        )

        logger.info("API key created", key_id=key_id, name=name, prefix=prefix)
        return key_id, raw

    async def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        ok = await self.repo.deactivate(key_id)
        if ok:
            logger.info("API key revoked", key_id=key_id)
        return ok
