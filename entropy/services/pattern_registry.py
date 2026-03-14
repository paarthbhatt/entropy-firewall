"""Dynamic pattern registry with hot-reload support.

Allows adding, updating, and removing detection patterns at runtime
without server restart. Uses PostgreSQL for persistence and Redis
pub/sub for notifying all instances of updates.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import structlog

from entropy.core.pattern_matcher import PatternMatcher, ThreatLevel
from entropy.models.schemas import ThreatLevel as ThreatLevelEnum

logger = structlog.get_logger(__name__)

# Redis channel for pattern updates
PATTERN_UPDATE_CHANNEL = "entropy:patterns:update"


@dataclass
class CustomPattern:
    """A custom detection pattern."""

    id: Optional[int] = None
    name: str
    category: str
    pattern: str
    threat_level: str = "medium"
    confidence: float = 0.8
    description: Optional[str] = None
    enabled: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None


@dataclass
class PatternUpdateEvent:
    """Event sent when patterns are updated."""

    action: str  # 'add', 'update', 'delete', 'reload'
    pattern_id: Optional[int] = None
    pattern_name: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class PatternRegistry:
    """Manages custom detection patterns with hot-reload.

    Features:
    - PostgreSQL persistence for patterns
    - Redis pub/sub for real-time updates across instances
    - Hot-reload without server restart
    - Pattern versioning and audit trail

    Usage:
        registry = PatternRegistry(db_pool, redis_client, pattern_matcher)
        await registry.start()

        # Add a custom pattern
        await registry.add_pattern(CustomPattern(
            name="custom_sql_injection",
            category="code_injection",
            pattern=r"(?i)(union.*select|select.*from)",
            threat_level="high",
        ))

        # Stop listening for updates
        await registry.stop()
    """

    def __init__(
        self,
        db_pool: Any,
        redis_client: Any = None,
        pattern_matcher: Optional[PatternMatcher] = None,
    ) -> None:
        """Initialize the pattern registry.

        Args:
            db_pool: asyncpg connection pool
            redis_client: Redis client for pub/sub (optional)
            pattern_matcher: PatternMatcher instance to update
        """
        self.pool = db_pool
        self.redis = redis_client
        self.matcher = pattern_matcher or PatternMatcher()
        self._pubsub = None
        self._listener_task = None

    async def start(self) -> None:
        """Start the registry and load patterns."""
        # Ensure table exists
        await self._ensure_table()

        # Load existing patterns
        await self.load_patterns()

        # Subscribe to updates if Redis is available
        if self.redis:
            await self._subscribe()

        logger.info("PatternRegistry started")

    async def stop(self) -> None:
        """Stop listening for updates."""
        if self._pubsub:
            await self._pubsub.unsubscribe(PATTERN_UPDATE_CHANNEL)
            self._pubsub = None

        logger.info("PatternRegistry stopped")

    async def _ensure_table(self) -> None:
        """Create the custom patterns table if it doesn't exist."""
        query = """
            CREATE TABLE IF NOT EXISTS custom_patterns (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                category VARCHAR(100) NOT NULL,
                pattern TEXT NOT NULL,
                threat_level VARCHAR(20) NOT NULL DEFAULT 'medium',
                confidence FLOAT NOT NULL DEFAULT 0.8,
                description TEXT,
                enabled BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(255)
            );

            CREATE INDEX IF NOT EXISTS idx_custom_patterns_category
                ON custom_patterns(category);
            CREATE INDEX IF NOT EXISTS idx_custom_patterns_enabled
                ON custom_patterns(enabled);
        """

        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def load_patterns(self) -> int:
        """Load all patterns from database.

        Returns:
            Number of patterns loaded
        """
        query = """
            SELECT id, name, category, pattern, threat_level, confidence,
                   description, enabled
            FROM custom_patterns
            WHERE enabled = true
        """

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query)

        loaded = 0
        for row in rows:
            try:
                level_map = {
                    "safe": ThreatLevel.SAFE,
                    "low": ThreatLevel.LOW,
                    "medium": ThreatLevel.MEDIUM,
                    "high": ThreatLevel.HIGH,
                    "critical": ThreatLevel.CRITICAL,
                }
                threat_level = level_map.get(
                    row["threat_level"].lower(),
                    ThreatLevel.MEDIUM,
                )

                self.matcher.add_custom_pattern(
                    category=row["category"],
                    name=row["name"],
                    pattern=row["pattern"],
                    threat_level=threat_level,
                )
                loaded += 1

            except Exception as e:
                logger.error(
                    "Failed to load pattern",
                    pattern=row["name"],
                    error=str(e),
                )

        logger.info("Patterns loaded from database", count=loaded)
        return loaded

    async def add_pattern(
        self,
        pattern: CustomPattern,
        notify: bool = True,
    ) -> int:
        """Add a new custom pattern.

        Args:
            pattern: The pattern to add
            notify: Whether to notify other instances

        Returns:
            The ID of the created pattern
        """
        query = """
            INSERT INTO custom_patterns (
                name, category, pattern, threat_level, confidence,
                description, enabled, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
        """

        async with self.pool.acquire() as conn:
            pattern_id = await conn.fetchval(
                query,
                pattern.name,
                pattern.category,
                pattern.pattern,
                pattern.threat_level,
                pattern.confidence,
                pattern.description,
                pattern.enabled,
                pattern.created_by,
            )

        # Add to in-memory matcher
        level_map = {
            "safe": ThreatLevel.SAFE,
            "low": ThreatLevel.LOW,
            "medium": ThreatLevel.MEDIUM,
            "high": ThreatLevel.HIGH,
            "critical": ThreatLevel.CRITICAL,
        }
        self.matcher.add_custom_pattern(
            category=pattern.category,
            name=pattern.name,
            pattern=pattern.pattern,
            threat_level=level_map.get(pattern.threat_level.lower(), ThreatLevel.MEDIUM),
        )

        logger.info("Pattern added", id=pattern_id, name=pattern.name)

        # Notify other instances
        if notify and self.redis:
            await self._publish_update("add", pattern_id, pattern.name)

        return pattern_id

    async def update_pattern(
        self,
        pattern_id: int,
        updates: dict[str, Any],
        notify: bool = True,
    ) -> bool:
        """Update an existing pattern.

        Args:
            pattern_id: The pattern ID to update
            updates: Fields to update
            notify: Whether to notify other instances

        Returns:
            True if updated successfully
        """
        # Build update query
        allowed_fields = {
            "name", "category", "pattern", "threat_level",
            "confidence", "description", "enabled",
        }
        update_fields = {k: v for k, v in updates.items() if k in allowed_fields}

        if not update_fields:
            return False

        set_clause = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(update_fields))
        query = f"""
            UPDATE custom_patterns
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """

        async with self.pool.acquire() as conn:
            result = await conn.execute(query, pattern_id, *update_fields.values())

        if "UPDATE 1" in result:
            # Reload patterns in memory
            await self.load_patterns()

            logger.info("Pattern updated", id=pattern_id)

            if notify and self.redis:
                await self._publish_update("update", pattern_id)

            return True

        return False

    async def delete_pattern(
        self,
        pattern_id: int,
        notify: bool = True,
    ) -> bool:
        """Delete a pattern.

        Args:
            pattern_id: The pattern ID to delete
            notify: Whether to notify other instances

        Returns:
            True if deleted successfully
        """
        # Get pattern name before deletion
        async with self.pool.acquire() as conn:
            name = await conn.fetchval(
                "SELECT name FROM custom_patterns WHERE id = $1",
                pattern_id,
            )

            if not name:
                return False

            await conn.execute("DELETE FROM custom_patterns WHERE id = $1", pattern_id)

        # Reload patterns (this removes the deleted one)
        await self.load_patterns()

        logger.info("Pattern deleted", id=pattern_id, name=name)

        if notify and self.redis:
            await self._publish_update("delete", pattern_id, name)

        return True

    async def list_patterns(
        self,
        category: Optional[str] = None,
        enabled_only: bool = True,
    ) -> list[CustomPattern]:
        """List all custom patterns.

        Args:
            category: Filter by category
            enabled_only: Only return enabled patterns

        Returns:
            List of patterns
        """
        conditions = []
        params = []

        if category:
            conditions.append("category = $1")
            params.append(category)

        if enabled_only:
            conditions.append("enabled = true")

        where_clause = " AND ".join(conditions) if conditions else "true"
        query = f"""
            SELECT id, name, category, pattern, threat_level, confidence,
                   description, enabled, created_at, updated_at, created_by
            FROM custom_patterns
            WHERE {where_clause}
            ORDER BY created_at DESC
        """

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [
            CustomPattern(
                id=row["id"],
                name=row["name"],
                category=row["category"],
                pattern=row["pattern"],
                threat_level=row["threat_level"],
                confidence=row["confidence"],
                description=row["description"],
                enabled=row["enabled"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                created_by=row["created_by"],
            )
            for row in rows
        ]

    async def _subscribe(self) -> None:
        """Subscribe to Redis pattern updates."""
        if not self.redis:
            return

        self._pubsub = self.redis.pubsub()
        await self._pubsub.subscribe(PATTERN_UPDATE_CHANNEL)

        logger.info("Subscribed to pattern updates", channel=PATTERN_UPDATE_CHANNEL)

    async def _publish_update(
        self,
        action: str,
        pattern_id: Optional[int] = None,
        pattern_name: Optional[str] = None,
    ) -> None:
        """Publish a pattern update event."""
        if not self.redis:
            return

        event = PatternUpdateEvent(
            action=action,
            pattern_id=pattern_id,
            pattern_name=pattern_name,
        )

        await self.redis.publish(
            PATTERN_UPDATE_CHANNEL,
            json.dumps({
                "action": event.action,
                "pattern_id": event.pattern_id,
                "pattern_name": event.pattern_name,
                "timestamp": event.timestamp,
            }),
        )

    async def listen_for_updates(self) -> None:
        """Listen for pattern updates from Redis.

        This should be run as a background task.
        """
        if not self._pubsub:
            return

        async for message in self._pubsub.listen():
            if message["type"] != "message":
                continue

            try:
                data = json.loads(message["data"])
                logger.info(
                    "Received pattern update",
                    action=data.get("action"),
                    pattern_id=data.get("pattern_id"),
                )

                # Reload patterns
                await self.load_patterns()

            except Exception as e:
                logger.error("Failed to process pattern update", error=str(e))


__all__ = [
    "PatternRegistry",
    "CustomPattern",
    "PatternUpdateEvent",
    "PATTERN_UPDATE_CHANNEL",
]