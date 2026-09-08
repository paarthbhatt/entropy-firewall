-- ==========================================================================
-- Entropy LLM Firewall — Migration 002
-- Drop the per-insert last_used_at trigger (lock contention under load).
--
-- last_used_at is now maintained by the application with a throttled,
-- conditional UPDATE (only when stale by > 5 minutes), which avoids a row
-- lock on api_keys for every single logged request.
-- ==========================================================================

DROP TRIGGER IF EXISTS trg_update_api_key_last_used ON request_logs;
DROP FUNCTION IF EXISTS update_api_key_last_used();
