-- ==========================================================================
-- Entropy LLM Firewall — Initial Database Schema
-- PostgreSQL 15+
-- ==========================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------------------------------------------
-- API Keys
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash        TEXT NOT NULL,
    key_prefix      VARCHAR(12) NOT NULL,           -- first 8 chars for lookup
    name            VARCHAR(255) NOT NULL,
    user_id         VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_rpm  INTEGER DEFAULT NULL,            -- per-key override
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_prefix ON api_keys (key_prefix);
CREATE INDEX idx_api_keys_user   ON api_keys (user_id);

-- --------------------------------------------------------------------------
-- Request Logs  (audit trail)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS request_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id      UUID REFERENCES api_keys(id),
    client_ip       INET NOT NULL,

    -- Request metadata
    provider        VARCHAR(50) NOT NULL DEFAULT 'openai',
    model           VARCHAR(100),
    message_count   INTEGER,
    input_tokens    INTEGER,

    -- Entropy verdict
    status          VARCHAR(20) NOT NULL DEFAULT 'allowed',   -- allowed | blocked | sanitized
    threat_level    VARCHAR(20),                                -- safe | low | medium | high | critical
    confidence      REAL,
    threats_json    JSONB DEFAULT '[]',

    -- Response metadata
    output_tokens   INTEGER,
    output_sanitized BOOLEAN DEFAULT FALSE,
    sanitization_json JSONB DEFAULT '[]',

    -- Timing
    processing_ms   REAL,
    provider_ms     REAL,
    total_ms        REAL,

    -- Metadata
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_request_logs_created  ON request_logs (created_at DESC);
CREATE INDEX idx_request_logs_status   ON request_logs (status);
CREATE INDEX idx_request_logs_api_key  ON request_logs (api_key_id);
CREATE INDEX idx_request_logs_ip       ON request_logs (client_ip);
CREATE INDEX idx_request_logs_threat   ON request_logs (threat_level);

-- --------------------------------------------------------------------------
-- Security Events  (blocked attacks, rate-limit violations)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_log_id  UUID REFERENCES request_logs(id),
    event_type      VARCHAR(50) NOT NULL,            -- attack_blocked | rate_limited | pii_detected
    severity        VARCHAR(20) NOT NULL,             -- low | medium | high | critical
    details         JSONB DEFAULT '{}',
    client_ip       INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_type    ON security_events (event_type);
CREATE INDEX idx_security_events_created ON security_events (created_at DESC);

-- --------------------------------------------------------------------------
-- Auto-update last_used_at on api_keys
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_api_key_last_used()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE api_keys SET last_used_at = NOW() WHERE id = NEW.api_key_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_update_api_key_last_used
    AFTER INSERT ON request_logs
    FOR EACH ROW
    WHEN (NEW.api_key_id IS NOT NULL)
    EXECUTE FUNCTION update_api_key_last_used();
