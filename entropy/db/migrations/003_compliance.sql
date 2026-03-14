-- ==========================================================================
-- Entropy LLM Firewall — Compliance Module Schema
-- PostgreSQL 15+
-- ==========================================================================

-- --------------------------------------------------------------------------
-- Compliance Rules  (rules extracted from uploaded policy PDFs)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         VARCHAR(64) NOT NULL UNIQUE,        -- e.g., "GDPR-12a"
    source_document VARCHAR(255),                       -- filename of uploaded PDF
    regulation      VARCHAR(64) NOT NULL,               -- GDPR | HIPAA | CCPA | DPDP | SOC2 | ISO27001
    category        VARCHAR(128) NOT NULL,              -- Data Retention | Access Control | etc.
    description     TEXT NOT NULL,
    trigger_condition TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium', -- critical | high | medium | low
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_rules_regulation ON compliance_rules (regulation);
CREATE INDEX idx_compliance_rules_severity   ON compliance_rules (severity);
CREATE INDEX idx_compliance_rules_active     ON compliance_rules (is_active);

-- --------------------------------------------------------------------------
-- Compliance Overrides  (manual override decisions by compliance officers)
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_overrides (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_log_id  UUID REFERENCES request_logs(id) ON DELETE SET NULL,
    reviewer_name   VARCHAR(255),
    action          VARCHAR(50) NOT NULL,  -- FALSE_POSITIVE | LEGAL_HOLD | DPO_EXCEPTION | REMEDIATION_IN_PROGRESS
    reason          TEXT,
    regulation_context VARCHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_overrides_log     ON compliance_overrides (request_log_id);
CREATE INDEX idx_compliance_overrides_action  ON compliance_overrides (action);
CREATE INDEX idx_compliance_overrides_created ON compliance_overrides (created_at DESC);
