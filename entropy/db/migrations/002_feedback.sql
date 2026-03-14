-- Migration 002: Feedback System
-- Creates tables for learning feedback and threshold tuning

-- Feedback table for storing user feedback on security decisions
CREATE TABLE IF NOT EXISTS feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_log_id UUID REFERENCES request_logs(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,

    -- What was detected
    pattern_name VARCHAR(255),
    category VARCHAR(100),
    threat_level VARCHAR(20),

    -- User feedback
    was_correct BOOLEAN NOT NULL,
    expected_action VARCHAR(50) CHECK (expected_action IN ('allow', 'block', 'sanitize')),
    reason TEXT,

    -- Metadata
    confidence FLOAT,
    original_verdict VARCHAR(50),

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Indexing
    reviewed_at TIMESTAMP WITH TIME ZONE,
    reviewed_by VARCHAR(255)
);

-- Index for pattern performance queries
CREATE INDEX IF NOT EXISTS idx_feedback_pattern ON feedback(pattern_name);
CREATE INDEX IF NOT EXISTS idx_feedback_category ON feedback(category);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
CREATE INDEX IF NOT EXISTS idx_feedback_correct ON feedback(was_correct);
CREATE INDEX IF NOT EXISTS idx_feedback_pattern_correct ON feedback(pattern_name, was_correct);

-- Threshold adjustments table for storing learned thresholds
CREATE TABLE IF NOT EXISTS threshold_adjustments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Pattern identification
    pattern_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),

    -- Threshold values
    original_threshold FLOAT NOT NULL,
    adjusted_threshold FLOAT NOT NULL,
    adjustment_reason TEXT,

    -- Performance metrics
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    true_negatives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Unique constraint - one adjustment per pattern
    UNIQUE(pattern_name)
);

-- Index for threshold lookups
CREATE INDEX IF NOT EXISTS idx_threshold_pattern ON threshold_adjustments(pattern_name);
CREATE INDEX IF NOT EXISTS idx_threshold_category ON threshold_adjustments(category);

-- Function to update threshold adjustment timestamps
CREATE OR REPLACE FUNCTION update_threshold_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for automatic timestamp updates
DROP TRIGGER IF EXISTS trigger_threshold_updated_at ON threshold_adjustments;
CREATE TRIGGER trigger_threshold_updated_at
    BEFORE UPDATE ON threshold_adjustments
    FOR EACH ROW
    EXECUTE FUNCTION update_threshold_updated_at();

-- View for pattern performance statistics
CREATE OR REPLACE VIEW pattern_performance AS
SELECT
    pattern_name,
    category,
    COUNT(*) as total_feedback,
    SUM(CASE WHEN was_correct THEN 1 ELSE 0 END) as correct_count,
    SUM(CASE WHEN NOT was_correct THEN 1 ELSE 0 END) as incorrect_count,
    ROUND(
        100.0 * SUM(CASE WHEN was_correct THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0),
        2
    ) as accuracy_percentage,
    AVG(confidence) as avg_confidence,
    MAX(created_at) as last_feedback_at
FROM feedback
GROUP BY pattern_name, category;

-- View for recent feedback (last 30 days)
CREATE OR REPLACE VIEW recent_feedback AS
SELECT * FROM feedback
WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY created_at DESC;

-- Comments for documentation
COMMENT ON TABLE feedback IS 'Stores user feedback on security decisions for learning';
COMMENT ON TABLE threshold_adjustments IS 'Stores learned threshold adjustments per pattern';
COMMENT ON VIEW pattern_performance IS 'Aggregate performance statistics per pattern';
COMMENT ON VIEW recent_feedback IS 'Feedback from the last 30 days';