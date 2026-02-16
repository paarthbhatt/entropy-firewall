"""Unit tests for OutputFilter."""

import pytest
from entropy.core.output_filter import OutputFilter


class TestOutputFilter:
    """Test suite for OutputFilter."""

    # ---- PII ----------------------------------------------------------------

    def test_redacts_email(self, output_filter: OutputFilter):
        text = "Contact me at john.doe@example.com for details"
        sanitized, detections = output_filter.filter(text)
        assert "[EMAIL_REDACTED]" in sanitized
        assert "john.doe@example.com" not in sanitized
        assert any(d["rule"] == "email" for d in detections)

    def test_redacts_phone(self, output_filter: OutputFilter):
        text = "Call me at (555) 123-4567"
        sanitized, detections = output_filter.filter(text)
        assert "[PHONE_REDACTED]" in sanitized

    def test_redacts_ssn(self, output_filter: OutputFilter):
        text = "My SSN is 123-45-6789"
        sanitized, detections = output_filter.filter(text)
        assert "[SSN_REDACTED]" in sanitized
        assert "123-45-6789" not in sanitized

    def test_redacts_credit_card_visa(self, output_filter: OutputFilter):
        text = "Card number: 4111111111111111"
        sanitized, detections = output_filter.filter(text)
        assert "[CREDIT_CARD_REDACTED]" in sanitized

    def test_redacts_credit_card_mastercard(self, output_filter: OutputFilter):
        text = "MC: 5500000000000004"
        sanitized, detections = output_filter.filter(text)
        assert "[CREDIT_CARD_REDACTED]" in sanitized

    # ---- Secrets ------------------------------------------------------------

    def test_redacts_openai_key(self, output_filter: OutputFilter):
        text = "My key is sk-abcdefghijklmnopqrstuvwxyz12345678901234567890"
        sanitized, detections = output_filter.filter(text)
        assert "[OPENAI_KEY_REDACTED]" in sanitized
        assert "sk-" not in sanitized.replace("[OPENAI_KEY_REDACTED]", "")

    def test_redacts_github_pat(self, output_filter: OutputFilter):
        text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        sanitized, detections = output_filter.filter(text)
        assert "[GITHUB_PAT_REDACTED]" in sanitized

    def test_redacts_aws_key(self, output_filter: OutputFilter):
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        sanitized, detections = output_filter.filter(text)
        assert "[AWS_KEY_REDACTED]" in sanitized

    def test_redacts_bearer_token(self, output_filter: OutputFilter):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        sanitized, detections = output_filter.filter(text)
        assert "[BEARER_TOKEN_REDACTED]" in sanitized

    def test_redacts_private_key(self, output_filter: OutputFilter):
        text = "-----BEGIN RSA PRIVATE KEY----- MIIBog..."
        sanitized, detections = output_filter.filter(text)
        assert "[PRIVATE_KEY_REDACTED]" in sanitized

    def test_redacts_password(self, output_filter: OutputFilter):
        text = 'password = "my_super_secret_pass123"'
        sanitized, detections = output_filter.filter(text)
        assert "[PASSWORD_REDACTED]" in sanitized

    def test_redacts_generic_api_key(self, output_filter: OutputFilter):
        text = "api_key = 'abcdef1234567890abcdef1234567890'"
        sanitized, detections = output_filter.filter(text)
        assert "[API_KEY_REDACTED]" in sanitized

    # ---- Leakage ------------------------------------------------------------

    def test_detects_system_prompt_leak(self, output_filter: OutputFilter):
        text = "You are a helpful assistant that answers questions"
        sanitized, detections = output_filter.filter(text)
        assert any(d["rule"] == "system_prompt_leak" for d in detections)

    # ---- Safe text ----------------------------------------------------------

    def test_safe_text_unchanged(self, output_filter: OutputFilter):
        text = "The capital of France is Paris."
        sanitized, detections = output_filter.filter(text)
        assert sanitized == text
        assert detections == []

    def test_empty_text(self, output_filter: OutputFilter):
        sanitized, detections = output_filter.filter("")
        assert sanitized == ""
        assert detections == []

    # ---- Multiple detections ------------------------------------------------

    def test_multiple_pii_types(self, output_filter: OutputFilter):
        text = (
            "Email: test@example.com, Phone: 555-123-4567, "
            "SSN: 123-45-6789"
        )
        sanitized, detections = output_filter.filter(text)
        assert len(detections) >= 3
        assert "test@example.com" not in sanitized
        assert "123-45-6789" not in sanitized

    # ---- Disabled mode ------------------------------------------------------

    def test_disabled_filter_passes_through(self):
        filt = OutputFilter(enable_pii=False, enable_code=True)
        text = "test@example.com 123-45-6789"
        sanitized, detections = filt.filter(text)
        # PII rules disabled, but secret/leakage rules may still fire
        assert "test@example.com" in sanitized  # PII not redacted

    # ---- Analyze mode -------------------------------------------------------

    def test_analyze_doesnt_modify(self, output_filter: OutputFilter):
        text = "test@example.com"
        detections = output_filter.analyze(text)
        assert len(detections) >= 1
        # Original text should still have the email (analyze doesn't redact)
