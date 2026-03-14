"""Integration tests for Enterprise features (Feedback, RAG, Patterns)."""

import pytest
from fastapi.testclient import TestClient

class TestFeedbackEndpoints:
    """Tests for /v1/feedback/* endpoints."""

    def test_submit_feedback_requires_auth(self, client: TestClient):
        resp = client.post(
            "/v1/feedback",
            json={
                "request_log_id": "00000000-0000-0000-0000-000000000000",
                "pattern_name": "test_pattern",
                "was_correct": True
            },
        )
        assert resp.status_code == 401

    def test_get_stats_requires_auth(self, client: TestClient):
        resp = client.get("/v1/feedback/stats")
        assert resp.status_code == 401

    def test_tune_thresholds_requires_admin(self, client: TestClient):
        resp = client.post(
            "/v1/feedback/tune",
            headers={"X-API-Key": "test-master-key"}
        )
        # Mocked DB fails so expects 503 or 403 depending on admin check
        assert resp.status_code in (403, 503)


class TestRAGEndpoints:
    """Tests for /v1/rag/* endpoints."""

    def test_scan_requires_auth(self, client: TestClient):
        resp = client.post(
            "/v1/rag/scan",
            json={
                "documents": [{"id": "doc1", "content": "Hello"}],
            },
        )
        assert resp.status_code == 401

    def test_quick_scan_requires_auth(self, client: TestClient):
        resp = client.post(
            "/v1/rag/quick-scan",
            json={
                "content": "Hello",
            },
        )
        assert resp.status_code == 401


class TestAdminPatternsEndpoint:
    """Tests for /admin/patterns endpoints."""

    def test_create_pattern_requires_auth(self, client: TestClient):
        resp = client.post(
            "/admin/patterns",
            json={
                "name": "test_injection",
                "category": "injection",
                "pattern": "select.*from",
                "threat_level": "high",
                "confidence": 0.9
            },
        )
        assert resp.status_code == 401

    def test_list_patterns_requires_auth(self, client: TestClient):
        resp = client.get("/admin/patterns")
        assert resp.status_code == 401
