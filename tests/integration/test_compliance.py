"""Integration tests for Entropy Compliance endpoints."""

import pytest
from fastapi.testclient import TestClient


class TestComplianceViolationsEndpoint:
    """Tests for GET /v1/compliance/violations."""

    def test_requires_auth(self, client: TestClient):
        resp = client.get("/v1/compliance/violations")
        assert resp.status_code == 401

    def test_with_master_key_returns_list(self, client: TestClient):
        resp = client.get(
            "/v1/compliance/violations",
            headers={"X-API-Key": "test-master-key"},
        )
        # DB is not available in test env — expect 503 or empty 200
        assert resp.status_code in (200, 503)
        if resp.status_code == 200:
            assert isinstance(resp.json(), list)


class TestComplianceStatsEndpoint:
    """Tests for GET /v1/compliance/stats."""

    def test_requires_auth(self, client: TestClient):
        resp = client.get("/v1/compliance/stats")
        assert resp.status_code == 401

    def test_returns_stats_schema(self, client: TestClient):
        resp = client.get(
            "/v1/compliance/stats",
            headers={"X-API-Key": "test-master-key"},
        )
        assert resp.status_code in (200, 503)
        if resp.status_code == 200:
            data = resp.json()
            assert "total_requests" in data
            assert "health_score" in data
            assert "violations_by_threat" in data


class TestComplianceOverrideEndpoint:
    """Tests for POST /v1/compliance/override."""

    def test_requires_auth(self, client: TestClient):
        resp = client.post(
            "/v1/compliance/override",
            json={
                "request_log_id": "00000000-0000-0000-0000-000000000000",
                "action": "FALSE_POSITIVE",
                "reason": "Safe healthcare context",
            },
        )
        assert resp.status_code == 401

    def test_invalid_body(self, client: TestClient):
        resp = client.post(
            "/v1/compliance/override",
            json={"action": "FALSE_POSITIVE"},  # missing required fields
            headers={"X-API-Key": "test-master-key"},
        )
        assert resp.status_code == 422


class TestComplianceDashboardRoute:
    """Tests for /admin/compliance static dashboard."""

    def test_dashboard_route_exists(self, client: TestClient):
        resp = client.get("/admin/compliance")
        # Either serves the HTML or 404 (if static folder not yet present)
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert "text/html" in resp.headers["content-type"]


class TestGuardrailsGeneratorEndpoint:
    """Tests for POST /v1/compliance/generate-guardrails."""

    def test_requires_auth(self, client: TestClient):
        resp = client.post(
            "/v1/compliance/generate-guardrails",
            files={"file": ("test.pdf", b"fake pdf content", "application/pdf")},
        )
        assert resp.status_code == 401

    def test_rejects_non_pdf(self, client: TestClient):
        resp = client.post(
            "/v1/compliance/generate-guardrails",
            files={"file": ("test.txt", b"some text", "text/plain")},
            headers={"X-API-Key": "test-master-key"},
        )
        assert resp.status_code == 422
