"""Unit tests for FastAPI application factory and wiring."""

from fastapi.testclient import TestClient

from certmesh.api.app import create_app


class TestCreateApp:
    def test_app_created(self, monkeypatch):
        """Application factory creates a FastAPI app."""
        monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        app = create_app()
        assert app.title == "certmesh"
        assert app.version == "3.2.0"

    def test_health_endpoint(self, monkeypatch):
        monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        app = create_app()
        client = TestClient(app)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_docs_available(self, monkeypatch):
        monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        app = create_app()
        client = TestClient(app)
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_auth_routes_registered(self, monkeypatch):
        monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        app = create_app()
        paths = [route.path for route in app.routes]
        assert "/api/v1/auth/token" in paths
        assert "/api/v1/auth/token/refresh" in paths
        assert "/api/v1/auth/token/revoke" in paths


class TestSecurityHeaders:
    def test_security_headers_present(self, monkeypatch):
        monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        app = create_app()
        client = TestClient(app)
        resp = client.get("/healthz")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "max-age" in resp.headers.get("Strict-Transport-Security", "")
        assert resp.headers.get("Cache-Control") == "no-store"

    def test_request_id_header(self, monkeypatch):
        monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        app = create_app()
        client = TestClient(app)
        resp = client.get("/healthz")
        assert "X-Request-ID" in resp.headers

    def test_request_id_propagated(self, monkeypatch):
        monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        app = create_app()
        client = TestClient(app)
        resp = client.get("/healthz", headers={"X-Request-ID": "test-req-123"})
        assert resp.headers.get("X-Request-ID") == "test-req-123"
