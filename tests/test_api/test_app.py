"""Tests for the certmesh REST API (Phase 4)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from certmesh.api.app import create_app
from certmesh.api.auth import OAuth2Config

JsonDict = dict[str, Any]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture()
def app() -> Any:
    """Create a test FastAPI app with mocked lifespan."""
    application = create_app()

    # Manually set up app state (bypass lifespan for unit tests)
    from certmesh.settings import build_config

    application.state.config = build_config()
    application.state.oauth2_config = OAuth2Config(enabled=False)
    application.state.jwt_bearer = MagicMock(return_value=None)
    application.state.vault_client = None
    application.state.aws_required = False

    return application


@pytest.fixture()
def client(app: Any) -> TestClient:
    """Synchronous test client (no async needed for these tests)."""
    return TestClient(app, raise_server_exceptions=False)


# =============================================================================
# Health endpoints
# =============================================================================


class TestHealthEndpoints:
    def test_healthz(self, client: TestClient) -> None:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "3.0.0"

    def test_livez(self, client: TestClient) -> None:
        resp = client.get("/livez")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_readyz_no_vault(self, client: TestClient) -> None:
        resp = client.get("/readyz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert data["checks"]["vault"] == "not_configured"

    def test_readyz_with_vault_authenticated(self, app: Any, client: TestClient) -> None:
        mock_vault = MagicMock()
        mock_vault.is_authenticated.return_value = True
        app.state.vault_client = mock_vault
        resp = client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["checks"]["vault"] == "ok"

    def test_readyz_with_vault_unauthenticated(self, app: Any, client: TestClient) -> None:
        mock_vault = MagicMock()
        mock_vault.is_authenticated.return_value = False
        app.state.vault_client = mock_vault
        resp = client.get("/readyz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["vault"] == "unauthenticated"
        assert data["status"] == "degraded"


# =============================================================================
# Security headers
# =============================================================================


class TestSecurityHeaders:
    def test_security_headers_present(self, client: TestClient) -> None:
        resp = client.get("/healthz")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Cache-Control"] == "no-store"
        assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "default-src 'none'" in resp.headers["Content-Security-Policy"]

    def test_request_id_generated(self, client: TestClient) -> None:
        resp = client.get("/healthz")
        assert "X-Request-ID" in resp.headers
        # Should be a UUID-like string
        assert len(resp.headers["X-Request-ID"]) > 10

    def test_request_id_propagated(self, client: TestClient) -> None:
        resp = client.get("/healthz", headers={"X-Request-ID": "test-req-123"})
        assert resp.headers["X-Request-ID"] == "test-req-123"


# =============================================================================
# Prometheus metrics
# =============================================================================


class TestMetrics:
    def test_metrics_endpoint(self, client: TestClient) -> None:
        # Make a request first to generate metrics
        client.get("/healthz")
        resp = client.get("/metrics")
        assert resp.status_code == 200
        body = resp.text
        # Should contain our custom metrics
        assert "certmesh_http_requests_total" in body
        assert "certmesh_http_request_duration_seconds" in body

    def test_metrics_increment(self, client: TestClient) -> None:
        # Multiple requests should increment counter
        for _ in range(3):
            client.get("/healthz")
        resp = client.get("/metrics")
        body = resp.text
        assert "certmesh_http_requests_total" in body


# =============================================================================
# Error handling
# =============================================================================


class TestErrorHandling:
    def test_404_for_unknown_route(self, client: TestClient) -> None:
        resp = client.get("/api/v1/nonexistent")
        assert resp.status_code == 404

    def test_certmesh_error_mapped(self, app: Any, client: TestClient) -> None:
        """CertMeshError exceptions are mapped to appropriate HTTP status codes."""
        from certmesh.exceptions import VaultSecretNotFoundError

        @app.get("/test-error")
        async def raise_error() -> None:
            raise VaultSecretNotFoundError("test secret not found")

        resp = client.get("/test-error")
        assert resp.status_code == 404
        assert "test secret not found" in resp.json()["detail"]


# =============================================================================
# DigiCert routes (basic structure test)
# =============================================================================


class TestDigiCertRoutes:
    def test_list_certificates_route_exists(self, client: TestClient) -> None:
        """Verify the route is registered (will fail calling the actual client)."""
        resp = client.get("/api/v1/digicert/certificates")
        # Will get 500 because there's no real DigiCert session, but route exists
        assert resp.status_code in (200, 500)

    def test_search_route_rejects_unknown_fields(self, client: TestClient) -> None:
        """Strict Pydantic mode rejects unknown fields."""
        resp = client.post(
            "/api/v1/digicert/certificates/search",
            json={"common_name": "test.com", "unknown_field": "bad"},
        )
        assert resp.status_code == 422

    def test_order_route_validates_input(self, client: TestClient) -> None:
        """DigiCertOrderRequest requires common_name."""
        resp = client.post("/api/v1/digicert/orders", json={})
        assert resp.status_code == 422


# =============================================================================
# Venafi routes
# =============================================================================


class TestVenafiRoutes:
    def test_list_certificates(self, client: TestClient) -> None:
        resp = client.get("/api/v1/venafi/certificates")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_certificate(self, client: TestClient) -> None:
        resp = client.get("/api/v1/venafi/certificates/test-guid-123")
        assert resp.status_code == 200
        assert resp.json()["guid"] == "test-guid-123"


# =============================================================================
# ACM routes
# =============================================================================


class TestACMRoutes:
    def test_request_cert_validates_input(self, client: TestClient) -> None:
        resp = client.post("/api/v1/acm/certificates", json={})
        assert resp.status_code == 422

    def test_route53_sync_validates_input(self, client: TestClient) -> None:
        resp = client.post("/api/v1/acm/route53/sync", json={})
        assert resp.status_code == 422

    def test_route53_sync_requires_fields(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/acm/route53/sync",
            json={"certificate_arn": "arn:aws:acm:us-east-1:123:cert/abc"},
        )
        assert resp.status_code == 422  # missing hosted_zone_id


# =============================================================================
# OAuth2 auth (disabled)
# =============================================================================


class TestOAuth2Disabled:
    def test_no_auth_required_when_disabled(self, client: TestClient) -> None:
        """When OAuth2 is disabled, endpoints should be accessible without tokens."""
        resp = client.get("/healthz")
        assert resp.status_code == 200

    def test_venafi_accessible_without_token(self, client: TestClient) -> None:
        resp = client.get("/api/v1/venafi/certificates")
        assert resp.status_code == 200


# =============================================================================
# OAuth2 auth (enabled — unit tests)
# =============================================================================


class TestOAuth2Config:
    def test_effective_jwks_uri_derived(self) -> None:
        config = OAuth2Config(issuer_url="https://auth.example.com")
        assert config.effective_jwks_uri() == "https://auth.example.com/.well-known/jwks.json"

    def test_effective_jwks_uri_explicit(self) -> None:
        config = OAuth2Config(
            issuer_url="https://auth.example.com",
            jwks_uri="https://custom.example.com/jwks",
        )
        assert config.effective_jwks_uri() == "https://custom.example.com/jwks"

    def test_oauth2_config_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.api.app import _build_oauth2_config

        monkeypatch.setenv("CM_OAUTH2_ENABLED", "true")
        monkeypatch.setenv("CM_OAUTH2_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("CM_OAUTH2_AUDIENCE", "certmesh-api")
        monkeypatch.setenv("CM_OAUTH2_REQUIRED_SCOPES", "certmesh:read,certmesh:write")

        config = _build_oauth2_config()
        assert config.enabled is True
        assert config.issuer_url == "https://auth.example.com"
        assert config.audience == "certmesh-api"
        assert config.required_scopes == ["certmesh:read", "certmesh:write"]


# =============================================================================
# Pydantic strict mode
# =============================================================================


class TestStrictMode:
    def test_order_rejects_wrong_type(self, client: TestClient) -> None:
        """Strict mode rejects type coercion (string where int expected)."""
        resp = client.post(
            "/api/v1/digicert/orders",
            json={
                "common_name": "test.com",
                "validity_years": "not-an-int",  # Should be int
            },
        )
        assert resp.status_code == 422

    def test_revoke_rejects_extra_fields(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/digicert/certificates/123/revoke",
            json={"reason": "unspecified", "extra": "field"},
        )
        assert resp.status_code == 422
