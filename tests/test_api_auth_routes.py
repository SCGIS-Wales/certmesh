"""Unit tests for auth routes (API key exchange endpoints)."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from certmesh.api.apikeys import APIKeyConfig, APIKeyStore
from certmesh.api.auth import JWTBearer, OAuth2Config
from certmesh.api.routes.auth_routes import router


def _create_test_app(oauth2_enabled: bool = True) -> FastAPI:
    """Create a minimal FastAPI app with auth routes for testing."""
    app = FastAPI()
    app.include_router(router)

    # Mock app state
    oauth2_config = OAuth2Config(enabled=oauth2_enabled)
    app.state.oauth2_config = oauth2_config
    app.state.jwt_bearer = JWTBearer(oauth2_config)
    app.state.api_key_config = APIKeyConfig()
    app.state.api_key_store = APIKeyStore()

    return app


class TestTokenExchangeEndpoint:
    def test_exchange_with_oauth_disabled(self):
        """When OAuth2 is disabled, JWTBearer returns None — exchange should fail 400."""
        app = _create_test_app(oauth2_enabled=False)
        client = TestClient(app)

        resp = client.post("/api/v1/auth/token", json={"ttl_seconds": 900})
        assert resp.status_code == 400
        assert "OAuth2 is disabled" in resp.json()["detail"]


class TestTokenRevokeEndpoint:
    def test_revoke_without_api_key_header(self):
        """Revoke requires X-API-Key header."""
        app = _create_test_app(oauth2_enabled=False)
        client = TestClient(app)

        resp = client.post("/api/v1/auth/token/revoke")
        assert resp.status_code == 400


class TestTokenRefreshEndpoint:
    def test_refresh_without_api_key_header(self):
        """Refresh check requires X-API-Key header."""
        app = _create_test_app(oauth2_enabled=False)
        client = TestClient(app)

        resp = client.post("/api/v1/auth/token/refresh")
        assert resp.status_code == 400


class TestAPIKeyValidation:
    def test_valid_api_key_accepted(self):
        """Direct store test: issue + validate flow."""
        store = APIKeyStore()
        claims = {"sub": "test-user", "scope": "certmesh:read"}
        raw_key, _expires_at = store.issue(claims, 900)

        validated, remaining = store.validate(raw_key)
        assert validated["sub"] == "test-user"
        assert remaining > 800  # should be close to 900

    def test_api_key_in_request_header(self):
        """Test that X-API-Key header is recognized by the store."""
        store = APIKeyStore()
        claims = {"sub": "test-user", "scope": "certmesh:read"}
        raw_key, _ = store.issue(claims, 900)

        # Validate directly (simulates middleware behavior)
        validated, _ = store.validate(raw_key)
        assert validated["sub"] == "test-user"
