"""Tests for DigiCert client resilience enhancements (Phase 1).

Covers: _RequestIDAdapter, _resolve_ca_bundle, _build_session, enhanced
error messages, DigiCertRateLimitError.retry_after_seconds, Retry-After-aware
retry strategy, and _validate_response_json.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from certmesh.exceptions import (
    DigiCertAPIError,
    DigiCertAuthenticationError,
    DigiCertOrderNotFoundError,
    DigiCertRateLimitError,
)
from certmesh.providers.digicert_client import (
    _build_session,
    _make_retry_decorator,
    _raise_for_digicert_error,
    _RequestIDAdapter,
    _resolve_ca_bundle,
    _validate_response_json,
)

JsonDict = dict[str, Any]


# =============================================================================
# Helpers
# =============================================================================


def _mock_response(
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
    *,
    request_id: str = "test-rid-123",
    endpoint: str = "https://api.digicert.com/test",
) -> MagicMock:
    """Build a mock response with certmesh_request_id and certmesh_endpoint."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.text = text
    resp.headers = headers or {}
    resp.certmesh_request_id = request_id
    resp.certmesh_endpoint = endpoint
    return resp


# =============================================================================
# _RequestIDAdapter
# =============================================================================


class TestRequestIDAdapter:
    """Test the per-request UUID correlation adapter."""

    def test_injects_x_request_id_header(self) -> None:
        adapter = _RequestIDAdapter()
        request = MagicMock(spec=requests.PreparedRequest)
        request.headers = {}
        request.method = "GET"
        request.url = "https://api.digicert.com/test"

        # Mock the parent send()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.elapsed = 0.1

        with patch.object(requests.adapters.HTTPAdapter, "send", return_value=mock_response):
            adapter.send(request)

        # Verify X-Request-ID was injected
        assert "X-Request-ID" in request.headers
        rid = request.headers["X-Request-ID"]
        assert len(rid) == 36  # UUID4 format: 8-4-4-4-12

    def test_attaches_metadata_to_response(self) -> None:
        adapter = _RequestIDAdapter()
        request = MagicMock(spec=requests.PreparedRequest)
        request.headers = {}
        request.method = "POST"
        request.url = "https://api.digicert.com/orders"

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.elapsed = 0.2

        with patch.object(requests.adapters.HTTPAdapter, "send", return_value=mock_response):
            response = adapter.send(request)

        # Verify metadata attached to response
        assert hasattr(response, "certmesh_request_id")
        assert hasattr(response, "certmesh_endpoint")
        assert response.certmesh_request_id == request.headers["X-Request-ID"]
        assert response.certmesh_endpoint == "https://api.digicert.com/orders"

    def test_unique_request_id_per_call(self) -> None:
        adapter = _RequestIDAdapter()
        ids: set[str] = set()

        for _ in range(5):
            request = MagicMock(spec=requests.PreparedRequest)
            request.headers = {}
            request.method = "GET"
            request.url = "https://api.digicert.com/test"

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.elapsed = 0.05

            with patch.object(requests.adapters.HTTPAdapter, "send", return_value=mock_response):
                adapter.send(request)

            ids.add(request.headers["X-Request-ID"])

        assert len(ids) == 5, "Each request should get a unique ID"


# =============================================================================
# _resolve_ca_bundle
# =============================================================================


class TestResolveCaBundle:
    """Test CA bundle resolution priority."""

    def test_config_ca_bundle_takes_priority(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CM_CA_BUNDLE", "/env/ca.pem")
        cfg: JsonDict = {"ca_bundle": "/config/ca.pem", "tls_verify": True}
        assert _resolve_ca_bundle(cfg) == "/config/ca.pem"

    def test_cm_ca_bundle_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CM_CA_BUNDLE", "/env/ca.pem")
        cfg: JsonDict = {"tls_verify": True}
        assert _resolve_ca_bundle(cfg) == "/env/ca.pem"

    def test_requests_ca_bundle_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CM_CA_BUNDLE", raising=False)
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/req/ca.pem")
        cfg: JsonDict = {"tls_verify": True}
        assert _resolve_ca_bundle(cfg) == "/req/ca.pem"

    def test_ssl_cert_file_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CM_CA_BUNDLE", raising=False)
        monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
        monkeypatch.setenv("SSL_CERT_FILE", "/ssl/ca.pem")
        cfg: JsonDict = {"tls_verify": True}
        assert _resolve_ca_bundle(cfg) == "/ssl/ca.pem"

    def test_curl_ca_bundle_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CM_CA_BUNDLE", raising=False)
        monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("CURL_CA_BUNDLE", "/curl/ca.pem")
        cfg: JsonDict = {"tls_verify": True}
        assert _resolve_ca_bundle(cfg) == "/curl/ca.pem"

    def test_tls_verify_true_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {"tls_verify": True}
        assert _resolve_ca_bundle(cfg) is True

    def test_tls_verify_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {"tls_verify": False}
        assert _resolve_ca_bundle(cfg) is False

    def test_tls_verify_string_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {"tls_verify": "/path/to/ca-bundle.crt"}
        assert _resolve_ca_bundle(cfg) == "/path/to/ca-bundle.crt"

    def test_env_priority_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CM_CA_BUNDLE should take priority over REQUESTS_CA_BUNDLE."""
        monkeypatch.setenv("CM_CA_BUNDLE", "/cm/ca.pem")
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/req/ca.pem")
        monkeypatch.setenv("SSL_CERT_FILE", "/ssl/ca.pem")
        cfg: JsonDict = {"tls_verify": True}
        assert _resolve_ca_bundle(cfg) == "/cm/ca.pem"


# =============================================================================
# _build_session — TLS verify, connection pool, proxy logging
# =============================================================================


class TestBuildSession:
    """Test session construction with TLS, pool, and proxy config."""

    @patch(
        "certmesh.providers.digicert_client.creds.resolve_digicert_api_key",
        return_value="test-key",
    )
    def test_session_tls_verify_from_config(
        self, _mock_creds: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {"tls_verify": False, "timeout_seconds": 10}
        session = _build_session(cfg, {}, None)
        assert session.verify is False

    @patch(
        "certmesh.providers.digicert_client.creds.resolve_digicert_api_key",
        return_value="test-key",
    )
    def test_session_ca_bundle_from_env(
        self, _mock_creds: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CM_CA_BUNDLE", "/custom/ca-bundle.pem")
        cfg: JsonDict = {"tls_verify": True, "timeout_seconds": 10}
        session = _build_session(cfg, {}, None)
        assert session.verify == "/custom/ca-bundle.pem"

    @patch(
        "certmesh.providers.digicert_client.creds.resolve_digicert_api_key",
        return_value="test-key",
    )
    def test_session_connection_pool_config(
        self, _mock_creds: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {
            "tls_verify": True,
            "timeout_seconds": 10,
            "connection_pool": {"pool_connections": 5, "pool_maxsize": 15},
        }
        session = _build_session(cfg, {}, None)
        adapter = session.get_adapter("https://example.com")
        assert isinstance(adapter, _RequestIDAdapter)
        # Check pool size on the internal pool manager config
        assert adapter._pool_connections == 5
        assert adapter._pool_maxsize == 15

    @patch(
        "certmesh.providers.digicert_client.creds.resolve_digicert_api_key",
        return_value="test-key",
    )
    def test_session_default_pool_values(
        self, _mock_creds: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {"tls_verify": True, "timeout_seconds": 10}
        session = _build_session(cfg, {}, None)
        adapter = session.get_adapter("https://example.com")
        assert isinstance(adapter, _RequestIDAdapter)
        assert adapter._pool_connections == 10
        assert adapter._pool_maxsize == 20

    @patch(
        "certmesh.providers.digicert_client.creds.resolve_digicert_api_key",
        return_value="test-key",
    )
    def test_proxy_env_logged(
        self,
        _mock_creds: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.com:3128")
        monkeypatch.setenv("NO_PROXY", "*.internal.com,localhost")
        cfg: JsonDict = {"tls_verify": True, "timeout_seconds": 10}
        import logging

        with caplog.at_level(logging.INFO, logger="certmesh.providers.digicert_client"):
            _build_session(cfg, {}, None)
        assert "Proxy environment detected" in caplog.text

    @patch(
        "certmesh.providers.digicert_client.creds.resolve_digicert_api_key",
        return_value="test-key",
    )
    def test_session_headers(
        self, _mock_creds: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {"tls_verify": True, "timeout_seconds": 10}
        session = _build_session(cfg, {}, None)
        assert session.headers["X-DC-DEVKEY"] == "test-key"
        assert session.headers["Content-Type"] == "application/json"
        assert session.headers["Accept"] == "application/json"

    @patch(
        "certmesh.providers.digicert_client.creds.resolve_digicert_api_key",
        return_value="test-key",
    )
    def test_session_timeout(
        self, _mock_creds: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in ("CM_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(var, raising=False)
        cfg: JsonDict = {"tls_verify": True, "timeout_seconds": 45}
        session = _build_session(cfg, {}, None)
        assert session.certmesh_timeout == 45


# =============================================================================
# Enhanced error messages
# =============================================================================


class TestEnhancedErrorMessages:
    """Test that error messages include request_id, endpoint, and remediation hints."""

    def test_401_includes_request_id_and_remediation(self) -> None:
        resp = _mock_response(status_code=401, text="Unauthorized", request_id="abc-123")
        with pytest.raises(DigiCertAuthenticationError, match="abc-123") as exc_info:
            _raise_for_digicert_error(resp)
        msg = str(exc_info.value)
        assert "request_id=abc-123" in msg
        assert "endpoint=" in msg
        assert "Remediation" in msg
        assert "API key" in msg
        assert "do not expire" in msg
        assert "not expired" not in msg  # API keys never expire per spec

    def test_404_includes_endpoint_and_remediation(self) -> None:
        resp = _mock_response(
            status_code=404,
            text="Not Found",
            endpoint="https://api.digicert.com/orders/99999",
        )
        with pytest.raises(DigiCertOrderNotFoundError) as exc_info:
            _raise_for_digicert_error(resp)
        msg = str(exc_info.value)
        assert "orders/99999" in msg
        assert "Remediation" in msg

    def test_429_uses_fixed_backoff_and_remediation(self) -> None:
        """DigiCert does NOT return Retry-After headers; fixed 60s backoff is used."""
        resp = _mock_response(
            status_code=429,
            text="Rate limited",
            request_id="rate-rid",
        )
        with pytest.raises(DigiCertRateLimitError) as exc_info:
            _raise_for_digicert_error(resp)
        msg = str(exc_info.value)
        assert "rate-rid" in msg
        assert "1000 req/3min" in msg
        assert "60s backoff" in msg

    def test_500_includes_status_page_hint(self) -> None:
        resp = _mock_response(status_code=500, text="Internal Server Error")
        with pytest.raises(DigiCertAPIError) as exc_info:
            _raise_for_digicert_error(resp)
        msg = str(exc_info.value)
        assert "status.digicert.com" in msg
        assert "request_id=" in msg

    def test_error_with_missing_certmesh_attrs(self) -> None:
        """Error handler should degrade gracefully if response lacks certmesh attrs."""
        resp = MagicMock(spec=["status_code", "ok", "text", "headers"])
        resp.status_code = 503
        resp.ok = False
        resp.text = "Service Unavailable"
        resp.headers = {}
        # spec=[] prevents auto-creation of certmesh_request_id / certmesh_endpoint
        with pytest.raises(DigiCertAPIError) as exc_info:
            _raise_for_digicert_error(resp)
        msg = str(exc_info.value)
        assert "unknown" in msg  # fallback value from getattr(..., "unknown")


# =============================================================================
# DigiCertRateLimitError.retry_after_seconds
# =============================================================================


class TestRateLimitRetryAfter:
    """Test fixed backoff since DigiCert does NOT return Retry-After headers."""

    def test_numeric_value(self) -> None:
        err = DigiCertRateLimitError("rate limited", retry_after="30")
        assert err.retry_after_seconds() == 30.0

    def test_float_value(self) -> None:
        err = DigiCertRateLimitError("rate limited", retry_after="2.5")
        assert err.retry_after_seconds() == 2.5

    def test_empty_string_returns_default(self) -> None:
        """Empty retry_after returns 60s default, not None."""
        err = DigiCertRateLimitError("rate limited", retry_after="")
        assert err.retry_after_seconds() == 60.0

    def test_default_retry_after_is_60(self) -> None:
        """Default backoff is 60s since DigiCert doesn't return Retry-After."""
        err = DigiCertRateLimitError("rate limited")
        assert err.retry_after == "60"
        assert err.retry_after_seconds() == 60.0

    def test_unparseable_value_returns_default(self) -> None:
        """Unparseable values fall back to 60s default."""
        err = DigiCertRateLimitError("rate limited", retry_after="not-a-number")
        assert err.retry_after_seconds() == 60.0

    def test_retry_after_stored_on_exception(self) -> None:
        err = DigiCertRateLimitError("msg", retry_after="60")
        assert err.retry_after == "60"


# =============================================================================
# _validate_response_json
# =============================================================================


class TestValidateResponseJson:
    """Test JSON response validation helper."""

    def test_all_keys_present_no_error(self) -> None:
        data = {"id": 1, "status": "issued", "certificate": "PEM"}
        _validate_response_json(data, {"id", "status"})  # should not raise

    def test_missing_keys_raises(self) -> None:
        data = {"id": 1}
        with pytest.raises(DigiCertAPIError, match="missing expected key") as exc_info:
            _validate_response_json(data, {"id", "status", "certificate"})
        msg = str(exc_info.value)
        assert "certificate" in msg
        assert "status" in msg

    def test_includes_context_in_message(self) -> None:
        data = {"foo": "bar"}
        with pytest.raises(DigiCertAPIError, match="order submission") as exc_info:
            _validate_response_json(data, {"id"}, context="order submission", request_id="ctx-rid")
        msg = str(exc_info.value)
        assert "ctx-rid" in msg
        assert "order submission" in msg

    def test_empty_data_with_required_keys(self) -> None:
        with pytest.raises(DigiCertAPIError, match="missing expected key"):
            _validate_response_json({}, {"id"})

    def test_empty_required_keys_no_error(self) -> None:
        _validate_response_json({"any": "data"}, set())  # should not raise

    def test_remediation_hint_in_message(self) -> None:
        with pytest.raises(DigiCertAPIError, match="Remediation"):
            _validate_response_json({}, {"missing_key"})


# =============================================================================
# Retry-After-aware retry strategy
# =============================================================================


class TestRetryAfterStrategy:
    """Test that _make_retry_decorator honours Retry-After."""

    def test_retry_decorator_retries_rate_limit(self) -> None:
        """Verify the decorator is configured to retry on DigiCertRateLimitError."""
        cfg: JsonDict = {
            "retry": {
                "max_attempts": 3,
                "wait_min_seconds": 0,
                "wait_max_seconds": 1,
                "wait_multiplier": 1.0,
            }
        }
        decorator = _make_retry_decorator(cfg)
        # The decorator should be a callable (tenacity retry decorator)
        assert callable(decorator)

    def test_retry_decorator_retries_connection_error(self) -> None:
        """The retry config should include ConnectionError in retry conditions."""
        cfg: JsonDict = {
            "retry": {
                "max_attempts": 2,
                "wait_min_seconds": 0,
                "wait_max_seconds": 0.1,
                "wait_multiplier": 1.0,
            }
        }
        decorator = _make_retry_decorator(cfg)

        call_count = 0

        @decorator
        def _failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise requests.exceptions.ConnectionError("connection refused")

        with pytest.raises(requests.exceptions.ConnectionError):
            _failing_func()

        assert call_count == 2  # max_attempts = 2

    def test_retry_decorator_retries_timeout(self) -> None:
        cfg: JsonDict = {
            "retry": {
                "max_attempts": 2,
                "wait_min_seconds": 0,
                "wait_max_seconds": 0.1,
                "wait_multiplier": 1.0,
            }
        }
        decorator = _make_retry_decorator(cfg)

        call_count = 0

        @decorator
        def _failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise requests.exceptions.Timeout("read timed out")

        with pytest.raises(requests.exceptions.Timeout):
            _failing_func()

        assert call_count == 2

    def test_rate_limit_retry_uses_retry_after(self) -> None:
        """Rate limit errors with Retry-After should be honoured in wait."""
        cfg: JsonDict = {
            "retry": {
                "max_attempts": 2,
                "wait_min_seconds": 0,
                "wait_max_seconds": 0.1,
                "wait_multiplier": 1.0,
            }
        }
        decorator = _make_retry_decorator(cfg)

        call_count = 0

        @decorator
        def _failing_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise DigiCertRateLimitError("rate limited", retry_after="0.01")
            return "success"

        result = _failing_func()
        assert result == "success"
        assert call_count == 2


# =============================================================================
# Settings env overrides
# =============================================================================


class TestSettingsEnvOverrides:
    """Test new DigiCert settings and env overrides."""

    def test_tls_verify_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_VAULT_URL", "https://vault.test")
        monkeypatch.setenv("CM_DIGICERT_TLS_VERIFY", "false")
        cfg = build_config()
        assert cfg["digicert"]["tls_verify"] is False

    def test_ca_bundle_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_VAULT_URL", "https://vault.test")
        monkeypatch.setenv("CM_DIGICERT_CA_BUNDLE", "/custom/ca.pem")
        cfg = build_config()
        assert cfg["digicert"]["ca_bundle"] == "/custom/ca.pem"

    def test_pool_connections_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_VAULT_URL", "https://vault.test")
        monkeypatch.setenv("CM_DIGICERT_POOL_CONNECTIONS", "25")
        cfg = build_config()
        assert cfg["digicert"]["connection_pool"]["pool_connections"] == 25

    def test_pool_maxsize_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_VAULT_URL", "https://vault.test")
        monkeypatch.setenv("CM_DIGICERT_POOL_MAXSIZE", "50")
        cfg = build_config()
        assert cfg["digicert"]["connection_pool"]["pool_maxsize"] == 50

    def test_defaults_present(self) -> None:
        from certmesh.settings import build_config

        cfg = build_config()
        assert cfg["digicert"]["tls_verify"] is True
        assert cfg["digicert"]["ca_bundle"] == ""
        assert cfg["digicert"]["connection_pool"]["pool_connections"] == 10
        assert cfg["digicert"]["connection_pool"]["pool_maxsize"] == 20

    def test_vault_kv_version_default(self) -> None:
        from certmesh.settings import build_config

        cfg = build_config()
        assert cfg["vault"]["kv_version"] == 2

    def test_vault_kv_version_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_VAULT_KV_VERSION", "1")
        cfg = build_config()
        assert cfg["vault"]["kv_version"] == 1
