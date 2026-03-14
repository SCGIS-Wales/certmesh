"""Tests for certmesh.api.routes.venafi — route handler signatures and wiring.

Verifies that every route handler correctly authenticates a Venafi session,
calls the underlying ``venafi_client`` functions with the correct arguments,
and returns the expected response shapes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from certmesh.api.routes.venafi import router
from certmesh.certificate_utils import CertificateBundle
from certmesh.providers.venafi_client import (
    VenafiCertificateDetail,
    VenafiCertificateSummary,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture()
def app() -> FastAPI:
    """Build a minimal FastAPI app with the Venafi router and mocked state."""
    app = FastAPI()
    app.include_router(router)

    app.state.config = {
        "venafi": {
            "base_url": "https://venafi.test",
            "auth_method": "oauth",
            "oauth_client_id": "certapi",
            "oauth_scope": "certificate:manage",
            "tls_verify": False,
            "timeout_seconds": 10,
            "certificate": {"key_size": 2048},
            "retry": {"max_attempts": 1, "wait_min_seconds": 0, "wait_max_seconds": 0},
            "circuit_breaker": {"failure_threshold": 3, "recovery_timeout_seconds": 5},
        },
        "vault": {"url": "https://vault.test", "kv_version": 2},
    }
    app.state.vault_client = MagicMock()
    app.state.jwt_bearer = MagicMock(return_value={"sub": "test-user"})
    return app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


def _make_cert_summary(**overrides: Any) -> VenafiCertificateSummary:
    defaults = {
        "guid": "aaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "dn": "\\VED\\Policy\\Certs\\test",
        "name": "test.example.com",
        "created_on": "2025-01-01T00:00:00Z",
        "schema_class": "X509 Server Certificate",
        "approx_not_after": "2026-01-01T00:00:00Z",
    }
    defaults.update(overrides)
    return VenafiCertificateSummary(**defaults)


def _make_cert_detail(**overrides: Any) -> VenafiCertificateDetail:
    defaults = {
        "guid": "11111111-2222-3333-4444-555555555555",
        "dn": "\\VED\\Policy\\Certs\\web1",
        "name": "web1.example.com",
        "created_on": "2025-06-15T12:00:00Z",
        "serial_number": "01:02:03:04",
        "thumbprint": "AABB1122",
        "valid_from": "2025-06-15T00:00:00Z",
        "valid_to": "2026-06-15T00:00:00Z",
        "issuer": "CN=Corp CA",
        "subject": "CN=web1.example.com",
        "key_algorithm": "RSA",
        "key_size": 2048,
        "san_dns_names": ["web1.example.com"],
        "stage": 500,
        "status": "OK",
        "in_error": False,
    }
    defaults.update(overrides)
    return VenafiCertificateDetail(**defaults)


def _make_bundle(**overrides: Any) -> CertificateBundle:
    defaults = {
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
        "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----",
        "chain_pem": None,
        "certificate_pem_b64": "REFURS0=",
        "serial_number": "AABB1122",
        "common_name": "web1.example.com",
        "not_after": datetime(2026, 6, 15, tzinfo=timezone.utc),
        "source_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    }
    defaults.update(overrides)
    return CertificateBundle(**defaults)


# =============================================================================
# GET /certificates — list
# =============================================================================


class TestListCertificates:
    @patch("certmesh.providers.venafi_client.list_certificates")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_list_returns_paginated(
        self,
        mock_auth: MagicMock,
        mock_list: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_list.return_value = [_make_cert_summary(), _make_cert_summary(guid="2222")]
        resp = client.get("/api/v1/venafi/certificates?limit=100&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    @patch("certmesh.providers.venafi_client.list_certificates")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_list_calls_authenticate(
        self,
        mock_auth: MagicMock,
        mock_list: MagicMock,
        client: TestClient,
        app: FastAPI,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_list.return_value = []
        client.get("/api/v1/venafi/certificates")
        mock_auth.assert_called_once()
        args, _kwargs = mock_auth.call_args
        assert args[0] == app.state.config["venafi"]


# =============================================================================
# POST /certificates/search
# =============================================================================


class TestSearchCertificates:
    @patch("certmesh.providers.venafi_client.search_certificates")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_search_returns_results(
        self,
        mock_auth: MagicMock,
        mock_search: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_search.return_value = [_make_cert_summary()]
        resp = client.post(
            "/api/v1/venafi/certificates/search",
            json={"common_name": "test", "limit": 50, "offset": 0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    @patch("certmesh.providers.venafi_client.search_certificates")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_search_passes_filters(
        self,
        mock_auth: MagicMock,
        mock_search: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_search.return_value = []
        client.post(
            "/api/v1/venafi/certificates/search",
            json={"common_name": "api.example.com", "thumbprint": "AABB"},
        )
        _, kwargs = mock_search.call_args
        assert kwargs["common_name"] == "api.example.com"
        assert kwargs["thumbprint"] == "AABB"


# =============================================================================
# GET /certificates/{guid} — describe
# =============================================================================


class TestGetCertificate:
    @patch("certmesh.providers.venafi_client.describe_certificate")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_describe_returns_detail(
        self,
        mock_auth: MagicMock,
        mock_describe: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_describe.return_value = _make_cert_detail()
        resp = client.get("/api/v1/venafi/certificates/11111111-2222-3333-4444-555555555555")
        assert resp.status_code == 200
        data = resp.json()
        assert data["guid"] == "11111111-2222-3333-4444-555555555555"
        assert data["serial_number"] == "01:02:03:04"
        assert data["key_size"] == 2048

    @patch("certmesh.providers.venafi_client.describe_certificate")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_describe_passes_guid(
        self,
        mock_auth: MagicMock,
        mock_describe: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_describe.return_value = _make_cert_detail()
        client.get("/api/v1/venafi/certificates/my-test-guid")
        _, kwargs = mock_describe.call_args
        assert kwargs["certificate_guid"] == "my-test-guid"


# =============================================================================
# POST /certificates/{guid}/renew
# =============================================================================


class TestRenewCertificate:
    @patch("certmesh.providers.venafi_client.renew_and_download_certificate")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_renew_returns_response(
        self,
        mock_auth: MagicMock,
        mock_renew: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_renew.return_value = _make_bundle()
        resp = client.post(
            "/api/v1/venafi/certificates/test-guid/renew",
            json={"key_size": 4096},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["guid"] == "test-guid"
        assert data["common_name"] == "web1.example.com"
        assert data["serial_number"] == "AABB1122"

    @patch("certmesh.providers.venafi_client.renew_and_download_certificate")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_renew_called_with_correct_guid(
        self,
        mock_auth: MagicMock,
        mock_renew: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_renew.return_value = _make_bundle()
        client.post("/api/v1/venafi/certificates/my-guid-123/renew")
        _, kwargs = mock_renew.call_args
        assert kwargs["certificate_guid"] == "my-guid-123"


# =============================================================================
# POST /certificates/{guid}/revoke
# =============================================================================


class TestRevokeCertificate:
    @patch("certmesh.providers.venafi_client.revoke_certificate")
    @patch("certmesh.providers.venafi_client.describe_certificate")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_revoke_returns_status(
        self,
        mock_auth: MagicMock,
        mock_describe: MagicMock,
        mock_revoke: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_describe.return_value = _make_cert_detail()
        mock_revoke.return_value = {"Success": True}
        resp = client.post(
            "/api/v1/venafi/certificates/test-guid/revoke",
            json={"reason": 1, "comments": "compromised"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "revoked"
        assert data["guid"] == "test-guid"

    @patch("certmesh.providers.venafi_client.revoke_certificate")
    @patch("certmesh.providers.venafi_client.describe_certificate")
    @patch("certmesh.providers.venafi_client.authenticate")
    def test_revoke_passes_correct_args(
        self,
        mock_auth: MagicMock,
        mock_describe: MagicMock,
        mock_revoke: MagicMock,
        client: TestClient,
    ) -> None:
        mock_auth.return_value = MagicMock()
        mock_describe.return_value = _make_cert_detail(dn="\\VED\\Policy\\cert1")
        mock_revoke.return_value = {"Success": True}
        client.post(
            "/api/v1/venafi/certificates/test-guid/revoke",
            json={"reason": 5, "comments": "decommissioned", "disable": True},
        )
        _, kwargs = mock_revoke.call_args
        assert kwargs["certificate_dn"] == "\\VED\\Policy\\cert1"
        assert kwargs["reason"] == 5
        assert kwargs["comments"] == "decommissioned"
        assert kwargs["disable"] is True
