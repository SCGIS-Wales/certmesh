"""Tests for certmesh.api.routes.digicert — route handler signatures and wiring.

Verifies that every route handler correctly extracts ``digicert_cfg``,
``vault_cfg``, and ``vault_client`` from ``request.app.state`` and
calls the underlying ``digicert_client`` functions with the correct
positional and keyword arguments.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from certmesh.api.routes.digicert import router
from certmesh.certificate_utils import CertificateBundle
from certmesh.providers.digicert_client import (
    DigiCertCertificateDetail,
    IssuedCertificateSummary,
    OrderRequest,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture()
def app() -> FastAPI:
    """Build a minimal FastAPI app with the DigiCert router and mocked state."""
    app = FastAPI()
    app.include_router(router)

    # Mock app.state to simulate what create_app() wires up.
    app.state.config = {
        "digicert": {
            "base_url": "https://www.digicert.com/services/v2",
            "timeout_seconds": 30,
            "tls_verify": True,
        },
        "vault": {"url": "https://vault.test", "kv_version": 2},
    }
    app.state.vault_client = MagicMock()  # mock hvac.Client
    # Mock JWT bearer to always pass.
    app.state.jwt_bearer = MagicMock(return_value={"sub": "test-user"})
    return app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


def _make_cert_summary(**overrides: Any) -> IssuedCertificateSummary:
    defaults = {
        "certificate_id": 1001,
        "order_id": 5001,
        "common_name": "test.example.com",
        "serial_number": "AABB1122",
        "status": "issued",
        "valid_from": "2025-01-01",
        "valid_till": "2025-12-31",
        "product_name": "ssl_plus",
    }
    defaults.update(overrides)
    return IssuedCertificateSummary(**defaults)


def _make_cert_detail(**overrides: Any) -> DigiCertCertificateDetail:
    defaults = {
        "certificate_id": 1001,
        "order_id": 5001,
        "common_name": "test.example.com",
        "serial_number": "AABB1122",
        "status": "issued",
        "valid_from": "2025-01-01",
        "valid_till": "2025-12-31",
        "product_name": "ssl_plus",
        "sans": ["www.example.com"],
        "organization": "Acme Inc",
        "signature_hash": "sha256",
        "key_size": 4096,
        "thumbprint": "AA:BB:CC",
        "raw": {},
    }
    defaults.update(overrides)
    return DigiCertCertificateDetail(**defaults)


def _make_bundle(**overrides: Any) -> CertificateBundle:
    defaults = {
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
        "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----",
        "chain_pem": None,
        "certificate_pem_b64": "REFURS0=",
        "serial_number": "AABB1122",
        "common_name": "test.example.com",
        "not_after": datetime(2025, 12, 31, tzinfo=timezone.utc),
        "source_id": "5001",
    }
    defaults.update(overrides)
    return CertificateBundle(**defaults)


# =============================================================================
# GET /certificates — list
# =============================================================================


class TestListCertificates:
    @patch("certmesh.providers.digicert_client.list_issued_certificates")
    def test_list_returns_paginated(self, mock_list: MagicMock, client: TestClient) -> None:
        mock_list.return_value = [_make_cert_summary(), _make_cert_summary(certificate_id=1002)]
        resp = client.get("/api/v1/digicert/certificates?page=1&per_page=10")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    @patch("certmesh.providers.digicert_client.list_issued_certificates")
    def test_list_called_with_correct_args(
        self, mock_list: MagicMock, client: TestClient, app: FastAPI
    ) -> None:
        mock_list.return_value = []
        client.get("/api/v1/digicert/certificates?page=1&per_page=25")
        mock_list.assert_called_once()
        args, _kwargs = mock_list.call_args
        # First 3 positional args: digicert_cfg, vault_cfg, vault_cl
        assert args[0] == app.state.config["digicert"]
        assert args[1] == app.state.config.get("vault", {})
        assert args[2] is app.state.vault_client


# =============================================================================
# POST /certificates/search
# =============================================================================


class TestSearchCertificates:
    @patch("certmesh.providers.digicert_client.search_certificates")
    def test_search_returns_results(self, mock_search: MagicMock, client: TestClient) -> None:
        mock_search.return_value = [_make_cert_summary()]
        resp = client.post(
            "/api/v1/digicert/certificates/search",
            json={"common_name": "test", "status": "issued", "page": 1, "per_page": 10},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    @patch("certmesh.providers.digicert_client.search_certificates")
    def test_search_passes_filters(self, mock_search: MagicMock, client: TestClient) -> None:
        mock_search.return_value = []
        client.post(
            "/api/v1/digicert/certificates/search",
            json={"common_name": "api.example.com", "status": "issued", "page": 1, "per_page": 20},
        )
        _, kwargs = mock_search.call_args
        assert kwargs["common_name"] == "api.example.com"
        assert kwargs["status"] == "issued"


# =============================================================================
# GET /certificates/{certificate_id} — describe
# =============================================================================


class TestGetCertificate:
    @patch("certmesh.providers.digicert_client.describe_certificate")
    def test_describe_returns_detail(self, mock_describe: MagicMock, client: TestClient) -> None:
        mock_describe.return_value = _make_cert_detail()
        resp = client.get("/api/v1/digicert/certificates/1001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["order_id"] == "5001"
        assert data["common_name"] == "test.example.com"
        assert data["status"] == "issued"

    @patch("certmesh.providers.digicert_client.describe_certificate")
    def test_describe_called_with_correct_args(
        self, mock_describe: MagicMock, client: TestClient, app: FastAPI
    ) -> None:
        mock_describe.return_value = _make_cert_detail()
        client.get("/api/v1/digicert/certificates/1001")
        args, _ = mock_describe.call_args
        assert args[0] == app.state.config["digicert"]
        assert args[1] == app.state.config.get("vault", {})
        assert args[2] is app.state.vault_client
        assert args[3] == 1001


# =============================================================================
# POST /orders — order
# =============================================================================


class TestOrderCertificate:
    @patch("certmesh.providers.digicert_client.order_and_await_certificate")
    def test_order_returns_response(self, mock_order: MagicMock, client: TestClient) -> None:
        mock_order.return_value = _make_bundle()
        resp = client.post(
            "/api/v1/digicert/orders",
            json={
                "common_name": "test.example.com",
                "san_dns_names": ["www.example.com"],
                "validity_years": 1,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["order_id"] == "5001"
        assert data["common_name"] == "test.example.com"
        assert data["serial_number"] == "AABB1122"

    @patch("certmesh.providers.digicert_client.order_and_await_certificate")
    def test_order_builds_order_request(self, mock_order: MagicMock, client: TestClient) -> None:
        mock_order.return_value = _make_bundle()
        client.post(
            "/api/v1/digicert/orders",
            json={
                "common_name": "test.example.com",
                "validity_years": 1,
                "payment_method": "balance",
                "dcv_method": "dns-txt-token",
            },
        )
        args, _ = mock_order.call_args
        order_req = args[3]
        assert isinstance(order_req, OrderRequest)
        assert order_req.common_name == "test.example.com"
        assert order_req.payment_method == "balance"
        assert order_req.dcv_method == "dns-txt-token"


# =============================================================================
# POST /certificates/{order_id}/revoke
# =============================================================================


class TestRevokeCertificate:
    @patch("certmesh.providers.digicert_client.revoke_certificate")
    def test_revoke_returns_status(self, mock_revoke: MagicMock, client: TestClient) -> None:
        mock_revoke.return_value = {"status": "revoked", "certificate_id": 1001}
        resp = client.post(
            "/api/v1/digicert/certificates/5001/revoke",
            json={"reason": "key_compromise", "comments": "test revoke"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "revoked"
        assert data["order_id"] == "5001"

    @patch("certmesh.providers.digicert_client.revoke_certificate")
    def test_revoke_called_with_correct_args(
        self, mock_revoke: MagicMock, client: TestClient, app: FastAPI
    ) -> None:
        mock_revoke.return_value = {"status": "revoked", "certificate_id": 1001}
        client.post(
            "/api/v1/digicert/certificates/5001/revoke",
            json={"reason": "cessation_of_operation", "comments": "decomm"},
        )
        args, kwargs = mock_revoke.call_args
        assert args[0] == app.state.config["digicert"]
        assert args[1] == app.state.config.get("vault", {})
        assert args[2] is app.state.vault_client
        assert kwargs["order_id"] == 5001
        assert kwargs["reason"] == "cessation_of_operation"
        assert kwargs["comments"] == "decomm"
