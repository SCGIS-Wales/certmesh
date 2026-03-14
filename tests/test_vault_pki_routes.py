"""Tests for certmesh.api.routes.vault_pki — route handler wiring and error handling.

Verifies:
- Issue, sign, read, list, and revoke endpoints call the correct backend functions.
- Error handling maps Vault exceptions to proper HTTP status codes.
- The sign endpoint calls ``sign_pki_certificate`` (not the old ``sign_pki_csr``).
- ``ip_sans`` is forwarded from request body to the backend.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from certmesh.api.routes.vault_pki import router
from certmesh.exceptions import (
    ConfigurationError,
    VaultAuthenticationError,
    VaultPKIError,
)

_VC_MODULE = "certmesh.backends.vault_client"

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture()
def app() -> FastAPI:
    """Build a minimal FastAPI app with the Vault PKI router and mocked state."""
    app = FastAPI()
    app.include_router(router)

    app.state.config = {
        "vault": {
            "url": "https://vault.test",
            "pki": {
                "mount_point": "pki",
                "role_name": "test-role",
                "ttl": "720h",
            },
        },
    }
    app.state.vault_client = MagicMock()
    app.state.jwt_bearer = MagicMock(return_value={"sub": "test-user"})
    return app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# =============================================================================
# List certificates
# =============================================================================


class TestListCertificates:
    def test_success(self, client: TestClient) -> None:
        with patch(f"{_VC_MODULE}.list_pki_certificates", return_value=["12:34", "56:78"]):
            resp = client.get("/api/v1/vault-pki/certificates")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["serial_number"] == "12:34"

    def test_no_vault_client_returns_empty(self, app: FastAPI) -> None:
        app.state.vault_client = None
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.get("/api/v1/vault-pki/certificates")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_auth_error_returns_403(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.list_pki_certificates",
            side_effect=VaultAuthenticationError("denied"),
        ):
            resp = client.get("/api/v1/vault-pki/certificates")
        assert resp.status_code == 403

    def test_pki_error_returns_502(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.list_pki_certificates",
            side_effect=VaultPKIError("backend error"),
        ):
            resp = client.get("/api/v1/vault-pki/certificates")
        assert resp.status_code == 502


# =============================================================================
# Issue certificate
# =============================================================================


class TestIssueCertificate:
    def test_success(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.issue_pki_certificate",
            return_value={
                "certificate": "-----BEGIN CERTIFICATE-----\nfake",
                "issuing_ca": "issuing-ca-pem",
                "serial_number": "ab:cd",
                "expiration": 1735689600,
            },
        ):
            resp = client.post(
                "/api/v1/vault-pki/certificates",
                json={"common_name": "test.example.com"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["serial_number"] == "ab:cd"
        assert body["certificate_pem"] == "-----BEGIN CERTIFICATE-----\nfake"

    def test_ip_sans_forwarded(self, client: TestClient) -> None:
        with patch(f"{_VC_MODULE}.issue_pki_certificate") as mock_issue:
            mock_issue.return_value = {
                "certificate": "cert",
                "serial_number": "11:22",
                "expiration": 0,
            }
            client.post(
                "/api/v1/vault-pki/certificates",
                json={
                    "common_name": "test.example.com",
                    "ip_sans": ["10.0.0.1", "192.168.1.1"],
                },
            )
            call_kwargs = mock_issue.call_args
            assert call_kwargs.kwargs["ip_sans"] == ["10.0.0.1", "192.168.1.1"]

    def test_no_vault_client_returns_503(self, app: FastAPI) -> None:
        app.state.vault_client = None
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post(
            "/api/v1/vault-pki/certificates",
            json={"common_name": "test.example.com"},
        )
        assert resp.status_code == 503

    def test_config_error_returns_422(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.issue_pki_certificate",
            side_effect=ConfigurationError("no role"),
        ):
            resp = client.post(
                "/api/v1/vault-pki/certificates",
                json={"common_name": "test.example.com"},
            )
        assert resp.status_code == 422

    def test_auth_error_returns_403(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.issue_pki_certificate",
            side_effect=VaultAuthenticationError("denied"),
        ):
            resp = client.post(
                "/api/v1/vault-pki/certificates",
                json={"common_name": "test.example.com"},
            )
        assert resp.status_code == 403


# =============================================================================
# Get certificate
# =============================================================================


class TestGetCertificate:
    def test_success(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.read_pki_certificate",
            return_value={"certificate": "cert-pem", "revocation_time": 0},
        ):
            resp = client.get("/api/v1/vault-pki/certificates/12:34")
        assert resp.status_code == 200
        assert resp.json()["certificate_pem"] == "cert-pem"

    def test_no_vault_client_returns_503(self, app: FastAPI) -> None:
        app.state.vault_client = None
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.get("/api/v1/vault-pki/certificates/12:34")
        assert resp.status_code == 503


# =============================================================================
# Sign CSR
# =============================================================================


class TestSignCSR:
    def test_success(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.sign_pki_certificate",
            return_value={
                "certificate": "signed-cert",
                "issuing_ca": "ca-pem",
                "serial_number": "ef:01",
            },
        ):
            resp = client.post(
                "/api/v1/vault-pki/sign",
                json={
                    "csr_pem": "-----BEGIN CSR-----\nfake",
                    "common_name": "test.example.com",
                },
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["serial_number"] == "ef:01"
        assert body["certificate_pem"] == "signed-cert"

    def test_calls_sign_pki_certificate_not_sign_pki_csr(self, client: TestClient) -> None:
        """Regression: the old code called vc.sign_pki_csr which doesn't exist."""
        with patch(f"{_VC_MODULE}.sign_pki_certificate") as mock_sign:
            mock_sign.return_value = {
                "certificate": "signed",
                "serial_number": "00:01",
            }
            client.post(
                "/api/v1/vault-pki/sign",
                json={
                    "csr_pem": "csr-data",
                    "common_name": "x.example.com",
                },
            )
            mock_sign.assert_called_once()

    def test_ip_sans_forwarded(self, client: TestClient) -> None:
        with patch(f"{_VC_MODULE}.sign_pki_certificate") as mock_sign:
            mock_sign.return_value = {
                "certificate": "cert",
                "serial_number": "22:33",
            }
            client.post(
                "/api/v1/vault-pki/sign",
                json={
                    "csr_pem": "csr-data",
                    "common_name": "test.example.com",
                    "ip_sans": ["10.0.0.1"],
                },
            )
            call_kwargs = mock_sign.call_args
            assert call_kwargs.kwargs["ip_sans"] == ["10.0.0.1"]


# =============================================================================
# Revoke certificate
# =============================================================================


class TestRevokeCertificate:
    def test_success(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.revoke_pki_certificate",
            return_value={"revocation_time": 1710000000},
        ):
            resp = client.post(
                "/api/v1/vault-pki/revoke",
                json={"serial_number": "ab:cd:ef"},
            )
        assert resp.status_code == 200
        assert resp.json()["serial_number"] == "ab:cd:ef"

    def test_auth_error_returns_403(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.revoke_pki_certificate",
            side_effect=VaultAuthenticationError("denied"),
        ):
            resp = client.post(
                "/api/v1/vault-pki/revoke",
                json={"serial_number": "ab:cd:ef"},
            )
        assert resp.status_code == 403

    def test_pki_error_returns_502(self, client: TestClient) -> None:
        with patch(
            f"{_VC_MODULE}.revoke_pki_certificate",
            side_effect=VaultPKIError("not found"),
        ):
            resp = client.post(
                "/api/v1/vault-pki/revoke",
                json={"serial_number": "ab:cd:ef"},
            )
        assert resp.status_code == 502

    def test_no_vault_client_returns_503(self, app: FastAPI) -> None:
        app.state.vault_client = None
        c = TestClient(app, raise_server_exceptions=False)
        resp = c.post(
            "/api/v1/vault-pki/revoke",
            json={"serial_number": "ab:cd:ef"},
        )
        assert resp.status_code == 503
