"""Tests for certmesh.api.routes.acm - route handler signatures and wiring.

Verifies that every route handler correctly calls the underlying
``acm_client`` functions with the correct arguments and return types,
and returns the expected response shapes.

Key bugs fixed by this test suite:
    - request_certificate returned str ARN, not dict (was calling .get())
    - export_certificate required passphrase bytes, not vault_client kwarg
    - get_validation_records returned dataclass objects, not dicts
    - list_certificates returned dataclass objects, not dicts
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from certmesh.api.routes.acm import router
from certmesh.providers.acm_client import (
    ACMCertificateDetail,
    ACMCertificateSummary,
    ACMValidationRecord,
)

# =============================================================================
# Fixtures
# =============================================================================

_SAMPLE_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/abcd-1234"


@pytest.fixture()
def app() -> FastAPI:
    """Build a minimal FastAPI app with the ACM router and mocked state."""
    application = FastAPI()
    application.include_router(router)

    application.state.config = {
        "acm": {
            "region": "us-east-1",
            "certificate": {
                "validation_method": "DNS",
                "key_algorithm": "RSA_2048",
            },
            "output": {},
            "polling": {"interval_seconds": 1, "max_wait_seconds": 10},
        },
    }
    application.state.vault_client = MagicMock()
    application.state.jwt_bearer = MagicMock(return_value={"sub": "test-user"})
    return application


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


def _make_cert_summary(**overrides: Any) -> ACMCertificateSummary:
    defaults = {
        "certificate_arn": _SAMPLE_ARN,
        "domain_name": "example.com",
        "status": "ISSUED",
        "key_algorithm": "RSA_2048",
        "type": "AMAZON_ISSUED",
        "in_use": True,
        "not_after": datetime(2026, 6, 15, tzinfo=timezone.utc),
        "not_before": datetime(2025, 6, 15, tzinfo=timezone.utc),
    }
    defaults.update(overrides)
    return ACMCertificateSummary(**defaults)


def _make_cert_detail(**overrides: Any) -> ACMCertificateDetail:
    defaults = {
        "certificate_arn": _SAMPLE_ARN,
        "domain_name": "example.com",
        "subject_alternative_names": ["example.com", "www.example.com"],
        "status": "ISSUED",
        "type": "AMAZON_ISSUED",
        "key_algorithm": "RSA_2048",
        "serial": "AA:BB:CC:DD",
        "issuer": "Amazon",
        "not_before": datetime(2025, 6, 15, tzinfo=timezone.utc),
        "not_after": datetime(2026, 6, 15, tzinfo=timezone.utc),
        "created_at": datetime(2025, 6, 15, tzinfo=timezone.utc),
        "renewal_eligibility": "ELIGIBLE",
        "in_use_by": ["arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb"],
        "failure_reason": "",
        "raw": {
            "DomainValidationOptions": [
                {
                    "DomainName": "example.com",
                    "ValidationMethod": "DNS",
                    "ValidationStatus": "SUCCESS",
                    "ResourceRecord": {
                        "Name": "_token.example.com",
                        "Type": "CNAME",
                        "Value": "_token.acm-validations.aws",
                    },
                }
            ]
        },
    }
    defaults.update(overrides)
    return ACMCertificateDetail(**defaults)


def _make_validation_record(**overrides: Any) -> ACMValidationRecord:
    defaults = {
        "domain_name": "example.com",
        "validation_method": "DNS",
        "validation_status": "SUCCESS",
        "resource_record_name": "_token.example.com.",
        "resource_record_type": "CNAME",
        "resource_record_value": "_token.acm-validations.aws.",
        "validation_emails": [],
    }
    defaults.update(overrides)
    return ACMValidationRecord(**defaults)


# =============================================================================
# GET /certificates - list
# =============================================================================


class TestListCertificates:
    @patch("certmesh.providers.acm_client.list_certificates")
    def test_list_returns_paginated(
        self,
        mock_list: MagicMock,
        client: TestClient,
    ) -> None:
        """list_certificates returns ACMCertificateSummary dataclasses
        which must be converted to dicts for PaginatedResponse."""
        mock_list.return_value = [
            _make_cert_summary(),
            _make_cert_summary(status="PENDING_VALIDATION"),
        ]
        resp = client.get("/api/v1/acm/certificates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2
        # Verify dataclass was converted to dict properly
        assert data["items"][0]["certificate_arn"] == _SAMPLE_ARN
        assert data["items"][0]["domain_name"] == "example.com"

    @patch("certmesh.providers.acm_client.list_certificates")
    def test_list_empty(
        self,
        mock_list: MagicMock,
        client: TestClient,
    ) -> None:
        mock_list.return_value = []
        resp = client.get("/api/v1/acm/certificates")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []


# =============================================================================
# POST /certificates - request
# =============================================================================


class TestRequestCertificate:
    @patch("certmesh.providers.acm_client.request_certificate")
    def test_request_returns_arn(
        self,
        mock_request: MagicMock,
        client: TestClient,
    ) -> None:
        """request_certificate returns a string ARN, not a dict.
        The route must use the string directly, not call .get()."""
        mock_request.return_value = _SAMPLE_ARN
        resp = client.post(
            "/api/v1/acm/certificates",
            json={"domain_name": "example.com"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["certificate_arn"] == _SAMPLE_ARN
        assert data["domain_name"] == "example.com"
        assert data["status"] == "PENDING_VALIDATION"
        assert data["key_algorithm"] == "RSA_2048"

    @patch("certmesh.providers.acm_client.request_certificate")
    def test_request_passes_all_params(
        self,
        mock_request: MagicMock,
        client: TestClient,
    ) -> None:
        mock_request.return_value = _SAMPLE_ARN
        client.post(
            "/api/v1/acm/certificates",
            json={
                "domain_name": "api.example.com",
                "subject_alternative_names": ["api.example.com", "*.api.example.com"],
                "validation_method": "DNS",
                "key_algorithm": "EC_prime256v1",
                "idempotency_token": "deploy-2026-03-14",
            },
        )
        _, kwargs = mock_request.call_args
        assert kwargs["domain_name"] == "api.example.com"
        assert kwargs["subject_alternative_names"] == ["api.example.com", "*.api.example.com"]
        assert kwargs["validation_method"] == "DNS"
        assert kwargs["key_algorithm"] == "EC_prime256v1"
        assert kwargs["idempotency_token"] == "deploy-2026-03-14"

    def test_request_validates_input(self, client: TestClient) -> None:
        """domain_name is required."""
        resp = client.post("/api/v1/acm/certificates", json={})
        assert resp.status_code == 422

    @patch("certmesh.providers.acm_client.request_certificate")
    def test_request_with_tags(
        self,
        mock_request: MagicMock,
        client: TestClient,
    ) -> None:
        mock_request.return_value = _SAMPLE_ARN
        client.post(
            "/api/v1/acm/certificates",
            json={
                "domain_name": "example.com",
                "tags": [{"Key": "Env", "Value": "prod"}],
            },
        )
        _, kwargs = mock_request.call_args
        assert kwargs["tags"] == [{"Key": "Env", "Value": "prod"}]


# =============================================================================
# GET /certificates/{arn}/detail - describe
# =============================================================================


class TestDescribeCertificate:
    @patch("certmesh.providers.acm_client.describe_certificate")
    def test_describe_returns_detail(
        self,
        mock_describe: MagicMock,
        client: TestClient,
    ) -> None:
        mock_describe.return_value = _make_cert_detail()
        resp = client.get(f"/api/v1/acm/certificates/{_SAMPLE_ARN}/detail")
        assert resp.status_code == 200
        data = resp.json()
        assert data["certificate_arn"] == _SAMPLE_ARN
        assert data["domain_name"] == "example.com"
        assert data["status"] == "ISSUED"
        assert data["serial"] == "AA:BB:CC:DD"
        assert data["subject_alternative_names"] == ["example.com", "www.example.com"]

    @patch("certmesh.providers.acm_client.describe_certificate")
    def test_describe_passes_arn(
        self,
        mock_describe: MagicMock,
        client: TestClient,
    ) -> None:
        mock_describe.return_value = _make_cert_detail()
        client.get(f"/api/v1/acm/certificates/{_SAMPLE_ARN}/detail")
        args, _kwargs = mock_describe.call_args
        assert args[1] == _SAMPLE_ARN


# =============================================================================
# GET /certificates/{arn}/validation-records
# =============================================================================


class TestGetValidationRecords:
    @patch("certmesh.providers.acm_client.get_validation_records")
    def test_validation_records_uses_dataclass_attrs(
        self,
        mock_records: MagicMock,
        client: TestClient,
    ) -> None:
        """get_validation_records returns ACMValidationRecord dataclass
        objects, not dicts. The route must access .resource_record_name
        etc., not call .get('Name')."""
        mock_records.return_value = [_make_validation_record()]
        resp = client.get(f"/api/v1/acm/certificates/{_SAMPLE_ARN}/validation-records")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        record = data[0]
        assert record["domain_name"] == "example.com"
        assert record["validation_method"] == "DNS"
        assert record["validation_status"] == "SUCCESS"
        assert record["resource_record_name"] == "_token.example.com."
        assert record["resource_record_type"] == "CNAME"
        assert record["resource_record_value"] == "_token.acm-validations.aws."

    @patch("certmesh.providers.acm_client.get_validation_records")
    def test_validation_records_multiple(
        self,
        mock_records: MagicMock,
        client: TestClient,
    ) -> None:
        mock_records.return_value = [
            _make_validation_record(domain_name="example.com"),
            _make_validation_record(domain_name="www.example.com"),
        ]
        resp = client.get(f"/api/v1/acm/certificates/{_SAMPLE_ARN}/validation-records")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        domains = [r["domain_name"] for r in data]
        assert "example.com" in domains
        assert "www.example.com" in domains


# =============================================================================
# POST /certificates/{arn}/export
# =============================================================================


class TestExportCertificate:
    @patch("certmesh.providers.acm_client.export_and_persist")
    def test_export_requires_passphrase(
        self,
        mock_export: MagicMock,
        client: TestClient,
    ) -> None:
        """export_certificate requires passphrase as bytes."""
        mock_export.return_value = {"cert": "/tmp/cert.pem", "key": "/tmp/key.pem"}
        resp = client.post(
            f"/api/v1/acm/certificates/{_SAMPLE_ARN}/export",
            json={"passphrase": "my-secret-pass"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["certificate_arn"] == _SAMPLE_ARN
        assert data["written_to"]["cert"] == "/tmp/cert.pem"

    @patch("certmesh.providers.acm_client.export_and_persist")
    def test_export_passes_passphrase_as_bytes(
        self,
        mock_export: MagicMock,
        client: TestClient,
    ) -> None:
        """The passphrase string must be encoded to bytes before
        calling export_and_persist."""
        mock_export.return_value = {}
        client.post(
            f"/api/v1/acm/certificates/{_SAMPLE_ARN}/export",
            json={"passphrase": "my-pass"},
        )
        args, _kwargs = mock_export.call_args
        # Third positional arg is passphrase (bytes)
        assert args[2] == b"my-pass"

    def test_export_rejects_missing_passphrase(self, client: TestClient) -> None:
        """Passphrase is required by the schema."""
        resp = client.post(
            f"/api/v1/acm/certificates/{_SAMPLE_ARN}/export",
            json={},
        )
        assert resp.status_code == 422

    @patch("certmesh.providers.acm_client.export_and_persist")
    def test_export_passes_vault_client(
        self,
        mock_export: MagicMock,
        client: TestClient,
        app: FastAPI,
    ) -> None:
        """Vault client should be passed through for certificate persistence."""
        mock_export.return_value = {}
        client.post(
            f"/api/v1/acm/certificates/{_SAMPLE_ARN}/export",
            json={"passphrase": "secret"},
        )
        _, kwargs = mock_export.call_args
        assert kwargs["vault_client"] is app.state.vault_client


# =============================================================================
# DELETE /certificates/{arn}
# =============================================================================


class TestDeleteCertificate:
    @patch("certmesh.providers.acm_client.delete_certificate")
    def test_delete_returns_status(
        self,
        mock_delete: MagicMock,
        client: TestClient,
    ) -> None:
        mock_delete.return_value = None
        resp = client.delete(f"/api/v1/acm/certificates/{_SAMPLE_ARN}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "deleted"
        assert data["certificate_arn"] == _SAMPLE_ARN

    @patch("certmesh.providers.acm_client.delete_certificate")
    def test_delete_passes_arn(
        self,
        mock_delete: MagicMock,
        client: TestClient,
    ) -> None:
        mock_delete.return_value = None
        client.delete(f"/api/v1/acm/certificates/{_SAMPLE_ARN}")
        args, _kwargs = mock_delete.call_args
        assert args[1] == _SAMPLE_ARN


# =============================================================================
# POST /route53/sync
# =============================================================================


class TestRoute53Sync:
    @patch("certmesh.backends.route53_client.sync_validation_records")
    def test_sync_returns_count(
        self,
        mock_sync: MagicMock,
        client: TestClient,
    ) -> None:
        mock_sync.return_value = 2
        resp = client.post(
            "/api/v1/acm/route53/sync",
            json={
                "certificate_arn": _SAMPLE_ARN,
                "hosted_zone_id": "Z1234567890ABC",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["synced_records"] == 2
        assert "2" in data["message"]

    def test_sync_validates_input(self, client: TestClient) -> None:
        """Both certificate_arn and hosted_zone_id are required."""
        resp = client.post("/api/v1/acm/route53/sync", json={})
        assert resp.status_code == 422

    def test_sync_requires_hosted_zone_id(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/acm/route53/sync",
            json={"certificate_arn": _SAMPLE_ARN},
        )
        assert resp.status_code == 422
