"""Integration tests for Venafi via VCert Python SDK fake connector.

The VCert fake connector simulates a Venafi TPP server locally,
no real Venafi instance is needed.

Run: pytest -m integration tests/integration/test_venafi_vcert.py -v
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

try:
    from vcert import (
        CertificateRequest,
        KeyType,
        venafi_connection,
    )

    HAS_VCERT = True
except ImportError:
    HAS_VCERT = False


@pytest.fixture
def fake_connector():
    """Create a VCert fake connector."""
    if not HAS_VCERT:
        pytest.skip("vcert package not installed (pip install vcert)")
    conn = venafi_connection(fake=True)
    conn.authenticate()
    return conn


class TestVCertFakeConnector:
    """Test certificate operations via VCert fake connector."""

    def test_authenticate(self, fake_connector):
        """Verify fake connector authenticates successfully."""
        assert fake_connector is not None

    def test_request_certificate(self, fake_connector):
        """Request a certificate via the fake connector."""
        request = CertificateRequest(common_name="test.example.com")
        request.san_dns = ["alt1.example.com", "alt2.example.com"]
        fake_connector.request_cert(request)
        assert request.id is not None

    def test_retrieve_certificate(self, fake_connector):
        """Request and retrieve a certificate."""
        request = CertificateRequest(common_name="retrieve-test.example.com")
        fake_connector.request_cert(request)
        cert = fake_connector.retrieve_cert(request)
        assert cert.cert is not None
        assert "BEGIN CERTIFICATE" in cert.cert

    def test_request_with_key_type(self, fake_connector):
        """Request a certificate with specific key type."""
        request = CertificateRequest(
            common_name="keytype-test.example.com",
            key_type=KeyType.RSA,
            key_length=2048,
        )
        fake_connector.request_cert(request)
        cert = fake_connector.retrieve_cert(request)
        assert cert.cert is not None

    def test_request_with_csr(self, fake_connector):
        """Request a certificate with a custom CSR."""
        request = CertificateRequest(common_name="csr-test.example.com")
        request.csr_origin = "local"
        fake_connector.request_cert(request)
        cert = fake_connector.retrieve_cert(request)
        assert cert.cert is not None
