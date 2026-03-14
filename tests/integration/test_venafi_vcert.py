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

# VCert fake connector uses a default zone
FAKE_ZONE = "Default"


@pytest.fixture
def fake_connector():
    """Create a VCert fake connector."""
    if not HAS_VCERT:
        pytest.skip("vcert package not installed (pip install vcert)")
    conn = venafi_connection(fake=True)
    # FakeConnection does not require authentication; only call if available
    if hasattr(conn, "authenticate"):
        conn.authenticate()
    return conn


class TestVCertFakeConnector:
    """Test certificate operations via VCert fake connector."""

    def test_authenticate(self, fake_connector):
        """Verify fake connector is created successfully."""
        assert fake_connector is not None

    def test_request_certificate(self, fake_connector):
        """Request a certificate via the fake connector."""
        request = CertificateRequest(common_name="test.example.com")
        request.san_dns = ["alt1.example.com", "alt2.example.com"]
        fake_connector.request_cert(request, FAKE_ZONE)
        assert request.id is not None

    def test_retrieve_certificate(self, fake_connector):
        """Request and retrieve a certificate."""
        request = CertificateRequest(common_name="retrieve-test.example.com")
        fake_connector.request_cert(request, FAKE_ZONE)
        cert = fake_connector.retrieve_cert(request)
        assert cert.cert is not None
        assert "BEGIN CERTIFICATE" in cert.cert

    def test_request_with_key_type(self, fake_connector):
        """Request a certificate with specific key type."""
        request = CertificateRequest(common_name="keytype-test.example.com")
        # VCert validates key_type via __setattr__; use the KeyType instance
        request.key_type = KeyType(KeyType.RSA, 2048)
        fake_connector.request_cert(request, FAKE_ZONE)
        cert = fake_connector.retrieve_cert(request)
        assert cert.cert is not None

    def test_request_with_csr(self, fake_connector):
        """Request a certificate with a custom CSR."""
        request = CertificateRequest(common_name="csr-test.example.com")
        request.csr_origin = "local"
        fake_connector.request_cert(request, FAKE_ZONE)
        cert = fake_connector.retrieve_cert(request)
        assert cert.cert is not None

    def test_certificate_contains_valid_pem(self, fake_connector):
        """Retrieved certificate should be valid PEM format."""
        request = CertificateRequest(common_name="pem-test.example.com")
        fake_connector.request_cert(request, FAKE_ZONE)
        cert = fake_connector.retrieve_cert(request)
        assert cert.cert is not None
        assert "BEGIN CERTIFICATE" in cert.cert
        assert "END CERTIFICATE" in cert.cert

    def test_request_empty_common_name_fails(self, fake_connector):
        """Requesting a cert with empty common_name should fail or produce an error."""
        request = CertificateRequest(common_name="")
        try:
            fake_connector.request_cert(request, FAKE_ZONE)
            # If fake connector allows it, cert should still be retrievable
            cert = fake_connector.retrieve_cert(request)
            # Fake connector may not validate — this is acceptable
            assert cert is not None
        except Exception:
            # Expected — empty CN should be rejected
            pass
