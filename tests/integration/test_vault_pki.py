"""Integration tests for Vault PKI secrets engine.

Requires a Vault server running in dev mode:
    docker run -d --name vault-dev -p 8200:8200 \\
        -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.15

Or in CI via GitHub Actions service container.

Run: pytest -m integration tests/integration/test_vault_pki.py -v
"""

from __future__ import annotations

import contextlib
import os

import hvac
import pytest

pytestmark = pytest.mark.integration


def _vault_available() -> bool:
    """Check if Vault dev server is available."""
    try:
        client = hvac.Client(
            url=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
            token=os.environ.get("VAULT_TOKEN", "root"),
        )
        return client.is_authenticated()
    except Exception:
        return False


@pytest.fixture(scope="module")
def vault_client():
    """Connect to Vault dev server and set up PKI engine."""
    if not _vault_available():
        pytest.skip("Vault dev server not available")

    client = hvac.Client(
        url=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
        token=os.environ.get("VAULT_TOKEN", "root"),
    )

    # Enable PKI engine (ignore if already enabled)
    mount_point = "pki_test"
    with contextlib.suppress(hvac.exceptions.InvalidRequest):
        client.sys.enable_secrets_engine("pki", path=mount_point)

    # Generate root CA
    client.secrets.pki.generate_root(
        type="internal",
        common_name="Test Root CA",
        mount_point=mount_point,
    )

    # Create a role
    client.secrets.pki.create_or_update_role(
        "test-server",
        mount_point=mount_point,
        extra_params={
            "allowed_domains": "example.com",
            "allow_subdomains": True,
            "max_ttl": "720h",
        },
    )

    yield client, mount_point

    # Cleanup
    with contextlib.suppress(Exception):
        client.sys.disable_secrets_engine(mount_point)


class TestVaultPKIIssue:
    """Test Vault PKI certificate issuance."""

    def test_issue_leaf_certificate(self, vault_client):
        client, mount = vault_client
        result = client.secrets.pki.generate_certificate(
            name="test-server",
            common_name="test.example.com",
            mount_point=mount,
            extra_params={"ttl": "24h"},
        )
        data = result["data"]
        assert data["certificate"].startswith("-----BEGIN CERTIFICATE-----")
        assert data["private_key"].startswith("-----BEGIN")
        assert data["serial_number"]
        assert data["issuing_ca"].startswith("-----BEGIN CERTIFICATE-----")

    def test_issue_with_sans(self, vault_client):
        client, mount = vault_client
        result = client.secrets.pki.generate_certificate(
            name="test-server",
            common_name="api.example.com",
            mount_point=mount,
            extra_params={
                "alt_names": "api2.example.com,api3.example.com",
                "ttl": "24h",
            },
        )
        assert result["data"]["certificate"]

    def test_issue_with_ip_sans(self, vault_client):
        client, mount = vault_client
        result = client.secrets.pki.generate_certificate(
            name="test-server",
            common_name="internal.example.com",
            mount_point=mount,
            extra_params={
                "ip_sans": "10.0.0.1,10.0.0.2",
                "ttl": "24h",
            },
        )
        assert result["data"]["certificate"]


class TestVaultPKIList:
    """Test listing and reading certificates."""

    def test_list_certificates(self, vault_client):
        client, mount = vault_client
        # Issue a cert first
        client.secrets.pki.generate_certificate(
            name="test-server",
            common_name="list-test.example.com",
            mount_point=mount,
            extra_params={"ttl": "24h"},
        )
        # List
        result = client.secrets.pki.list_certificates(mount_point=mount)
        assert "keys" in result["data"]
        assert len(result["data"]["keys"]) > 0

    def test_read_certificate(self, vault_client):
        client, mount = vault_client
        # Issue a cert
        issue_result = client.secrets.pki.generate_certificate(
            name="test-server",
            common_name="read-test.example.com",
            mount_point=mount,
            extra_params={"ttl": "24h"},
        )
        serial = issue_result["data"]["serial_number"]
        # Read it back
        read_result = client.secrets.pki.read_certificate(serial, mount_point=mount)
        assert read_result["data"]["certificate"].startswith("-----BEGIN CERTIFICATE-----")


class TestVaultPKIRevoke:
    """Test certificate revocation."""

    def test_revoke_certificate(self, vault_client):
        client, mount = vault_client
        # Issue
        issue_result = client.secrets.pki.generate_certificate(
            name="test-server",
            common_name="revoke-test.example.com",
            mount_point=mount,
            extra_params={"ttl": "24h"},
        )
        serial = issue_result["data"]["serial_number"]
        # Revoke
        revoke_result = client.secrets.pki.revoke_certificate(serial, mount_point=mount)
        assert revoke_result["data"]["revocation_time"] > 0


class TestVaultPKISign:
    """Test CSR signing."""

    def test_sign_csr(self, vault_client):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        client, mount = vault_client

        # Generate a CSR
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sign-test.example.com")])
            )
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        result = client.secrets.pki.sign_certificate(
            name="test-server",
            csr=csr_pem,
            common_name="sign-test.example.com",
            mount_point=mount,
            extra_params={"ttl": "24h"},
        )
        assert result["data"]["certificate"].startswith("-----BEGIN CERTIFICATE-----")
        assert result["data"]["serial_number"]


class TestVaultPKICAChain:
    """Test CA chain retrieval (used by the Helm init container)."""

    def test_read_ca_certificate(self, vault_client):
        client, mount = vault_client
        result = client.secrets.pki.read_certificate("ca", mount_point=mount)
        assert result["data"]["certificate"].startswith("-----BEGIN CERTIFICATE-----")
