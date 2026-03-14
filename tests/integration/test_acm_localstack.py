"""Integration tests for AWS ACM via LocalStack.

Requires LocalStack running:
    docker run -d --name localstack -p 4566:4566 \\
        -e SERVICES=acm localstack/localstack

Run: pytest -m integration tests/integration/test_acm_localstack.py -v
"""

from __future__ import annotations

import os

import boto3
import pytest
from botocore.exceptions import ClientError

pytestmark = pytest.mark.integration


def _localstack_available() -> bool:
    """Check if LocalStack is available."""
    try:
        client = boto3.client(
            "acm",
            endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566"),
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        client.list_certificates()
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def acm_client():
    """Create ACM client pointing to LocalStack."""
    if not _localstack_available():
        pytest.skip("LocalStack not available")

    return boto3.client(
        "acm",
        endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566"),
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


class TestACMRequestCertificate:
    """Test ACM certificate request operations via LocalStack."""

    def test_request_dns_validated_certificate(self, acm_client):
        """Request a DNS-validated certificate."""
        response = acm_client.request_certificate(
            DomainName="test.example.com",
            ValidationMethod="DNS",
        )
        assert "CertificateArn" in response
        assert response["CertificateArn"].startswith("arn:aws:acm:")

    def test_request_with_sans(self, acm_client):
        """Request a certificate with Subject Alternative Names."""
        response = acm_client.request_certificate(
            DomainName="primary.example.com",
            SubjectAlternativeNames=[
                "primary.example.com",
                "alt1.example.com",
                "alt2.example.com",
            ],
            ValidationMethod="DNS",
        )
        assert "CertificateArn" in response

    def test_request_with_tags(self, acm_client):
        """Request a certificate with tags."""
        response = acm_client.request_certificate(
            DomainName="tagged.example.com",
            ValidationMethod="DNS",
            Tags=[
                {"Key": "Environment", "Value": "test"},
                {"Key": "ManagedBy", "Value": "certmesh"},
            ],
        )
        assert "CertificateArn" in response


class TestACMDescribeCertificate:
    """Test ACM certificate describe operations via LocalStack."""

    def test_describe_certificate(self, acm_client):
        """Describe a requested certificate."""
        req = acm_client.request_certificate(
            DomainName="describe.example.com",
            ValidationMethod="DNS",
        )
        arn = req["CertificateArn"]

        detail = acm_client.describe_certificate(CertificateArn=arn)
        cert = detail["Certificate"]
        assert cert["DomainName"] == "describe.example.com"
        assert cert["CertificateArn"] == arn
        assert "Status" in cert

    def test_describe_nonexistent_certificate(self, acm_client):
        """Describing a non-existent certificate should fail."""
        with pytest.raises(ClientError) as exc_info:
            acm_client.describe_certificate(
                CertificateArn="arn:aws:acm:us-east-1:123456789012:certificate/nonexistent"
            )
        assert exc_info.value.response["Error"]["Code"] in (
            "ResourceNotFoundException",
            "CertificateNotFoundException",
        )


class TestACMListCertificates:
    """Test ACM certificate listing via LocalStack."""

    def test_list_certificates(self, acm_client):
        """List all certificates."""
        # Request one first
        acm_client.request_certificate(
            DomainName="list-test.example.com",
            ValidationMethod="DNS",
        )
        response = acm_client.list_certificates()
        assert "CertificateSummaryList" in response
        assert len(response["CertificateSummaryList"]) > 0

    def test_list_empty(self, acm_client):
        """List returns a list (may be empty or populated)."""
        response = acm_client.list_certificates()
        assert isinstance(response["CertificateSummaryList"], list)


class TestACMDeleteCertificate:
    """Test ACM certificate deletion via LocalStack."""

    def test_delete_certificate(self, acm_client):
        """Delete a certificate."""
        req = acm_client.request_certificate(
            DomainName="delete-test.example.com",
            ValidationMethod="DNS",
        )
        arn = req["CertificateArn"]

        # Delete should succeed
        acm_client.delete_certificate(CertificateArn=arn)

        # Describe should now fail
        with pytest.raises(ClientError):
            acm_client.describe_certificate(CertificateArn=arn)


class TestACMErrorHandling:
    """Test ACM error handling via LocalStack."""

    def test_delete_nonexistent_certificate(self, acm_client):
        """Deleting a nonexistent certificate should raise a ClientError."""
        with pytest.raises(ClientError) as exc_info:
            acm_client.delete_certificate(
                CertificateArn="arn:aws:acm:us-east-1:123456789012:certificate/nonexistent-id"
            )
        error_code = exc_info.value.response["Error"]["Code"]
        assert error_code in (
            "ResourceNotFoundException",
            "CertificateNotFoundException",
        ), f"Unexpected error code: {error_code}"

    def test_request_invalid_domain(self, acm_client):
        """Requesting a cert with an invalid domain should fail or return an ARN."""
        # LocalStack may be lenient with domain validation — test the response shape
        try:
            response = acm_client.request_certificate(
                DomainName="*.*.invalid..domain",
                ValidationMethod="DNS",
            )
            # LocalStack may not validate domain format strictly
            assert "CertificateArn" in response
        except ClientError as e:
            # If it does validate, we expect a validation error
            error_code = e.response["Error"]["Code"]
            assert error_code in (
                "InvalidDomainValidationOptionsException",
                "ValidationException",
                "InvalidParameterException",
            ), f"Unexpected error code for invalid domain: {error_code}"

    def test_describe_error_has_proper_structure(self, acm_client):
        """Error responses should have proper Error Code and Message structure."""
        with pytest.raises(ClientError) as exc_info:
            acm_client.describe_certificate(
                CertificateArn="arn:aws:acm:us-east-1:123456789012:certificate/does-not-exist"
            )
        error = exc_info.value.response["Error"]
        assert "Code" in error, "Error response missing 'Code' field"
        assert "Message" in error, "Error response missing 'Message' field"
        assert len(error["Code"]) > 0, "Error code should not be empty"
        assert len(error["Message"]) > 0, "Error message should not be empty"
