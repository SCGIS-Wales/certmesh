"""Unit tests for RFC 7807 error handling in middleware."""

import pytest

from certmesh.api.middleware import (
    _STATUS_ERROR_TYPES,
    _build_error_body,
    _resolve_status_code,
)
from certmesh.exceptions import (
    ACMRequestError,
    ACMValidationError,
    CertificateError,
    CircuitBreakerOpenError,
    ConfigurationError,
    DigiCertAPIError,
    DigiCertAuthenticationError,
    DigiCertCertificateNotReadyError,
    DigiCertOrderNotFoundError,
    DigiCertPollingTimeoutError,
    DigiCertRateLimitError,
    LetsEncryptChallengeError,
    LetsEncryptRateLimitError,
    VaultAuthenticationError,
    VaultPKIError,
    VaultSecretNotFoundError,
    VaultWriteError,
    VenafiAuthenticationError,
    VenafiCertificateNotFoundError,
    VenafiPollingTimeoutError,
    VenafiPrivateKeyExportError,
)


class TestResolveStatusCode:
    """Verify correct RFC HTTP status codes for each exception type."""

    @pytest.mark.parametrize(
        "exc_class,expected_code",
        [
            # 400 Bad Request
            (CertificateError, 400),
            (ACMValidationError, 400),
            # 401 Unauthorized
            (VaultAuthenticationError, 401),
            (DigiCertAuthenticationError, 401),
            (VenafiAuthenticationError, 401),
            # 403 Forbidden
            (VenafiPrivateKeyExportError, 403),
            # 404 Not Found
            (VaultSecretNotFoundError, 404),
            (DigiCertOrderNotFoundError, 404),
            (VenafiCertificateNotFoundError, 404),
            # 408 Request Timeout
            (DigiCertPollingTimeoutError, 408),
            (VenafiPollingTimeoutError, 408),
            # 409 Conflict
            (DigiCertCertificateNotReadyError, 409),
            (LetsEncryptChallengeError, 409),
            # 429 Too Many Requests
            (DigiCertRateLimitError, 429),
            (LetsEncryptRateLimitError, 429),
            # 500 Internal Server Error
            (ConfigurationError, 500),
            (VaultWriteError, 500),
            # 502 Bad Gateway
            (DigiCertAPIError, 502),
            (VaultPKIError, 502),
            (ACMRequestError, 502),
            # 503 Service Unavailable
            (CircuitBreakerOpenError, 503),
        ],
    )
    def test_exception_to_status_code(self, exc_class, expected_code):
        if exc_class == DigiCertRateLimitError:
            exc = exc_class("rate limited", retry_after="60")
        elif exc_class == DigiCertAPIError:
            exc = exc_class("api error", status_code=500, body="error")
        else:
            exc = exc_class("test error")
        assert _resolve_status_code(exc) == expected_code


class TestBuildErrorBody:
    def test_basic_error_body(self):
        body = _build_error_body(404, "Not found", "req-123")
        assert body["error"] == "not_found"
        assert body["status"] == 404
        assert body["detail"] == "Not found"
        assert body["request_id"] == "req-123"

    def test_error_body_with_retry_after(self):
        body = _build_error_body(429, "Rate limited", "req-456", retry_after="60")
        assert body["error"] == "too_many_requests"
        assert body["retry_after_seconds"] == 60

    def test_error_body_custom_error_type(self):
        body = _build_error_body(502, "Upstream fail", "req-789", error_type="DigiCertAPIError")
        assert body["error"] == "DigiCertAPIError"

    def test_all_rfc_status_codes_have_types(self):
        """Ensure all mapped status codes have human-readable error types."""
        for code in [400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503]:
            assert code in _STATUS_ERROR_TYPES

    def test_unknown_status_code_fallback(self):
        body = _build_error_body(418, "I'm a teapot", "req-000")
        assert body["error"] == "error"  # fallback
