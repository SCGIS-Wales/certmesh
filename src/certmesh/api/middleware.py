"""
certmesh.api.middleware
========================

Request logging, correlation ID, security headers, RFC 7807 error handling,
and API key expiry signaling.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from certmesh.api.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS_TOTAL
from certmesh.exceptions import (
    ACMError,
    ACMExportError,
    ACMPrivateCAError,
    ACMRequestError,
    ACMValidationError,
    CertificateError,
    CertMeshError,
    CircuitBreakerOpenError,
    ConfigurationError,
    DigiCertAPIError,
    DigiCertAuthenticationError,
    DigiCertCertificateNotReadyError,
    DigiCertDownloadError,
    DigiCertError,
    DigiCertOrderNotFoundError,
    DigiCertPollingTimeoutError,
    DigiCertRateLimitError,
    LetsEncryptChallengeError,
    LetsEncryptError,
    LetsEncryptOrderError,
    LetsEncryptRateLimitError,
    LetsEncryptRegistrationError,
    SecretsManagerError,
    VaultAuthenticationError,
    VaultAWSIAMError,
    VaultError,
    VaultPKIError,
    VaultSecretNotFoundError,
    VaultWriteError,
    VenafiAPIError,
    VenafiAuthenticationError,
    VenafiCertificateNotFoundError,
    VenafiError,
    VenafiLDAPAuthError,
    VenafiPollingTimeoutError,
    VenafiPrivateKeyExportError,
    VenafiWorkflowApprovalError,
)

logger = logging.getLogger(__name__)

# ── RFC HTTP Status Code Mapping ─────────────────────────────────────────────
# Maps exception types to correct RFC 7231 / 9110 HTTP status codes.
# More specific exception types take precedence over base types.
_ERROR_STATUS_MAP: dict[type, int] = {
    # --- 400 Bad Request: client-side input errors ---
    CertificateError: 400,
    ACMValidationError: 400,
    # --- 401 Unauthorized: authentication failures ---
    VaultAuthenticationError: 401,
    VaultAWSIAMError: 401,
    DigiCertAuthenticationError: 401,
    VenafiAuthenticationError: 401,
    VenafiLDAPAuthError: 401,
    LetsEncryptRegistrationError: 401,
    # --- 403 Forbidden: authorization failures ---
    VenafiPrivateKeyExportError: 403,
    VenafiWorkflowApprovalError: 403,
    # --- 404 Not Found ---
    VaultSecretNotFoundError: 404,
    DigiCertOrderNotFoundError: 404,
    VenafiCertificateNotFoundError: 404,
    # --- 408 Request Timeout: polling timeouts ---
    DigiCertPollingTimeoutError: 408,
    VenafiPollingTimeoutError: 408,
    # --- 409 Conflict: resource state conflicts ---
    DigiCertCertificateNotReadyError: 409,
    LetsEncryptChallengeError: 409,
    # --- 422 Unprocessable Entity: semantic errors in valid input ---
    DigiCertDownloadError: 422,
    ACMExportError: 422,
    # --- 429 Too Many Requests ---
    DigiCertRateLimitError: 429,
    LetsEncryptRateLimitError: 429,
    # --- 500 Internal Server Error: server-side failures ---
    ConfigurationError: 500,
    VaultWriteError: 500,
    SecretsManagerError: 500,
    # --- 502 Bad Gateway: upstream provider failures ---
    DigiCertAPIError: 502,
    VenafiAPIError: 502,
    VaultPKIError: 502,
    ACMRequestError: 502,
    ACMPrivateCAError: 502,
    LetsEncryptOrderError: 502,
    # --- 503 Service Unavailable: circuit breaker / temporary ---
    CircuitBreakerOpenError: 503,
    # --- Fallback base types ---
    VaultError: 502,
    DigiCertError: 502,
    VenafiError: 502,
    ACMError: 502,
    LetsEncryptError: 502,
}

# Map HTTP status codes to RFC error type strings
_STATUS_ERROR_TYPES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    408: "request_timeout",
    409: "conflict",
    422: "unprocessable_entity",
    429: "too_many_requests",
    500: "internal_server_error",
    502: "bad_gateway",
    503: "service_unavailable",
}

# Security headers applied to every response
_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def _resolve_status_code(exc: CertMeshError) -> int:
    """Resolve HTTP status code for an exception.

    Checks the exception type and all parent types in MRO order,
    giving the most specific match.
    """
    for cls in type(exc).__mro__:
        if cls in _ERROR_STATUS_MAP:
            return _ERROR_STATUS_MAP[cls]
    return 500


def _build_error_body(
    status_code: int,
    detail: str,
    request_id: str,
    *,
    error_type: str | None = None,
    retry_after: str | None = None,
) -> dict:
    """Build an RFC 7807-inspired JSON error response body.

    All error responses include:
    - ``error``: machine-readable error type
    - ``status``: HTTP status code (integer)
    - ``detail``: human-readable description
    - ``request_id``: correlation ID for tracing
    """
    body: dict = {
        "error": error_type or _STATUS_ERROR_TYPES.get(status_code, "error"),
        "status": status_code,
        "detail": detail,
        "request_id": request_id,
    }
    if retry_after:
        body["retry_after_seconds"] = int(retry_after)
    return body


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject/propagate X-Request-ID, log requests, record metrics, signal API key expiry."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Generate or propagate request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        start = time.monotonic()
        response: Response | None = None
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "Unhandled exception",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                },
            )
            response = JSONResponse(
                status_code=500,
                content=_build_error_body(500, "Internal server error", request_id),
            )
        finally:
            elapsed = time.monotonic() - start
            status_code = response.status_code if response else 500

            # Metrics
            endpoint = request.url.path
            HTTP_REQUESTS_TOTAL.labels(
                method=request.method,
                endpoint=endpoint,
                status=str(status_code),
            ).inc()
            HTTP_REQUEST_DURATION.labels(endpoint=endpoint).observe(elapsed)

            # Response headers
            if response is not None:
                response.headers["X-Request-ID"] = request_id
                for header, value in _SECURITY_HEADERS.items():
                    response.headers[header] = value

                # Signal API key expiry approaching
                if getattr(request.state, "api_key_expiring", False):
                    response.headers["X-CertMesh-Key-Expiring"] = "true"
                    response.headers["X-CertMesh-Refresh-URL"] = "/api/v1/auth/token"

            logger.info(
                "HTTP request completed",
                extra={
                    "method": request.method,
                    "path": endpoint,
                    "status": status_code,
                    "duration_seconds": round(elapsed, 4),
                    "request_id": request_id,
                },
            )

        return response  # type: ignore[return-value]


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers with RFC 7807 JSON error bodies."""

    @app.exception_handler(CertMeshError)
    async def certmesh_error_handler(request: Request, exc: CertMeshError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        status_code = _resolve_status_code(exc)

        # Authentication errors get special logging for auditing
        if status_code == 401:
            logger.warning(
                "Authentication failure",
                extra={
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "path": request.url.path,
                    "request_id": request_id,
                },
            )
        elif status_code == 403:
            logger.warning(
                "Authorization failure",
                extra={
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "path": request.url.path,
                    "request_id": request_id,
                },
            )
        else:
            logger.error(
                "CertMeshError",
                extra={
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "status": status_code,
                    "request_id": request_id,
                },
            )

        headers: dict[str, str] = {}
        retry_after = None

        # Add Retry-After header for rate limit errors
        if isinstance(exc, DigiCertRateLimitError) and exc.retry_after:
            retry_after = exc.retry_after
            headers["Retry-After"] = retry_after

        body = _build_error_body(
            status_code,
            str(exc),
            request_id,
            error_type=type(exc).__name__,
            retry_after=retry_after,
        )

        return JSONResponse(status_code=status_code, content=body, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle Pydantic/FastAPI validation errors with RFC-compliant JSON."""
        request_id = getattr(request.state, "request_id", "unknown")
        errors = exc.errors()
        detail = "; ".join(
            f"{'.'.join(str(loc) for loc in e.get('loc', []))}: {e.get('msg', '')}" for e in errors
        )
        logger.warning(
            "Request validation error",
            extra={
                "detail": detail,
                "path": request.url.path,
                "request_id": request_id,
            },
        )
        body = _build_error_body(
            422,
            detail,
            request_id,
            error_type="validation_error",
        )
        body["validation_errors"] = errors
        return JSONResponse(status_code=422, content=body)

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception("Unhandled error", extra={"request_id": request_id})
        return JSONResponse(
            status_code=500,
            content=_build_error_body(500, "Internal server error", request_id),
        )
