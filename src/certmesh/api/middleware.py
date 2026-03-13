"""
certmesh.api.middleware
========================

Request logging, correlation ID, security headers, and error handling.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from certmesh.api.metrics import HTTP_REQUEST_DURATION, HTTP_REQUESTS_TOTAL
from certmesh.exceptions import (
    CertMeshError,
    ConfigurationError,
    DigiCertAuthenticationError,
    DigiCertRateLimitError,
    VaultAuthenticationError,
    VaultSecretNotFoundError,
)

logger = logging.getLogger(__name__)

# Map exception types to HTTP status codes
_ERROR_STATUS_MAP: dict[type, int] = {
    ConfigurationError: 500,
    VaultAuthenticationError: 502,
    VaultSecretNotFoundError: 404,
    DigiCertAuthenticationError: 502,
    DigiCertRateLimitError: 429,
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


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject/propagate X-Request-ID, log requests, record metrics."""

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
                "Unhandled exception | request_id=%s method=%s path=%s",
                request_id,
                request.method,
                request.url.path,
            )
            response = JSONResponse(
                status_code=500,
                content={"detail": "Internal server error", "request_id": request_id},
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

            logger.info(
                "%s %s -> %d (%.3fs) request_id=%s",
                request.method,
                endpoint,
                status_code,
                elapsed,
                request_id,
            )

        return response  # type: ignore[return-value]


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers that map CertMeshError to HTTP responses."""

    @app.exception_handler(CertMeshError)
    async def certmesh_error_handler(request: Request, exc: CertMeshError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        status_code = _ERROR_STATUS_MAP.get(type(exc), 500)
        logger.error(
            "CertMeshError: %s | status=%d request_id=%s",
            exc,
            status_code,
            request_id,
        )
        return JSONResponse(
            status_code=status_code,
            content={"detail": str(exc), "request_id": request_id},
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception("Unhandled error | request_id=%s", request_id)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )
