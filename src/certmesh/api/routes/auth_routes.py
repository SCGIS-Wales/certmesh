"""
certmesh.api.routes.auth_routes
=================================

Authentication endpoints:
- POST /api/v1/auth/token     — exchange JWT for short-lived API key
- POST /api/v1/auth/token/refresh  — check key status, signal renewal
- POST /api/v1/auth/token/revoke   — revoke an API key
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from certmesh.api.apikeys import (
    APIKeyStore,
    validate_api_key_or_jwt,
)
from certmesh.api.auth import JWTBearer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# ── Request / Response models ────────────────────────────────────────────────


class TokenExchangeRequest(BaseModel):
    """Request body for JWT → API key exchange."""

    model_config = ConfigDict(strict=True, extra="forbid")

    ttl_seconds: int | None = Field(
        default=None,
        description="Desired key lifetime in seconds (default 900 = 15 min, max 28800 = 8h).",
    )


class TokenExchangeResponse(BaseModel):
    """Response containing the newly issued API key."""

    api_key: str
    expires_at: float
    expires_in_seconds: int
    token_type: str = "api_key"
    message: str = ""


class TokenStatusResponse(BaseModel):
    """Response for token status / refresh check."""

    valid: bool
    expires_at: float = 0.0
    remaining_seconds: int = 0
    refresh_required: bool = False
    message: str = ""


class TokenRevokeResponse(BaseModel):
    """Response for token revocation."""

    revoked: bool
    message: str = ""


# ── Dependency helpers ───────────────────────────────────────────────────────


async def _get_jwt_claims(request: Request) -> dict[str, Any] | None:
    """Resolve JWT claims by calling the JWTBearer dependency."""
    bearer: JWTBearer = request.app.state.jwt_bearer
    return await bearer(request)


def _get_store(request: Request) -> APIKeyStore:
    return request.app.state.api_key_store


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/token", response_model=TokenExchangeResponse)
async def exchange_token(
    request: Request,
    body: TokenExchangeRequest,
    claims: Any = Depends(_get_jwt_claims),
) -> TokenExchangeResponse:
    """Exchange a valid JWT Bearer token for a short-lived API key.

    The JWT must be valid (not expired, correct issuer/audience/scopes).
    The returned API key can be used via ``X-API-Key`` header for subsequent requests.
    """
    if claims is None:
        # OAuth2 is disabled — no exchange needed
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth2 is disabled. API key exchange requires OAuth2 to be enabled.",
        )

    store: APIKeyStore = _get_store(request)
    config = request.app.state.api_key_config

    ttl = config.effective_ttl(body.ttl_seconds)

    # Annotate claims with the key TTL for expiry signaling
    enriched_claims = {**claims, "_api_key_ttl": ttl}

    raw_key, expires_at = store.issue(enriched_claims, ttl)
    remaining = int(expires_at - time.time())

    subject = claims.get("sub", claims.get("client_id", "unknown"))
    logger.info(
        "API key exchanged via token endpoint",
        extra={"subject": subject, "ttl_seconds": ttl},
    )

    return TokenExchangeResponse(
        api_key=raw_key,
        expires_at=expires_at,
        expires_in_seconds=remaining,
        message=f"API key issued. Expires in {remaining}s. "
        "Use X-API-Key header for subsequent requests.",
    )


@router.post("/token/refresh", response_model=TokenStatusResponse)
async def refresh_token_status(
    request: Request,
    _claims: Any = Depends(validate_api_key_or_jwt),
) -> TokenStatusResponse:
    """Check API key status and signal when refresh is needed.

    If the key is approaching expiry, ``refresh_required`` is set to ``true``
    to prompt the client to exchange a new JWT for a fresh API key.
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-API-Key header required for token status check.",
        )

    store: APIKeyStore = _get_store(request)
    claims, remaining = store.validate(api_key)

    ttl_total = claims.get("_api_key_ttl", 900)
    threshold = ttl_total * 0.1  # 10% remaining
    refresh_required = remaining <= threshold

    message = "Token is valid."
    if refresh_required:
        message = (
            "API key is expiring soon. Please exchange a new JWT "
            "for a fresh API key via POST /api/v1/auth/token."
        )

    return TokenStatusResponse(
        valid=True,
        expires_at=time.time() + remaining,
        remaining_seconds=int(remaining),
        refresh_required=refresh_required,
        message=message,
    )


@router.post("/token/revoke", response_model=TokenRevokeResponse)
async def revoke_token(
    request: Request,
    _claims: Any = Depends(validate_api_key_or_jwt),
) -> TokenRevokeResponse:
    """Revoke the current API key (from the ``X-API-Key`` header)."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-API-Key header required for revocation.",
        )

    store: APIKeyStore = _get_store(request)
    revoked = store.revoke(api_key)

    if revoked:
        logger.info("API key revoked via token/revoke endpoint")
        return TokenRevokeResponse(revoked=True, message="API key has been revoked.")

    return TokenRevokeResponse(revoked=False, message="API key not found or already expired.")
