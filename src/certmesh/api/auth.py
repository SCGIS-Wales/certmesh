"""
certmesh.api.auth
==================

OAuth2 Bearer token (JWT) validation with JWKS endpoint caching.
Configurable via ``CM_OAUTH2_*`` environment variables or Helm values.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

logger = logging.getLogger(__name__)


@dataclass
class OAuth2Config:
    """OAuth2 / OIDC configuration."""

    enabled: bool = False
    issuer_url: str = ""
    audience: str = ""
    jwks_uri: str = ""
    required_scopes: list[str] = field(default_factory=list)
    admin_scopes: list[str] = field(default_factory=list)
    write_scopes: list[str] = field(default_factory=list)

    def effective_jwks_uri(self) -> str:
        """Derive JWKS URI from issuer if not explicitly set."""
        if self.jwks_uri:
            return self.jwks_uri
        return f"{self.issuer_url.rstrip('/')}/.well-known/jwks.json"


# Module-level JWKS cache
_jwks_cache: dict[str, Any] = {}
_jwks_cache_time: float = 0.0
_JWKS_CACHE_TTL: float = 3600.0  # 1 hour
_MIN_REFRESH_INTERVAL: float = 60.0  # max 1 refresh per minute


def _fetch_jwks(jwks_uri: str, *, force: bool = False) -> dict[str, Any]:
    """Fetch and cache JWKS keys from the identity provider."""
    global _jwks_cache, _jwks_cache_time

    now = time.monotonic()
    if not force and _jwks_cache and (now - _jwks_cache_time) < _JWKS_CACHE_TTL:
        return _jwks_cache

    if force and (now - _jwks_cache_time) < _MIN_REFRESH_INTERVAL:
        logger.warning("JWKS refresh throttled (last refresh < 60s ago).")
        return _jwks_cache

    try:
        resp = httpx.get(jwks_uri, timeout=10.0)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_cache_time = now
        logger.info("JWKS fetched from %s (%d keys).", jwks_uri, len(_jwks_cache.get("keys", [])))
    except Exception:
        logger.exception("Failed to fetch JWKS from %s", jwks_uri)
        if not _jwks_cache:
            raise
    return _jwks_cache


def _validate_token(token: str, config: OAuth2Config) -> dict[str, Any]:
    """Validate a JWT Bearer token against JWKS and return claims."""
    jwks_uri = config.effective_jwks_uri()
    jwks = _fetch_jwks(jwks_uri)

    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token header: {exc}",
        ) from exc

    # Find the matching key
    kid = unverified_header.get("kid")
    rsa_key: dict[str, str] = {}
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key.get("use", "sig"),
                "n": key["n"],
                "e": key["e"],
            }
            break

    if not rsa_key:
        # Key rotation — try refreshing JWKS
        jwks = _fetch_jwks(jwks_uri, force=True)
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key.get("use", "sig"),
                    "n": key["n"],
                    "e": key["e"],
                }
                break

    if not rsa_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"No matching key found for kid={kid}",
        )

    try:
        claims = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=config.audience,
            issuer=config.issuer_url,
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from exc
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {exc}",
        ) from exc

    # Scope check
    token_scopes = set(claims.get("scope", "").split())
    required = set(config.required_scopes)
    if required and not required.intersection(token_scopes):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient scopes. Required: {sorted(required)}",
        )

    return claims


class JWTBearer(HTTPBearer):
    """FastAPI dependency for OAuth2 JWT Bearer token validation."""

    def __init__(self, config: OAuth2Config, **kwargs: Any) -> None:
        super().__init__(auto_error=True, **kwargs)
        self.config = config

    async def __call__(self, request: Request) -> dict[str, Any] | None:
        if not self.config.enabled:
            return None

        credentials: HTTPAuthorizationCredentials | None = await super().__call__(request)
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
            )
        claims = _validate_token(credentials.credentials, self.config)
        # Stash claims in request state for audit logging
        request.state.oauth2_claims = claims
        return claims
