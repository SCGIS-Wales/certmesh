"""
certmesh.api.auth
==================

OAuth2 Bearer token (JWT) validation with JWKS endpoint caching.
Configurable via ``CM_OAUTH2_*`` environment variables or Helm values.

All authentication failures are logged as structured JSON with contextual
fields for security auditing and log aggregation.
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
    provider_hint: str = "generic"  # "generic", "adfs", "entra_id"

    def effective_jwks_uri(self) -> str:
        """Derive JWKS URI from issuer if not explicitly set."""
        if self.jwks_uri:
            return self.jwks_uri
        issuer = self.issuer_url.rstrip("/")
        if self.provider_hint == "adfs":
            # ADFS: https://adfs.corp.example.com/adfs/discovery/keys
            return f"{issuer}/discovery/keys"
        if self.provider_hint == "entra_id":
            # Azure Entra ID: https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys
            return f"{issuer}/discovery/v2.0/keys"
        # Generic OIDC
        return f"{issuer}/.well-known/jwks.json"


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
        logger.warning(
            "JWKS refresh throttled",
            extra={"min_interval_seconds": _MIN_REFRESH_INTERVAL},
        )
        return _jwks_cache

    try:
        resp = httpx.get(jwks_uri, timeout=10.0)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_cache_time = now
        logger.info(
            "JWKS fetched",
            extra={"jwks_uri": jwks_uri, "key_count": len(_jwks_cache.get("keys", []))},
        )
    except httpx.HTTPStatusError as exc:
        logger.error(
            "JWKS fetch failed",
            extra={"status_code": exc.response.status_code, "jwks_uri": jwks_uri},
        )
        if not _jwks_cache:
            raise
    except httpx.ConnectError:
        logger.error("JWKS fetch failed: connection refused", extra={"jwks_uri": jwks_uri})
        if not _jwks_cache:
            raise
    except Exception:
        logger.exception("JWKS fetch failed", extra={"jwks_uri": jwks_uri})
        if not _jwks_cache:
            raise
    return _jwks_cache


def _extract_jwk(jwks: dict[str, Any], kid: str | None) -> dict[str, str]:
    """Find a JWK matching the given ``kid`` from a JWKS key set."""
    for key in jwks.get("keys", []):
        if key.get("kid") != kid:
            continue
        result: dict[str, str] = {
            "kty": key["kty"],
            "kid": key["kid"],
            "use": key.get("use", "sig"),
        }
        if "n" in key and "e" in key:
            result["n"] = key["n"]
            result["e"] = key["e"]
        if "x5c" in key:
            result["x5c"] = key["x5c"]
        return result
    return {}


def _decode_jwt(token: str, rsa_key: dict[str, str], config: OAuth2Config) -> dict[str, Any]:
    """Decode and verify a JWT, raising HTTPException on failure."""
    try:
        return jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=config.audience,
            issuer=config.issuer_url,
        )
    except jwt.ExpiredSignatureError as exc:
        logger.warning(
            "JWT validation failed: token expired",
            extra={"issuer": config.issuer_url, "audience": config.audience},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please obtain a new JWT and retry.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc
    except JWTError as exc:
        logger.warning(
            "JWT validation failed",
            extra={
                "error": str(exc),
                "issuer": config.issuer_url,
                "audience": config.audience,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {exc}",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc


def _extract_scopes(claims: dict[str, Any]) -> set[str]:
    """Extract scopes from JWT claims (supports OIDC ``scope`` and ADFS ``scp``)."""
    raw = claims.get("scope") or claims.get("scp", "")
    if isinstance(raw, list):
        return set(raw)
    return set(raw.split())


def _validate_token(token: str, config: OAuth2Config) -> dict[str, Any]:
    """Validate a JWT Bearer token against JWKS and return claims."""
    jwks_uri = config.effective_jwks_uri()
    jwks = _fetch_jwks(jwks_uri)

    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as exc:
        logger.warning(
            "JWT header parse failed",
            extra={"error": str(exc), "jwks_uri": jwks_uri},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token header: {exc}",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc

    kid = unverified_header.get("kid")
    rsa_key = _extract_jwk(jwks, kid)

    if not rsa_key:
        # Key rotation — try refreshing JWKS
        logger.info("JWKS key not in cache, refreshing", extra={"kid": kid})
        jwks = _fetch_jwks(jwks_uri, force=True)
        rsa_key = _extract_jwk(jwks, kid)

    if not rsa_key:
        logger.warning(
            "JWT validation failed: no matching key",
            extra={
                "kid": kid,
                "jwks_uri": jwks_uri,
                "available_keys": len(jwks.get("keys", [])),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"No matching key found for kid={kid}",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    claims = _decode_jwt(token, rsa_key, config)

    # Scope check
    required = set(config.required_scopes)
    token_scopes = _extract_scopes(claims)
    if required and not required.intersection(token_scopes):
        subject = claims.get("sub", claims.get("client_id", "unknown"))
        logger.warning(
            "Insufficient scopes",
            extra={
                "subject": subject,
                "token_scopes": sorted(token_scopes),
                "required_scopes": sorted(required),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient scopes. Required: {sorted(required)}. "
            f"Token has: {sorted(token_scopes)}.",
            headers={
                "WWW-Authenticate": f'Bearer error="insufficient_scope", '
                f'scope="{" ".join(sorted(required))}"'
            },
        )

    subject = claims.get("sub", claims.get("client_id", "unknown"))
    logger.info(
        "JWT validated",
        extra={
            "subject": subject,
            "scopes": sorted(token_scopes),
            "issuer": claims.get("iss", ""),
        },
    )
    return claims


class JWTBearer(HTTPBearer):
    """FastAPI dependency for OAuth2 JWT Bearer token validation."""

    def __init__(self, config: OAuth2Config, **kwargs: Any) -> None:
        super().__init__(auto_error=True, **kwargs)
        self.config = config

    async def __call__(self, request: Request) -> dict[str, Any] | None:
        if not self.config.enabled:
            logger.debug(
                "OAuth2 disabled, skipping JWT validation",
                extra={"path": request.url.path},
            )
            return None

        credentials: HTTPAuthorizationCredentials | None = await super().__call__(request)
        if credentials is None:
            client_host = request.client.host if request.client else "unknown"
            logger.warning(
                "Missing authorization header",
                extra={"path": request.url.path, "client": client_host},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header. Provide Bearer token or X-API-Key.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        claims = _validate_token(credentials.credentials, self.config)
        # Stash claims in request state for audit logging
        request.state.oauth2_claims = claims
        request.state.auth_method = "jwt"
        return claims
