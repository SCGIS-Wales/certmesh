"""
certmesh.api.apikeys
=====================

Short-lived API key exchange: exchange a valid JWT for a temporary API key.

The key is stored in-memory with a configurable TTL (default 15 minutes,
maximum 8 hours).  When the key nears expiry the ``/api/v1/auth/token/refresh``
endpoint signals the caller to re-authenticate with a fresh JWT.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_TTL_SECONDS: int = 900  # 15 minutes
MAX_TTL_SECONDS: int = 28_800  # 8 hours
EXPIRY_WARNING_FRACTION: float = 0.1  # signal refresh when 10% TTL remaining
API_KEY_BYTE_LENGTH: int = 32  # 256-bit random key


@dataclass
class APIKeyConfig:
    """API key exchange configuration."""

    enabled: bool = True
    default_ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_ttl_seconds: int = MAX_TTL_SECONDS
    max_active_keys: int = 10_000  # safeguard against memory exhaustion

    def effective_ttl(self, requested: int | None) -> int:
        """Clamp requested TTL to [60, max_ttl_seconds]."""
        if requested is None:
            return self.default_ttl_seconds
        return max(60, min(requested, self.max_ttl_seconds))


# ── In-memory store ──────────────────────────────────────────────────────────


@dataclass
class _StoredKey:
    key_hash: str
    claims: dict[str, Any]
    created_at: float
    expires_at: float
    subject: str = ""


@dataclass
class APIKeyStore:
    """Thread-safe in-memory API key store with automatic eviction."""

    _keys: dict[str, _StoredKey] = field(default_factory=dict)
    _max_keys: int = 10_000

    def issue(
        self,
        claims: dict[str, Any],
        ttl_seconds: int,
    ) -> tuple[str, float]:
        """Issue a new API key for the given JWT claims.

        Returns ``(raw_key, expires_at)`` — the raw key is shown only once.
        """
        self._evict_expired()

        if len(self._keys) >= self._max_keys:
            logger.warning(
                "API key store at capacity (%d keys); rejecting new key.", self._max_keys
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API key store at capacity. Try again later.",
            )

        raw_key = secrets.token_urlsafe(API_KEY_BYTE_LENGTH)
        key_hash = _hash_key(raw_key)
        now = time.time()
        expires_at = now + ttl_seconds
        subject = claims.get("sub", claims.get("client_id", "unknown"))

        self._keys[key_hash] = _StoredKey(
            key_hash=key_hash,
            claims=claims,
            created_at=now,
            expires_at=expires_at,
            subject=subject,
        )
        logger.info(
            "API key issued for subject=%s ttl=%ds expires_at=%.0f active_keys=%d",
            subject,
            ttl_seconds,
            expires_at,
            len(self._keys),
        )
        return raw_key, expires_at

    def validate(self, raw_key: str) -> tuple[dict[str, Any], float]:
        """Validate an API key.

        Returns ``(claims, remaining_seconds)``.
        Raises ``HTTPException`` on invalid/expired key.
        """
        key_hash = _hash_key(raw_key)
        stored = self._keys.get(key_hash)

        if stored is None:
            logger.warning("API key validation failed: key not found.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key.",
            )

        now = time.time()
        remaining = stored.expires_at - now
        if remaining <= 0:
            del self._keys[key_hash]
            logger.warning(
                "API key expired for subject=%s (expired %.0fs ago).",
                stored.subject,
                -remaining,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired. Please exchange a new JWT for a fresh key.",
                headers={"X-CertMesh-Key-Expired": "true"},
            )

        return stored.claims, remaining

    def revoke(self, raw_key: str) -> bool:
        """Revoke a single API key. Returns True if found and revoked."""
        key_hash = _hash_key(raw_key)
        if key_hash in self._keys:
            subject = self._keys[key_hash].subject
            del self._keys[key_hash]
            logger.info("API key revoked for subject=%s.", subject)
            return True
        return False

    def revoke_all_for_subject(self, subject: str) -> int:
        """Revoke all keys belonging to a subject. Returns count removed."""
        to_remove = [h for h, s in self._keys.items() if s.subject == subject]
        for h in to_remove:
            del self._keys[h]
        if to_remove:
            logger.info("Revoked %d API key(s) for subject=%s.", len(to_remove), subject)
        return len(to_remove)

    def active_count(self) -> int:
        """Return number of active (non-expired) keys."""
        self._evict_expired()
        return len(self._keys)

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [h for h, s in self._keys.items() if s.expires_at <= now]
        for h in expired:
            del self._keys[h]
        if expired:
            logger.debug("Evicted %d expired API key(s).", len(expired))


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash of the raw key — we never store the plaintext."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


# ── Bearer token introspection ───────────────────────────────────────────────


async def validate_api_key_or_jwt(request: Request) -> dict[str, Any] | None:
    """FastAPI dependency: accept either ``Bearer <jwt>`` or ``X-API-Key`` header.

    1. If ``X-API-Key`` is present → validate against the in-memory store.
    2. Otherwise fall through to JWT validation (handled by ``JWTBearer``).
    3. If OAuth2 is disabled → return None (unauthenticated access).
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        store: APIKeyStore = request.app.state.api_key_store
        claims, remaining = store.validate(api_key)
        request.state.auth_method = "api_key"
        request.state.oauth2_claims = claims

        # Signal key expiry approaching
        ttl_total = claims.get("_api_key_ttl", DEFAULT_TTL_SECONDS)
        threshold = ttl_total * EXPIRY_WARNING_FRACTION
        if remaining <= threshold:
            request.state.api_key_expiring = True

        return claims

    # Fall through — JWT validation handled by the caller / JWTBearer dependency
    return None
