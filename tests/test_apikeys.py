"""Unit tests for API key exchange module."""

import time

import pytest
from fastapi import HTTPException

from certmesh.api.apikeys import (
    API_KEY_BYTE_LENGTH,
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    APIKeyConfig,
    APIKeyStore,
    _hash_key,
)


class TestAPIKeyConfig:
    def test_default_ttl(self):
        cfg = APIKeyConfig()
        assert cfg.effective_ttl(None) == DEFAULT_TTL_SECONDS

    def test_requested_ttl_within_range(self):
        cfg = APIKeyConfig(max_ttl_seconds=3600)
        assert cfg.effective_ttl(1800) == 1800

    def test_requested_ttl_clamped_to_max(self):
        cfg = APIKeyConfig(max_ttl_seconds=3600)
        assert cfg.effective_ttl(7200) == 3600

    def test_requested_ttl_clamped_to_minimum(self):
        cfg = APIKeyConfig()
        assert cfg.effective_ttl(10) == 60  # min 60 seconds

    def test_max_ttl_is_8_hours(self):
        assert MAX_TTL_SECONDS == 28_800


class TestAPIKeyStore:
    def test_issue_returns_key_and_expiry(self):
        store = APIKeyStore()
        claims = {"sub": "test-user", "scope": "certmesh:read"}
        raw_key, expires_at = store.issue(claims, 900)

        assert isinstance(raw_key, str)
        assert len(raw_key) > 0
        assert expires_at > time.time()

    def test_validate_valid_key(self):
        store = APIKeyStore()
        claims = {"sub": "test-user"}
        raw_key, _ = store.issue(claims, 900)

        validated_claims, remaining = store.validate(raw_key)
        assert validated_claims["sub"] == "test-user"
        assert remaining > 0

    def test_validate_invalid_key_raises_401(self):
        store = APIKeyStore()
        with pytest.raises(HTTPException) as exc_info:
            store.validate("invalid-key-12345")
        assert exc_info.value.status_code == 401

    def test_validate_expired_key_raises_401(self):
        store = APIKeyStore()
        claims = {"sub": "test-user"}
        raw_key, _ = store.issue(claims, 1)  # 1 second TTL

        # Manually expire the key
        key_hash = _hash_key(raw_key)
        store._keys[key_hash].expires_at = time.time() - 10

        with pytest.raises(HTTPException) as exc_info:
            store.validate(raw_key)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_revoke_existing_key(self):
        store = APIKeyStore()
        raw_key, _ = store.issue({"sub": "user1"}, 900)
        assert store.revoke(raw_key) is True
        assert store.active_count() == 0

    def test_revoke_nonexistent_key(self):
        store = APIKeyStore()
        assert store.revoke("nonexistent") is False

    def test_revoke_all_for_subject(self):
        store = APIKeyStore()
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user2"}, 900)

        count = store.revoke_all_for_subject("user1")
        assert count == 2
        assert store.active_count() == 1

    def test_max_keys_limit(self):
        store = APIKeyStore(_max_keys=3)
        store.issue({"sub": "u1"}, 900)
        store.issue({"sub": "u2"}, 900)
        store.issue({"sub": "u3"}, 900)

        with pytest.raises(HTTPException) as exc_info:
            store.issue({"sub": "u4"}, 900)
        assert exc_info.value.status_code == 503

    def test_eviction_of_expired_keys(self):
        store = APIKeyStore()
        raw_key, _ = store.issue({"sub": "user1"}, 1)

        # Manually expire
        key_hash = _hash_key(raw_key)
        store._keys[key_hash].expires_at = time.time() - 10

        # Issue a new key triggers eviction
        store.issue({"sub": "user2"}, 900)
        assert store.active_count() == 1

    def test_key_hash_is_consistent(self):
        assert _hash_key("test-key") == _hash_key("test-key")
        assert _hash_key("key-a") != _hash_key("key-b")

    def test_key_length(self):
        store = APIKeyStore()
        raw_key, _ = store.issue({"sub": "user"}, 900)
        # token_urlsafe(32) produces ~43 chars
        assert len(raw_key) >= API_KEY_BYTE_LENGTH

    def test_expired_key_header_signal(self):
        """Verify expired key response includes X-CertMesh-Key-Expired header."""
        store = APIKeyStore()
        raw_key, _ = store.issue({"sub": "user"}, 1)
        key_hash = _hash_key(raw_key)
        store._keys[key_hash].expires_at = time.time() - 1

        with pytest.raises(HTTPException) as exc_info:
            store.validate(raw_key)
        assert exc_info.value.headers is not None
        assert exc_info.value.headers.get("X-CertMesh-Key-Expired") == "true"
