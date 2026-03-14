"""Unit tests for API key exchange module."""

import time

import pytest
from fastapi import HTTPException

from certmesh.api.apikeys import (
    API_KEY_BYTE_LENGTH,
    DEFAULT_TTL_SECONDS,
    MAX_KEYS_PER_SUBJECT,
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

    def test_max_keys_per_subject_default(self):
        cfg = APIKeyConfig()
        assert cfg.max_keys_per_subject == MAX_KEYS_PER_SUBJECT


class TestAPIKeyStore:
    def test_issue_returns_key_and_expiry(self):
        store = APIKeyStore(_max_keys_per_subject=100)
        claims = {"sub": "test-user", "scope": "certmesh:read"}
        raw_key, expires_at = store.issue(claims, 900)

        assert isinstance(raw_key, str)
        assert len(raw_key) > 0
        assert expires_at > time.time()

    def test_validate_valid_key(self):
        store = APIKeyStore(_max_keys_per_subject=100)
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
        store = APIKeyStore(_max_keys_per_subject=100)
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
        store = APIKeyStore(_max_keys_per_subject=100)
        raw_key, _ = store.issue({"sub": "user1"}, 900)
        assert store.revoke(raw_key) is True
        assert store.active_count() == 0

    def test_revoke_nonexistent_key(self):
        store = APIKeyStore()
        assert store.revoke("nonexistent") is False

    def test_revoke_all_for_subject(self):
        store = APIKeyStore(_max_keys_per_subject=100)
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user2"}, 900)

        count = store.revoke_all_for_subject("user1")
        assert count == 2
        assert store.active_count() == 1

    def test_lru_eviction_at_capacity(self):
        """When at max_keys, oldest active key is evicted (not 503)."""
        store = APIKeyStore(_max_keys=3, _max_keys_per_subject=100)
        keys = []
        for i in range(3):
            raw_key, _ = store.issue({"sub": f"u{i}"}, 900)
            keys.append(raw_key)

        # 4th key should succeed — oldest evicted
        new_key, _ = store.issue({"sub": "u3"}, 900)
        assert store.active_count() == 3

        # First key evicted
        with pytest.raises(HTTPException):
            store.validate(keys[0])

        # New key valid
        _claims, _ = store.validate(new_key)

    def test_eviction_of_expired_keys(self):
        store = APIKeyStore(_max_keys_per_subject=100)
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

    def test_key_length_is_long(self):
        """API key should be at least 60 characters (384-bit random)."""
        store = APIKeyStore()
        raw_key, _ = store.issue({"sub": "user"}, 900)
        # token_urlsafe(48) produces ~64 chars
        assert len(raw_key) >= 60, f"Key too short: {len(raw_key)} chars"
        assert API_KEY_BYTE_LENGTH == 48

    def test_expired_key_header_signal(self):
        """Verify expired key response includes X-CertMesh-Key-Expired header."""
        store = APIKeyStore(_max_keys_per_subject=100)
        raw_key, _ = store.issue({"sub": "user"}, 1)
        key_hash = _hash_key(raw_key)
        store._keys[key_hash].expires_at = time.time() - 1

        with pytest.raises(HTTPException) as exc_info:
            store.validate(raw_key)
        assert exc_info.value.headers is not None
        assert exc_info.value.headers.get("X-CertMesh-Key-Expired") == "true"


class TestPerSubjectKeyLimit:
    def test_subject_limited_to_max_keys(self):
        """Oldest key for subject is evicted when limit exceeded."""
        store = APIKeyStore(_max_keys=100, _max_keys_per_subject=3)
        keys = []
        for _ in range(5):
            raw_key, _ = store.issue({"sub": "user1"}, 900)
            keys.append(raw_key)

        # Only last 3 should be valid
        assert store.subject_key_count("user1") == 3

        # First 2 evicted
        with pytest.raises(HTTPException):
            store.validate(keys[0])
        with pytest.raises(HTTPException):
            store.validate(keys[1])

        # Last 3 valid
        for k in keys[2:]:
            _claims, _ = store.validate(k)

    def test_different_subjects_independent(self):
        store = APIKeyStore(_max_keys=100, _max_keys_per_subject=2)
        store.issue({"sub": "alice"}, 900)
        store.issue({"sub": "alice"}, 900)
        store.issue({"sub": "bob"}, 900)
        store.issue({"sub": "bob"}, 900)

        assert store.subject_key_count("alice") == 2
        assert store.subject_key_count("bob") == 2
        assert store.active_count() == 4

    def test_subject_key_count(self):
        store = APIKeyStore(_max_keys=100, _max_keys_per_subject=10)
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user2"}, 900)

        assert store.subject_key_count("user1") == 2
        assert store.subject_key_count("user2") == 1
        assert store.subject_key_count("unknown") == 0

    def test_default_per_subject_limit(self):
        assert MAX_KEYS_PER_SUBJECT == 5
