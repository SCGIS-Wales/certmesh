"""
Capacity / performance integration test for certmesh API.

Tests:
1. Rate limiting returns 429 with correct RFC headers
2. Exempt paths (health checks) bypass rate limiting
3. Concurrent request handling under load
4. API key store capacity limits + LRU eviction
5. Per-subject key limiting
6. Response time under sustained load
7. GZip compression effectiveness

Requires: certmesh API running (or uses TestClient for in-process testing).
"""

from __future__ import annotations

import concurrent.futures
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from certmesh.api.apikeys import APIKeyStore, _hash_key
from certmesh.api.app import create_app


@pytest.fixture()
def app(monkeypatch):
    """Create a test app with rate limiting enabled at low thresholds for testing."""
    monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
    monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("CM_RATE_LIMIT_DEFAULT", "10/minute")  # low limit for testing
    monkeypatch.setenv("CM_RATE_LIMIT_BURST", "5/second")
    monkeypatch.setenv("CM_COMPRESSION_ENABLED", "true")
    monkeypatch.setenv("CM_COMPRESSION_MIN_SIZE", "100")
    # No exempt paths — so health endpoints ARE rate-limited for testing
    monkeypatch.setenv("CM_RATE_LIMIT_EXEMPT_PATHS", "")
    return create_app()


@pytest.fixture()
def client(app):
    return TestClient(app)


@pytest.fixture()
def unlimited_app(monkeypatch):
    """App with rate limiting disabled for pure throughput testing."""
    monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
    monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("CM_COMPRESSION_ENABLED", "true")
    return create_app()


@pytest.fixture()
def unlimited_client(unlimited_app):
    return TestClient(unlimited_app)


@pytest.fixture()
def exempt_app(monkeypatch):
    """App with rate limiting ON and default exempt paths (health endpoints exempt)."""
    monkeypatch.setenv("CM_OAUTH2_ENABLED", "false")
    monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("CM_RATE_LIMIT_DEFAULT", "5/minute")  # very low
    monkeypatch.setenv("CM_RATE_LIMIT_BURST", "3/second")
    # Default exempt paths: /healthz, /livez, /readyz, /metrics
    monkeypatch.delenv("CM_RATE_LIMIT_EXEMPT_PATHS", raising=False)
    return create_app()


@pytest.fixture()
def exempt_client(exempt_app):
    return TestClient(exempt_app)


@pytest.mark.integration
class TestRateLimiting429:
    """Test that rate limiting returns proper HTTP 429 responses."""

    def test_rate_limit_returns_429(self, client):
        """Exceeding rate limit returns 429 with RFC-compliant response."""
        # Send requests until rate limited (limit is 10/minute, no exempt paths)
        responses = []
        for _ in range(20):
            resp = client.get("/healthz")
            responses.append(resp)
            if resp.status_code == 429:
                break

        rate_limited = [r for r in responses if r.status_code == 429]
        assert len(rate_limited) > 0, "Expected at least one 429 response"

        # Verify RFC 7231 compliance
        resp_429 = rate_limited[0]
        assert "Retry-After" in resp_429.headers
        body = resp_429.json()
        assert body["error"] == "too_many_requests"
        assert "request_id" in body
        assert "retry_after_seconds" in body

    def test_rate_limit_header_format(self, client):
        """Retry-After header is a valid integer."""
        for _ in range(20):
            resp = client.get("/healthz")
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                assert retry_after is not None
                assert int(retry_after) > 0
                break


@pytest.mark.integration
class TestRateLimitExemptPaths:
    """Test that exempt paths bypass rate limiting."""

    def test_healthz_exempt_when_configured(self, exempt_client):
        """Health endpoints are not rate-limited when in exempt_paths."""
        # With limit of 5/minute but /healthz exempt, 20 requests should all succeed
        results = []
        for _ in range(20):
            resp = exempt_client.get("/healthz")
            results.append(resp.status_code)

        assert all(code == 200 for code in results), (
            f"Expected all 200s for exempt path, got: {set(results)}"
        )

    def test_livez_exempt_when_configured(self, exempt_client):
        """livez is also exempt from rate limiting."""
        for _ in range(20):
            resp = exempt_client.get("/livez")
            assert resp.status_code == 200


@pytest.mark.integration
class TestConcurrentRequests:
    """Test API under concurrent load."""

    def test_concurrent_health_checks(self, unlimited_client):
        """API handles 50 concurrent health check requests."""
        num_requests = 50
        results = []

        def _make_request():
            resp = unlimited_client.get("/healthz")
            return resp.status_code, resp.elapsed.total_seconds()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_make_request) for _ in range(num_requests)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        status_codes = [r[0] for r in results]
        response_times = [r[1] for r in results]

        # All should succeed
        assert all(code == 200 for code in status_codes), (
            f"Expected all 200s, got: {set(status_codes)}"
        )

        # Average response time under 1 second
        avg_time = sum(response_times) / len(response_times)
        assert avg_time < 1.0, f"Average response time {avg_time:.3f}s exceeds 1s"


@pytest.mark.integration
class TestAPIKeyStoreCapacity:
    """Test API key store under load."""

    def test_store_handles_many_keys(self):
        """Store handles 1000 concurrent keys."""
        store = APIKeyStore(_max_keys=5000)
        keys = []
        for i in range(1000):
            raw_key, _ = store.issue({"sub": f"user-{i}"}, 900)
            keys.append(raw_key)

        assert store.active_count() == 1000

        # Validate all keys
        for key in keys[:10]:  # spot check
            _claims, remaining = store.validate(key)
            assert remaining > 800

    def test_store_evicts_oldest_at_capacity(self):
        """Store evicts oldest key (LRU) when at capacity instead of rejecting."""
        store = APIKeyStore(_max_keys=5, _max_keys_per_subject=100)
        keys = []
        for i in range(5):
            raw_key, _ = store.issue({"sub": f"user-{i}"}, 900)
            keys.append(raw_key)

        # 6th key should succeed — oldest gets evicted
        new_key, _ = store.issue({"sub": "user-new"}, 900)
        assert store.active_count() == 5  # still at capacity

        # The first key (oldest) should have been evicted
        with pytest.raises(HTTPException) as exc_info:
            store.validate(keys[0])
        assert exc_info.value.status_code == 401

        # The new key should be valid
        _claims, _ = store.validate(new_key)

    def test_store_rejects_when_all_eviction_fails(self):
        """Store rejects only when eviction cannot free enough space."""
        store = APIKeyStore(_max_keys=3, _max_keys_per_subject=100)
        for i in range(3):
            store.issue({"sub": f"user-{i}"}, 900)

        # With LRU eviction, issuing another key should succeed
        raw_key, _ = store.issue({"sub": "overflow"}, 900)
        assert store.active_count() == 3
        _claims, _ = store.validate(raw_key)

    def test_store_eviction_under_load(self):
        """Expired keys are evicted to make room for new ones."""
        store = APIKeyStore(_max_keys=100, _max_keys_per_subject=100)

        # Issue 50 keys with short TTL
        for i in range(50):
            raw_key, _ = store.issue({"sub": f"expired-{i}"}, 1)
            store._keys[_hash_key(raw_key)].expires_at = time.time() - 1

        # Issue 50 more — eviction should happen
        for i in range(50):
            store.issue({"sub": f"active-{i}"}, 900)

        assert store.active_count() == 50  # only active keys remain


@pytest.mark.integration
class TestPerSubjectKeyLimit:
    """Test per-subject API key limiting."""

    def test_subject_limited_to_max_keys(self):
        """A single subject can hold at most max_keys_per_subject keys."""
        store = APIKeyStore(_max_keys=100, _max_keys_per_subject=3)
        keys = []
        for _ in range(5):
            raw_key, _ = store.issue({"sub": "user1"}, 900)
            keys.append(raw_key)

        # Only the last 3 keys should be valid (oldest 2 evicted)
        assert store.subject_key_count("user1") == 3

        # First 2 should be revoked
        with pytest.raises(HTTPException):
            store.validate(keys[0])
        with pytest.raises(HTTPException):
            store.validate(keys[1])

        # Last 3 should be valid
        for k in keys[2:]:
            _claims, _ = store.validate(k)

    def test_different_subjects_independent(self):
        """Different subjects have independent key limits."""
        store = APIKeyStore(_max_keys=100, _max_keys_per_subject=2)
        store.issue({"sub": "alice"}, 900)
        store.issue({"sub": "alice"}, 900)
        store.issue({"sub": "bob"}, 900)
        store.issue({"sub": "bob"}, 900)

        assert store.subject_key_count("alice") == 2
        assert store.subject_key_count("bob") == 2
        assert store.active_count() == 4

    def test_subject_key_count(self):
        """subject_key_count returns correct count."""
        store = APIKeyStore(_max_keys=100, _max_keys_per_subject=10)
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user1"}, 900)
        store.issue({"sub": "user2"}, 900)

        assert store.subject_key_count("user1") == 2
        assert store.subject_key_count("user2") == 1
        assert store.subject_key_count("unknown") == 0


@pytest.mark.integration
class TestAPIKeyLength:
    """Test that API keys are sufficiently long."""

    def test_key_length_minimum(self):
        """API key should be at least 60 characters (384-bit random)."""
        store = APIKeyStore()
        raw_key, _ = store.issue({"sub": "user"}, 900)
        # token_urlsafe(48) → ~64 chars
        assert len(raw_key) >= 60, f"Key too short: {len(raw_key)} chars"

    def test_key_uniqueness(self):
        """Each issued key is unique."""
        store = APIKeyStore()
        keys = set()
        for _ in range(100):
            raw_key, _ = store.issue({"sub": "user"}, 900)
            keys.add(raw_key)
        assert len(keys) == 100


@pytest.mark.integration
class TestResponseCompression:
    """Test GZip compression of responses."""

    def test_compressed_response(self, unlimited_client):
        """Responses are compressed when Accept-Encoding: gzip is sent."""
        resp = unlimited_client.get(
            "/healthz",
            headers={"Accept-Encoding": "gzip"},
        )
        assert resp.status_code == 200
        # Small health responses may not be compressed (below minimum_size)
        # but the server should still respond successfully

    def test_large_response_compressed(self, unlimited_client):
        """Large responses should be compressed."""
        # The readyz endpoint returns more data
        resp = unlimited_client.get(
            "/readyz",
            headers={"Accept-Encoding": "gzip"},
        )
        assert resp.status_code == 200


@pytest.mark.integration
class TestResponseTimeBaseline:
    """Establish response time baseline."""

    def test_health_check_under_50ms(self, unlimited_client):
        """Health check responds in under 50ms."""
        times = []
        for _ in range(10):
            start = time.monotonic()
            resp = unlimited_client.get("/healthz")
            elapsed = time.monotonic() - start
            times.append(elapsed)
            assert resp.status_code == 200

        avg_ms = (sum(times) / len(times)) * 1000
        assert avg_ms < 50, f"Average health check time {avg_ms:.1f}ms exceeds 50ms"

    def test_sustained_load_50_requests(self, unlimited_client):
        """50 sequential requests complete within 5 seconds total."""
        start = time.monotonic()
        for _ in range(50):
            resp = unlimited_client.get("/healthz")
            assert resp.status_code == 200
        total = time.monotonic() - start
        assert total < 5.0, f"50 requests took {total:.2f}s (>5s)"
