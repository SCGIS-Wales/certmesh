"""Unit tests for rate limiting middleware."""

from certmesh.api.rate_limiter import (
    DEFAULT_BURST_LIMIT,
    DEFAULT_RATE_LIMIT,
    RateLimitConfig,
    build_rate_limit_config,
    create_limiter,
)


class TestRateLimitConfig:
    def test_default_values(self):
        cfg = RateLimitConfig()
        assert cfg.enabled is True
        assert cfg.default_limit == DEFAULT_RATE_LIMIT
        assert cfg.burst_limit == DEFAULT_BURST_LIMIT

    def test_default_limit_is_high(self):
        """Default limits should be high to avoid impacting normal use."""
        assert "1000" in DEFAULT_RATE_LIMIT
        assert "minute" in DEFAULT_RATE_LIMIT

    def test_exempt_paths_include_health(self):
        cfg = RateLimitConfig()
        assert "/healthz" in cfg.exempt_paths
        assert "/livez" in cfg.exempt_paths
        assert "/readyz" in cfg.exempt_paths
        assert "/metrics" in cfg.exempt_paths

    def test_disabled_config(self):
        cfg = RateLimitConfig(enabled=False)
        limiter = create_limiter(cfg)
        assert limiter.enabled is False


class TestBuildRateLimitConfig:
    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.delenv("CM_RATE_LIMIT_ENABLED", raising=False)
        monkeypatch.delenv("CM_RATE_LIMIT_DEFAULT", raising=False)
        monkeypatch.delenv("CM_RATE_LIMIT_BURST", raising=False)
        cfg = build_rate_limit_config()
        assert cfg.enabled is True
        assert cfg.default_limit == DEFAULT_RATE_LIMIT

    def test_from_env_custom(self, monkeypatch):
        monkeypatch.setenv("CM_RATE_LIMIT_ENABLED", "false")
        monkeypatch.setenv("CM_RATE_LIMIT_DEFAULT", "500/minute")
        monkeypatch.setenv("CM_RATE_LIMIT_BURST", "50/second")
        cfg = build_rate_limit_config()
        assert cfg.enabled is False
        assert cfg.default_limit == "500/minute"
        assert cfg.burst_limit == "50/second"


class TestCreateLimiter:
    def test_limiter_created_enabled(self):
        cfg = RateLimitConfig(enabled=True)
        limiter = create_limiter(cfg)
        assert limiter is not None
        assert limiter.enabled is True

    def test_limiter_created_disabled(self):
        cfg = RateLimitConfig(enabled=False)
        limiter = create_limiter(cfg)
        assert limiter.enabled is False
