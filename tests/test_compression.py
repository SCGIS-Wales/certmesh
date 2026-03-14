"""Unit tests for compression middleware."""

from certmesh.api.compression import (
    DEFAULT_MIN_SIZE,
    CompressionConfig,
    build_compression_config,
)


class TestCompressionConfig:
    def test_default_values(self):
        cfg = CompressionConfig()
        assert cfg.enabled is True
        assert cfg.minimum_size == DEFAULT_MIN_SIZE
        assert cfg.compresslevel == 6

    def test_default_min_size(self):
        assert DEFAULT_MIN_SIZE == 500


class TestBuildCompressionConfig:
    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.delenv("CM_COMPRESSION_ENABLED", raising=False)
        monkeypatch.delenv("CM_COMPRESSION_MIN_SIZE", raising=False)
        monkeypatch.delenv("CM_COMPRESSION_LEVEL", raising=False)
        cfg = build_compression_config()
        assert cfg.enabled is True
        assert cfg.minimum_size == 500
        assert cfg.compresslevel == 6

    def test_from_env_custom(self, monkeypatch):
        monkeypatch.setenv("CM_COMPRESSION_ENABLED", "false")
        monkeypatch.setenv("CM_COMPRESSION_MIN_SIZE", "1024")
        monkeypatch.setenv("CM_COMPRESSION_LEVEL", "9")
        cfg = build_compression_config()
        assert cfg.enabled is False
        assert cfg.minimum_size == 1024
        assert cfg.compresslevel == 9
