"""Unit tests for TLS server configuration."""

import ssl

from certmesh.api.tls_config import (
    DEFAULT_CIPHERS,
    TLS12_CIPHERS,
    TLS13_CIPHERS,
    ServerConfig,
    TLSConfig,
    build_server_config,
    build_tls_config,
    create_ssl_context,
    get_uvicorn_ssl_kwargs,
)


class TestTLSConfig:
    def test_default_values(self):
        cfg = TLSConfig()
        assert cfg.enabled is False
        assert cfg.min_version == "TLSv1.2"
        assert cfg.max_version == "TLSv1.3"
        assert cfg.honor_cipher_order is True
        assert cfg.session_tickets is False
        assert cfg.keepalive_timeout == 75
        assert cfg.keepalive_max_requests == 1000

    def test_default_ciphers_are_strong(self):
        """Verify default ciphers include only strong suites."""
        for cipher in TLS12_CIPHERS:
            # All ciphers should use AEAD (GCM or CHACHA20)
            assert "GCM" in cipher or "CHACHA20" in cipher
            # No CBC mode ciphers
            assert "CBC" not in cipher

    def test_tls13_ciphers_present(self):
        assert "TLS_AES_256_GCM_SHA384" in TLS13_CIPHERS
        assert "TLS_CHACHA20_POLY1305_SHA256" in TLS13_CIPHERS
        assert "TLS_AES_128_GCM_SHA256" in TLS13_CIPHERS

    def test_tls12_ciphers_include_ecdhe(self):
        """All TLS 1.2 ciphers should support forward secrecy (ECDHE or DHE)."""
        for cipher in TLS12_CIPHERS:
            assert cipher.startswith("ECDHE-") or cipher.startswith("DHE-")


class TestServerConfig:
    def test_defaults(self):
        cfg = ServerConfig()
        assert cfg.host == "0.0.0.0"
        assert cfg.port == 8000
        assert cfg.workers == 4
        assert cfg.timeout == 120
        assert cfg.max_request_size == 1_048_576
        assert cfg.keepalive_timeout == 75


class TestBuildTLSConfig:
    def test_from_env_defaults(self, monkeypatch):
        for key in [
            "CM_TLS_ENABLED",
            "CM_TLS_CERT_FILE",
            "CM_TLS_KEY_FILE",
            "CM_TLS_CA_FILE",
            "CM_TLS_MIN_VERSION",
            "CM_TLS_MAX_VERSION",
            "CM_TLS_CIPHERS",
        ]:
            monkeypatch.delenv(key, raising=False)
        cfg = build_tls_config()
        assert cfg.enabled is False
        assert cfg.min_version == "TLSv1.2"
        assert cfg.max_version == "TLSv1.3"

    def test_from_env_custom(self, monkeypatch):
        monkeypatch.setenv("CM_TLS_ENABLED", "true")
        monkeypatch.setenv("CM_TLS_CERT_FILE", "/custom/cert.pem")
        monkeypatch.setenv("CM_TLS_KEY_FILE", "/custom/key.pem")
        monkeypatch.setenv("CM_TLS_MIN_VERSION", "TLSv1.3")
        cfg = build_tls_config()
        assert cfg.enabled is True
        assert cfg.cert_file == "/custom/cert.pem"
        assert cfg.min_version == "TLSv1.3"


class TestBuildServerConfig:
    def test_defaults(self, monkeypatch):
        for key in ["CM_HOST", "CM_PORT", "CM_API_WORKERS", "CM_API_TIMEOUT"]:
            monkeypatch.delenv(key, raising=False)
        cfg = build_server_config()
        assert cfg.port == 8000
        assert cfg.workers == 4

    def test_custom_port(self, monkeypatch):
        monkeypatch.setenv("CM_PORT", "9443")
        cfg = build_server_config()
        assert cfg.port == 9443


class TestCreateSSLContext:
    def test_disabled_returns_none(self):
        cfg = TLSConfig(enabled=False)
        assert create_ssl_context(cfg) is None

    def test_enabled_creates_context(self, tmp_path):
        # We can't easily test full cert loading without real certs,
        # but we can test the context creation logic
        cfg = TLSConfig(
            enabled=True,
            cert_file="",
            key_file="",
            min_version="TLSv1.2",
            max_version="TLSv1.3",
            honor_cipher_order=True,
            session_tickets=False,
        )
        ctx = create_ssl_context(cfg)
        assert ctx is not None
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3


class TestGetUvicornSSLKwargs:
    def test_disabled(self):
        cfg = TLSConfig(enabled=False)
        assert get_uvicorn_ssl_kwargs(cfg) == {}

    def test_enabled(self):
        cfg = TLSConfig(
            enabled=True,
            cert_file="/etc/tls/tls.crt",
            key_file="/etc/tls/tls.key",
            ca_file="/etc/tls/ca.crt",
            ciphers=DEFAULT_CIPHERS,
        )
        kwargs = get_uvicorn_ssl_kwargs(cfg)
        assert kwargs["ssl_certfile"] == "/etc/tls/tls.crt"
        assert kwargs["ssl_keyfile"] == "/etc/tls/tls.key"
        assert kwargs["ssl_ca_certs"] == "/etc/tls/ca.crt"
        assert kwargs["ssl_ciphers"] == DEFAULT_CIPHERS
