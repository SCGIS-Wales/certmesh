"""
certmesh.api.tls_config
=========================

TLS server configuration for Uvicorn.

Supports TLS 1.3 + 1.2 with configurable cipher suites and keep-alive
settings.  Strong defaults per Mozilla "Intermediate" compatibility.

Configuration is applied when launching uvicorn programmatically or via
the gunicorn worker.  For Helm/Kubernetes deployments, TLS termination
is typically handled by the ingress controller or Vault PKI init container.
"""

from __future__ import annotations

import logging
import os
import ssl
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── TLS Cipher Suites ───────────────────────────────────────────────────────
# Mozilla "Intermediate" compatibility (March 2026).
# TLS 1.3 cipher suites are managed by OpenSSL and cannot be disabled individually;
# TLS 1.2 cipher suites are explicitly listed.

TLS13_CIPHERS: list[str] = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
]

TLS12_CIPHERS: list[str] = [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
]

# Combined default cipher string for OpenSSL
DEFAULT_CIPHERS = ":".join(TLS12_CIPHERS)


@dataclass
class TLSConfig:
    """TLS server configuration."""

    enabled: bool = False
    cert_file: str = ""
    key_file: str = ""
    ca_file: str = ""
    min_version: str = "TLSv1.2"
    max_version: str = "TLSv1.3"
    ciphers: str = DEFAULT_CIPHERS
    # HTTP keep-alive
    keepalive_timeout: int = 75  # seconds (matches nginx default)
    keepalive_max_requests: int = 1000  # max requests per connection
    # Additional hardening
    honor_cipher_order: bool = True
    session_tickets: bool = False  # disable for forward secrecy


@dataclass
class ServerConfig:
    """Combined server configuration."""

    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    timeout: int = 120
    max_request_size: int = 1_048_576  # 1MB
    tls: TLSConfig = field(default_factory=TLSConfig)
    # Keep-alive settings (applied even without TLS)
    keepalive_timeout: int = 75
    keepalive_max_requests: int = 1000


def build_tls_config() -> TLSConfig:
    """Build TLS config from environment variables."""
    return TLSConfig(
        enabled=os.environ.get("CM_TLS_ENABLED", "false").lower() in ("1", "true", "yes"),
        cert_file=os.environ.get("CM_TLS_CERT_FILE", "/etc/tls/tls.crt"),
        key_file=os.environ.get("CM_TLS_KEY_FILE", "/etc/tls/tls.key"),
        ca_file=os.environ.get("CM_TLS_CA_FILE", "/etc/tls/ca.crt"),
        min_version=os.environ.get("CM_TLS_MIN_VERSION", "TLSv1.2"),
        max_version=os.environ.get("CM_TLS_MAX_VERSION", "TLSv1.3"),
        ciphers=os.environ.get("CM_TLS_CIPHERS", DEFAULT_CIPHERS),
        keepalive_timeout=int(os.environ.get("CM_TLS_KEEPALIVE_TIMEOUT", "75")),
        keepalive_max_requests=int(os.environ.get("CM_TLS_KEEPALIVE_MAX_REQUESTS", "1000")),
        honor_cipher_order=os.environ.get("CM_TLS_HONOR_CIPHER_ORDER", "true").lower()
        in ("1", "true", "yes"),
        session_tickets=os.environ.get("CM_TLS_SESSION_TICKETS", "false").lower()
        in ("1", "true", "yes"),
    )


def build_server_config() -> ServerConfig:
    """Build full server config from environment variables."""
    return ServerConfig(
        host=os.environ.get("CM_HOST", "0.0.0.0"),
        port=int(os.environ.get("CM_PORT", "8000")),
        workers=int(os.environ.get("CM_API_WORKERS", "4")),
        timeout=int(os.environ.get("CM_API_TIMEOUT", "120")),
        max_request_size=int(os.environ.get("CM_API_MAX_REQUEST_SIZE", "1048576")),
        tls=build_tls_config(),
        keepalive_timeout=int(os.environ.get("CM_KEEPALIVE_TIMEOUT", "75")),
        keepalive_max_requests=int(os.environ.get("CM_KEEPALIVE_MAX_REQUESTS", "1000")),
    )


def create_ssl_context(config: TLSConfig) -> ssl.SSLContext | None:
    """Create an SSL context from TLS configuration.

    Returns ``None`` if TLS is not enabled.
    """
    if not config.enabled:
        return None

    # Map version strings to protocol constants
    min_versions = {
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    max_versions = {
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = min_versions.get(config.min_version, ssl.TLSVersion.TLSv1_2)
    ctx.maximum_version = max_versions.get(config.max_version, ssl.TLSVersion.TLSv1_3)

    # Cipher suites
    if config.ciphers:
        ctx.set_ciphers(config.ciphers)

    # Server cipher order preference
    if config.honor_cipher_order:
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    # Session tickets
    if not config.session_tickets:
        ctx.options |= ssl.OP_NO_TICKET

    # Load certificates
    if config.cert_file and config.key_file:
        ctx.load_cert_chain(
            certfile=config.cert_file,
            keyfile=config.key_file,
        )
        logger.info("TLS certificate loaded: cert=%s key=%s", config.cert_file, config.key_file)

    # Load CA bundle for client verification (optional)
    if config.ca_file:
        try:
            ctx.load_verify_locations(config.ca_file)
            logger.info("TLS CA bundle loaded: %s", config.ca_file)
        except Exception:
            logger.warning("Could not load CA bundle from %s; continuing without.", config.ca_file)

    logger.info(
        "TLS context created: min=%s max=%s honor_order=%s session_tickets=%s",
        config.min_version,
        config.max_version,
        config.honor_cipher_order,
        config.session_tickets,
    )
    return ctx


def get_uvicorn_ssl_kwargs(config: TLSConfig) -> dict:
    """Return kwargs suitable for uvicorn.run() SSL configuration."""
    if not config.enabled:
        return {}

    return {
        "ssl_certfile": config.cert_file,
        "ssl_keyfile": config.key_file,
        "ssl_ca_certs": config.ca_file or None,
        "ssl_ciphers": config.ciphers,
    }
