"""
certmesh.api.app
=================

FastAPI application factory with lifespan context manager.

Production entrypoint (gunicorn)::

    gunicorn certmesh.api.app:create_app \\
        --worker-class uvicorn.workers.UvicornWorker \\
        --workers 4 \\
        --bind 0.0.0.0:8000 \\
        --factory
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from certmesh.api.apikeys import APIKeyConfig, APIKeyStore
from certmesh.api.auth import JWTBearer, OAuth2Config
from certmesh.api.compression import build_compression_config, register_compression
from certmesh.api.middleware import RequestIDMiddleware, register_exception_handlers
from certmesh.api.rate_limiter import build_rate_limit_config, register_rate_limiter
from certmesh.api.routes import acm, digicert, health, vault_pki, venafi
from certmesh.api.routes.auth_routes import router as auth_router
from certmesh.logging_config import configure_logging as configure_structured_logging
from certmesh.settings import build_config, configure_logging

logger = logging.getLogger(__name__)


def _build_oauth2_config() -> OAuth2Config:
    """Build OAuth2 config from environment variables."""
    return OAuth2Config(
        enabled=os.environ.get("CM_OAUTH2_ENABLED", "false").lower() in ("1", "true", "yes"),
        issuer_url=os.environ.get("CM_OAUTH2_ISSUER_URL", ""),
        audience=os.environ.get("CM_OAUTH2_AUDIENCE", ""),
        jwks_uri=os.environ.get("CM_OAUTH2_JWKS_URI", ""),
        required_scopes=os.environ.get("CM_OAUTH2_REQUIRED_SCOPES", "").split(",")
        if os.environ.get("CM_OAUTH2_REQUIRED_SCOPES")
        else [],
        admin_scopes=os.environ.get("CM_OAUTH2_ADMIN_SCOPES", "").split(",")
        if os.environ.get("CM_OAUTH2_ADMIN_SCOPES")
        else [],
        write_scopes=os.environ.get("CM_OAUTH2_WRITE_SCOPES", "").split(",")
        if os.environ.get("CM_OAUTH2_WRITE_SCOPES")
        else [],
    )


def _build_api_key_config() -> APIKeyConfig:
    """Build API key exchange config from environment variables."""
    return APIKeyConfig(
        enabled=os.environ.get("CM_API_KEY_ENABLED", "true").lower() in ("1", "true", "yes"),
        default_ttl_seconds=int(os.environ.get("CM_API_KEY_DEFAULT_TTL", "900")),
        max_ttl_seconds=int(os.environ.get("CM_API_KEY_MAX_TTL", "28800")),
        max_active_keys=int(os.environ.get("CM_API_KEY_MAX_ACTIVE", "10000")),
    )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: startup + shutdown."""
    # Structured JSON logging for the API — always JSON in production.
    configure_structured_logging(
        level=os.environ.get("CM_LOG_LEVEL", "INFO"),
        log_format="json",
    )

    config_file = os.environ.get("CM_CONFIG_FILE")
    cfg = build_config(config_file=config_file)
    configure_logging(cfg.get("logging", {}))

    app.state.config = cfg

    # OAuth2
    oauth2_config = _build_oauth2_config()
    app.state.oauth2_config = oauth2_config
    app.state.jwt_bearer = JWTBearer(oauth2_config)

    # API key exchange
    api_key_config = _build_api_key_config()
    app.state.api_key_config = api_key_config
    app.state.api_key_store = APIKeyStore(_max_keys=api_key_config.max_active_keys)

    # Vault client (optional)
    vault_cfg = cfg.get("vault", {})
    app.state.vault_client = None
    if vault_cfg.get("url"):
        try:
            from certmesh.backends import vault_client as vc

            client = vc.create_client(vault_cfg)
            vc.authenticate(client, vault_cfg)
            app.state.vault_client = client
            logger.info("Vault client initialized and authenticated.")
        except Exception:
            logger.warning("Vault client initialization failed; continuing without Vault.")

    app.state.aws_required = False

    logger.info(
        "certmesh API started (OAuth2 enabled=%s, API key exchange enabled=%s, "
        "rate_limiting=%s, compression=%s).",
        oauth2_config.enabled,
        api_key_config.enabled,
        getattr(app.state, "rate_limit_enabled", True),
        os.environ.get("CM_COMPRESSION_ENABLED", "true"),
    )
    yield
    logger.info("certmesh API shutting down.")


def create_app(**kwargs: Any) -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title="certmesh",
        description="TLS certificate lifecycle management API",
        version="3.2.0",
        lifespan=_lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Middleware (order matters — outermost first)
    app.add_middleware(RequestIDMiddleware)

    # CORS
    cors_origins = os.environ.get("CM_API_CORS_ORIGINS", "").split(",")
    cors_origins = [o.strip() for o in cors_origins if o.strip()]
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # GZip compression (enabled by default)
    compression_config = build_compression_config()
    register_compression(app, compression_config)

    # Rate limiting (enabled by default, high limits)
    rate_limit_config = build_rate_limit_config()
    register_rate_limiter(app, rate_limit_config)
    app.state.rate_limit_enabled = rate_limit_config.enabled

    # Exception handlers (RFC 7807 compliant)
    register_exception_handlers(app)

    # Routes
    app.include_router(health.router)
    app.include_router(auth_router)
    app.include_router(digicert.router)
    app.include_router(venafi.router)
    app.include_router(vault_pki.router)
    app.include_router(acm.router)

    # Prometheus metrics endpoint
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    return app
