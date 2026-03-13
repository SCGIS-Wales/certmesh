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

from certmesh.api.auth import JWTBearer, OAuth2Config
from certmesh.api.middleware import RequestIDMiddleware, register_exception_handlers
from certmesh.api.routes import acm, digicert, health, vault_pki, venafi
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

    logger.info("certmesh API started (OAuth2 enabled=%s).", oauth2_config.enabled)
    yield
    logger.info("certmesh API shutting down.")


def create_app(**kwargs: Any) -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title="certmesh",
        description="TLS certificate lifecycle management API",
        version="3.0.0",
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

    # Exception handlers
    register_exception_handlers(app)

    # Routes
    app.include_router(health.router)
    app.include_router(digicert.router)
    app.include_router(venafi.router)
    app.include_router(vault_pki.router)
    app.include_router(acm.router)

    # Prometheus metrics endpoint
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    return app
