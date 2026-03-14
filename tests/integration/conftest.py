"""Shared fixtures for integration tests."""

from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config, items):
    """Auto-skip integration tests when required services are not available."""
    for item in items:
        if "integration" in item.keywords:
            # Each test module handles its own skip logic via fixtures
            pass


@pytest.fixture(scope="session")
def vault_addr():
    """Vault server address for integration tests."""
    return os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")


@pytest.fixture(scope="session")
def vault_token():
    """Vault dev token for integration tests."""
    return os.environ.get("VAULT_TOKEN", "root")


@pytest.fixture(scope="session")
def localstack_endpoint():
    """LocalStack endpoint URL."""
    return os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
