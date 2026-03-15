"""
certmesh.config_loader
========================

Compatibility shim — delegates to certmesh.settings.

.. deprecated:: 3.0
    Use :func:`certmesh.settings.build_config` directly.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

from certmesh.settings import build_config, configure_logging, validate_config

__all__ = ["configure_logging", "load_config"]

JsonDict = dict[str, Any]


def load_config(config_path: str | Path = "config/config.yaml") -> JsonDict:
    """Load configuration from a YAML file.

    .. deprecated:: 3.0
        Use :func:`certmesh.settings.build_config` instead.
    """
    warnings.warn(
        "certmesh.config_loader.load_config is deprecated. "
        "Use certmesh.settings.build_config instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    cfg = build_config(config_file=config_path)
    validate_config(cfg)
    return cfg
