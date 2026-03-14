"""
certmesh.renewal
================

Automatic certificate renewal engine. Checks certificates across providers
for approaching expiry and renews them based on a configurable policy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Time unit conversion factors (to seconds)
_UNIT_SECONDS = {
    "hour": 3600,
    "day": 86400,
    "month": 2592000,  # 30 days
    "year": 31536000,  # 365 days
}


@dataclass
class RenewalPolicy:
    """Policy controlling when certificates should be renewed."""

    before_expiry: int = 30
    unit: str = "day"
    providers: list[str] = field(default_factory=lambda: ["all"])
    dry_run: bool = False


@dataclass
class RenewalResult:
    """Result of a renewal check/action for a single certificate."""

    provider: str
    identifier: str  # ARN, GUID, serial, CN, etc.
    common_name: str
    not_after: datetime | None
    needs_renewal: bool
    renewed: bool = False
    error: str | None = None


def _convert_to_seconds(value: int, unit: str) -> float:
    """Convert a value + unit to seconds."""
    if unit not in _UNIT_SECONDS:
        raise ValueError(f"Invalid unit '{unit}'. Must be one of: {sorted(_UNIT_SECONDS)}")
    return value * _UNIT_SECONDS[unit]


def should_renew(not_after: datetime | None, policy: RenewalPolicy) -> bool:
    """Check if a certificate should be renewed based on the policy."""
    if not_after is None:
        return False
    threshold_seconds = _convert_to_seconds(policy.before_expiry, policy.unit)
    now = datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    remaining = (not_after - now).total_seconds()
    return remaining <= threshold_seconds


def check_and_renew(
    cfg: dict[str, Any],
    policy: RenewalPolicy,
) -> list[RenewalResult]:
    """Scan configured providers for certificates approaching expiry.

    Returns a list of RenewalResult objects describing what was checked
    and what actions were taken (or would be taken in dry-run mode).
    """
    results: list[RenewalResult] = []
    active_providers = policy.providers

    if "all" in active_providers:
        active_providers = ["vault-pki", "acm", "digicert", "venafi", "letsencrypt"]

    for provider in active_providers:
        try:
            provider_results = _check_provider(cfg, provider, policy)
            results.extend(provider_results)
        except Exception as exc:
            logger.error("Error checking provider '%s': %s", provider, exc)
            results.append(
                RenewalResult(
                    provider=provider,
                    identifier="*",
                    common_name="*",
                    not_after=None,
                    needs_renewal=False,
                    error=str(exc),
                )
            )

    # Summary logging
    total = len(results)
    needs_renewal = sum(1 for r in results if r.needs_renewal)
    renewed = sum(1 for r in results if r.renewed)
    errors = sum(1 for r in results if r.error)

    logger.info(
        "Renewal check complete: %d certificates checked, %d need renewal, %d renewed, %d errors.",
        total,
        needs_renewal,
        renewed,
        errors,
    )

    return results


def _check_provider(
    cfg: dict[str, Any],
    provider: str,
    policy: RenewalPolicy,
) -> list[RenewalResult]:
    """Check a single provider for certificates needing renewal."""
    logger.info("Checking provider '%s' for certificates approaching expiry...", provider)

    # Each provider-specific check is a stub that can be extended
    # when the provider's list/describe capabilities are wired up.
    # For now, return empty list (provider not configured or no certs found).
    results: list[RenewalResult] = []

    provider_cfg = cfg.get(provider.replace("-", "_"), {})
    if not provider_cfg:
        logger.debug("Provider '%s' not configured, skipping.", provider)
        return results

    logger.info(
        "Provider '%s': found %d certificates, %d need renewal.",
        provider,
        len(results),
        sum(1 for r in results if r.needs_renewal),
    )
    return results
