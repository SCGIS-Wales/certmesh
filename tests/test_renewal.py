"""Tests for certmesh.renewal -- auto-renewal engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from certmesh.renewal import (
    RenewalPolicy,
    RenewalResult,
    _convert_to_seconds,
    check_and_renew,
    should_renew,
)


class TestConvertToSeconds:
    def test_hour(self):
        assert _convert_to_seconds(1, "hour") == 3600

    def test_day(self):
        assert _convert_to_seconds(1, "day") == 86400

    def test_month(self):
        assert _convert_to_seconds(1, "month") == 2592000

    def test_year(self):
        assert _convert_to_seconds(1, "year") == 31536000

    def test_multiple_units(self):
        assert _convert_to_seconds(7, "day") == 604800

    def test_invalid_unit(self):
        with pytest.raises(ValueError, match="Invalid unit"):
            _convert_to_seconds(1, "minute")


class TestShouldRenew:
    def test_cert_expiring_within_window(self):
        not_after = datetime.now(timezone.utc) + timedelta(days=20)
        policy = RenewalPolicy(before_expiry=30, unit="day")
        assert should_renew(not_after, policy) is True

    def test_cert_not_expiring(self):
        not_after = datetime.now(timezone.utc) + timedelta(days=60)
        policy = RenewalPolicy(before_expiry=30, unit="day")
        assert should_renew(not_after, policy) is False

    def test_cert_already_expired(self):
        not_after = datetime.now(timezone.utc) - timedelta(days=1)
        policy = RenewalPolicy(before_expiry=30, unit="day")
        assert should_renew(not_after, policy) is True

    def test_none_not_after(self):
        policy = RenewalPolicy(before_expiry=30, unit="day")
        assert should_renew(None, policy) is False

    def test_naive_datetime_treated_as_utc(self):
        # Naive datetime (no tzinfo) should be treated as UTC
        not_after = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=20)
        policy = RenewalPolicy(before_expiry=30, unit="day")
        assert should_renew(not_after, policy) is True

    def test_hour_unit(self):
        not_after = datetime.now(timezone.utc) + timedelta(hours=5)
        policy = RenewalPolicy(before_expiry=12, unit="hour")
        assert should_renew(not_after, policy) is True

    def test_hour_unit_not_expiring(self):
        not_after = datetime.now(timezone.utc) + timedelta(hours=24)
        policy = RenewalPolicy(before_expiry=12, unit="hour")
        assert should_renew(not_after, policy) is False

    def test_exact_boundary(self):
        not_after = datetime.now(timezone.utc) + timedelta(days=30)
        policy = RenewalPolicy(before_expiry=30, unit="day")
        # At exactly 30 days, remaining == threshold, should renew (<=)
        assert should_renew(not_after, policy) is True


class TestRenewalPolicy:
    def test_defaults(self):
        policy = RenewalPolicy()
        assert policy.before_expiry == 30
        assert policy.unit == "day"
        assert policy.providers == ["all"]
        assert policy.dry_run is False

    def test_custom_values(self):
        policy = RenewalPolicy(
            before_expiry=7,
            unit="hour",
            providers=["acm", "venafi"],
            dry_run=True,
        )
        assert policy.before_expiry == 7
        assert policy.unit == "hour"
        assert policy.providers == ["acm", "venafi"]
        assert policy.dry_run is True


class TestRenewalResult:
    def test_basic_result(self):
        result = RenewalResult(
            provider="acm",
            identifier="arn:aws:acm:...",
            common_name="test.example.com",
            not_after=datetime.now(timezone.utc),
            needs_renewal=True,
            renewed=False,
        )
        assert result.provider == "acm"
        assert result.needs_renewal is True
        assert result.renewed is False
        assert result.error is None


class TestCheckAndRenew:
    def test_no_providers_configured(self):
        results = check_and_renew({}, RenewalPolicy())
        assert isinstance(results, list)

    def test_all_expands_to_all_providers(self):
        results = check_and_renew({}, RenewalPolicy(providers=["all"]))
        assert isinstance(results, list)

    def test_specific_provider(self):
        results = check_and_renew({}, RenewalPolicy(providers=["acm"]))
        assert isinstance(results, list)

    def test_dry_run_flag(self):
        policy = RenewalPolicy(dry_run=True)
        results = check_and_renew({}, policy)
        assert isinstance(results, list)
