"""Regression tests for JA4PROXY-2026-0022 — Trusted CIDR /0 Acceptance.

Before the fix, proxy.py accepted any string that ipaddress.ip_network() could
parse as a trusted upstream CIDR — including 0.0.0.0/0, ::/0, and other
dangerously-broad ranges. A single misconfiguration (templating accident,
bad Ansible variable, injected config) meant every attacker on the Internet
was treated as a trusted PROXY-protocol upstream and could rewrite the
client IP at will, defeating the whole trust model.

_validate_upstream_trust() now refuses /0–/2 on IPv4 and /0–/7 on IPv6
outright, logs CRITICAL on any range broader than /16 (IPv4) / /32 (IPv6),
and WARNs on loopback/private ranges (used for local testing but never for
production). This test pins that behaviour.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from proxy import ConfigManager, ValidationError


def _mgr() -> ConfigManager:
    """ConfigManager pinned to the real proxy.yml — we invoke only the
    validator methods directly, so no IO beyond the initial read."""
    return ConfigManager("config/proxy.yml")


@pytest.mark.parametrize(
    "bad_cidr",
    [
        "0.0.0.0/0",
        "0.0.0.0/1",
        "0.0.0.0/2",
        "128.0.0.0/1",
        "192.0.0.0/2",
        "::/0",
        "::/1",
        "::/7",
    ],
)
def test_regression_JA4PROXY_2026_0022_rejects_overly_broad_cidr(bad_cidr: str) -> None:
    mgr = _mgr()
    with pytest.raises(ValidationError, match="dangerously broad"):
        mgr._validate_upstream_trust({"trusted_cidrs": [bad_cidr]})


@pytest.mark.parametrize(
    "bad_input",
    [
        "not-a-cidr",
        "999.999.999.999/8",
        "10.0.0.0/33",
        "::1/200",
        "",
    ],
)
def test_regression_JA4PROXY_2026_0022_rejects_malformed_cidr(bad_input: str) -> None:
    mgr = _mgr()
    with pytest.raises(ValidationError, match="Invalid trusted CIDR"):
        mgr._validate_upstream_trust({"trusted_cidrs": [bad_input]})


def test_regression_JA4PROXY_2026_0022_rejects_non_string_entry() -> None:
    mgr = _mgr()
    with pytest.raises(ValidationError, match="must be a string CIDR"):
        mgr._validate_upstream_trust({"trusted_cidrs": [1234]})


def test_regression_JA4PROXY_2026_0022_rejects_non_list() -> None:
    mgr = _mgr()
    with pytest.raises(ValidationError, match="must be a list"):
        mgr._validate_upstream_trust({"trusted_cidrs": "10.0.0.0/8"})


def test_regression_JA4PROXY_2026_0022_rejects_non_mapping_trust_block() -> None:
    mgr = _mgr()
    with pytest.raises(ValidationError, match="must be a mapping"):
        mgr._validate_upstream_trust([])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "safe_cidr",
    [
        "10.0.0.0/24",
        "192.168.1.0/24",
        "172.16.0.0/16",
        "203.0.113.0/24",
        "2001:db8::/48",
        "fd00::/64",
    ],
)
def test_regression_JA4PROXY_2026_0022_accepts_narrow_cidr(safe_cidr: str) -> None:
    mgr = _mgr()
    # Should not raise.
    mgr._validate_upstream_trust({"trusted_cidrs": [safe_cidr]})


def test_regression_JA4PROXY_2026_0022_empty_list_is_fine() -> None:
    mgr = _mgr()
    mgr._validate_upstream_trust({"trusted_cidrs": []})
    mgr._validate_upstream_trust({})  # no trusted_cidrs key at all
    mgr._validate_upstream_trust({"trusted_cidrs": None})


def test_regression_JA4PROXY_2026_0022_broad_cidr_logs_critical() -> None:
    mgr = _mgr()
    mgr.logger = MagicMock(spec=logging.Logger)
    # /8 is broader than /16, so CRITICAL fires.
    mgr._validate_upstream_trust({"trusted_cidrs": ["10.0.0.0/8"]})
    assert (
        mgr.logger.critical.called
    ), "trusted CIDR broader than /16 must emit CRITICAL per 118h spec"
    # /24 is narrow — no CRITICAL.
    mgr.logger.reset_mock()
    mgr._validate_upstream_trust({"trusted_cidrs": ["192.0.2.0/24"]})
    assert not mgr.logger.critical.called, "narrow /24 must not trigger CRITICAL"


def test_regression_JA4PROXY_2026_0022_rfc1918_and_loopback_warn() -> None:
    mgr = _mgr()
    mgr.logger = MagicMock(spec=logging.Logger)
    mgr._validate_upstream_trust({"trusted_cidrs": ["127.0.0.0/24"]})
    assert mgr.logger.warning.called, "loopback CIDR must WARN"

    mgr.logger.reset_mock()
    mgr._validate_upstream_trust({"trusted_cidrs": ["192.168.1.0/24"]})
    assert mgr.logger.warning.called, "RFC1918 CIDR must WARN"

    mgr.logger.reset_mock()
    # A truly public, narrow range: neither CRITICAL (narrower than /16)
    # nor WARN (not loopback/private). 203.0.113.0/24 looks public but Python
    # classifies RFC5737 documentation ranges as private, so use a real
    # global range.
    mgr._validate_upstream_trust({"trusted_cidrs": ["8.8.8.0/24"]})
    assert not mgr.logger.warning.called
    assert not mgr.logger.critical.called


def test_regression_JA4PROXY_2026_0022_validate_proxy_config_routes_through_helper() -> (
    None
):
    """_validate_proxy_config must call _validate_upstream_trust when the key
    is present — otherwise the end-to-end config load path stays unprotected."""
    mgr = _mgr()
    with pytest.raises(ValidationError, match="dangerously broad"):
        mgr._validate_proxy_config({"upstream_trust": {"trusted_cidrs": ["0.0.0.0/0"]}})
