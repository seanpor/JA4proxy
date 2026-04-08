"""Phase 85 — unit tests for ``analytics.ti_feeds.stix_ja4``.

Verifies the STIX 2.1 JA4 extension helpers:
- ``parse_ja4_pattern`` extracts the JA4 string from
  ``[x-ja4-fingerprint:value = '...']``
- malformed JA4 strings are rejected (wrong shape, length, illegal chars)
- ``parse_new_sco`` reads ``new-sco`` extension objects
- the indicator's ``pattern_type`` is asserted as ``"stix"`` (the consumer
  must NOT invent ``"x-ja4-fingerprint"`` as a pattern_type)

These tests are RED until ``src/analytics/ti_feeds/stix_ja4.py`` exists.
"""

from __future__ import annotations

import pytest


def _import_stix_ja4():
    from analytics.ti_feeds import stix_ja4

    return stix_ja4


# ── Pattern detection ─────────────────────────────────────────────────────────


def test_is_ja4_pattern_returns_true_for_canonical_form():
    sj = _import_stix_ja4()
    assert sj.is_ja4_pattern("[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']") is True


def test_is_ja4_pattern_returns_false_for_ip_indicator():
    sj = _import_stix_ja4()
    assert sj.is_ja4_pattern("[ipv4-addr:value = '198.51.100.42']") is False


def test_is_ip_pattern_returns_true_for_ipv4():
    sj = _import_stix_ja4()
    assert sj.is_ip_pattern("[ipv4-addr:value = '198.51.100.42']") is True


def test_is_ip_pattern_returns_true_for_ipv6():
    sj = _import_stix_ja4()
    assert sj.is_ip_pattern("[ipv6-addr:value = '2001:db8::1']") is True


# ── Parser ─────────────────────────────────────────────────────────────────────


def test_parse_ja4_pattern_returns_ja4_string():
    sj = _import_stix_ja4()
    ja4 = sj.parse_ja4_pattern(
        "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']"
    )
    assert ja4 == "t10d170900_9dc949161b6c_b64c0ad42cb7"


def test_parse_ip_pattern_extracts_ipv4():
    sj = _import_stix_ja4()
    ip = sj.parse_ip_pattern("[ipv4-addr:value = '198.51.100.42']")
    assert ip == "198.51.100.42"


def test_parse_ip_pattern_extracts_ipv6():
    sj = _import_stix_ja4()
    ip = sj.parse_ip_pattern("[ipv6-addr:value = '2001:db8::dead:beef']")
    assert ip == "2001:db8::dead:beef"


# ── Malformed JA4 rejection ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "tooshort",
        "wrongshape_only_two",
        "x10d170900_9dc949161b6c_b64c0ad42cb7",  # wrong leading char
        "t10d170900_9dc949161b6cz_b64c0ad42cb7",  # 13-char middle
        "t10d170900_9dc949161b6_b64c0ad42cb7",  # 11-char middle
        "t10d170900_9dc949161B6C_b64c0ad42cb7",  # uppercase hex disallowed
        "",
        "t10d170900__b64c0ad42cb7",  # empty middle
    ],
)
def test_parse_ja4_rejects_malformed(bad):
    sj = _import_stix_ja4()
    with pytest.raises((ValueError, AssertionError)):
        sj.validate_ja4(bad)


def test_validate_ja4_accepts_canonical():
    sj = _import_stix_ja4()
    sj.validate_ja4("t10d170900_9dc949161b6c_b64c0ad42cb7")  # no raise = pass
    sj.validate_ja4("t13d301100_5b57614c22b0_3d5424432f57")


# ── new-sco object parsing ─────────────────────────────────────────────────────


def test_parse_new_sco_returns_metadata():
    sj = _import_stix_ja4()

    sco = {
        "type": "x-ja4-fingerprint",
        "spec_version": "2.1",
        "id": "x-ja4-fingerprint--0e3b8c44-5f2e-4d2a-9ed7-8a1a2b3c4d5e",
        "value": "t10d170900_9dc949161b6c_b64c0ad42cb7",
        "extensions": {
            "extension-definition--3b37e1e8-5a20-4c3d-aa0c-9a581b6f9d4e": {
                "extension_type": "new-sco",
                "likely_category": "c2_framework",
                "likely_tool": "cobalt_strike",
                "ja4x": None,
                "source": "ja4proxy-community-feed",
            }
        },
    }

    parsed = sj.parse_new_sco(sco)
    assert parsed["value"] == "t10d170900_9dc949161b6c_b64c0ad42cb7"
    assert parsed["likely_category"] == "c2_framework"
    assert parsed["likely_tool"] == "cobalt_strike"
    assert parsed["source"] == "ja4proxy-community-feed"


# ── pattern_type contract ──────────────────────────────────────────────────────


def test_indicator_pattern_type_must_be_stix():
    """The consumer asserts pattern_type=='stix', not 'x-ja4-fingerprint'."""
    sj = _import_stix_ja4()
    indicator = {
        "type": "indicator",
        "id": "indicator--xxx",
        "pattern_type": "stix",
        "pattern": "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
        "confidence": 90,
        "valid_from": "2026-04-01T00:00:00Z",
    }
    assert sj.is_supported_indicator(indicator) is True


def test_indicator_with_invented_pattern_type_rejected():
    sj = _import_stix_ja4()
    indicator = {
        "type": "indicator",
        "id": "indicator--bad",
        "pattern_type": "x-ja4-fingerprint",  # WRONG — invented value
        "pattern": "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
        "confidence": 90,
        "valid_from": "2026-04-01T00:00:00Z",
    }
    assert sj.is_supported_indicator(indicator) is False
