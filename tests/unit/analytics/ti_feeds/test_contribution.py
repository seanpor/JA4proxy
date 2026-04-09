"""Phase 85 — unit tests for ``analytics.ti_feeds.contribution``.

This is the **GDPR hard gate**. The community contribution payload schema is a
closed whitelist of fields:
    {ja4, category, triggering_signals, occurrences_count,
     first_seen_bucket, last_seen_bucket, confirmed_fp_rate}

Adding ANY other field must raise ``ValueError`` at serialise time. The
contribution client must also default to disabled and emit a once-per-hour
WARN if enabled with an unreachable endpoint.

These tests are RED until ``src/analytics/ti_feeds/contribution.py`` exists.
"""

from __future__ import annotations

import asyncio
import logging
import time
from unittest.mock import MagicMock, patch

import pytest


def _run(coro):
    return asyncio.run(coro)


def _import_contribution():
    from src.analytics.ti_feeds import contribution

    return contribution


# ── Field whitelist (the hard gate) ───────────────────────────────────────────


_ALLOWED_FIELDS = {
    "ja4",
    "category",
    "triggering_signals",
    "occurrences_count",
    "first_seen_bucket",
    "last_seen_bucket",
    "confirmed_fp_rate",
}


def _make_valid_payload():
    return {
        "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
        "category": "c2_framework",
        "triggering_signals": ["abuseipdb", "spamhaus"],
        "occurrences_count": 142,
        "first_seen_bucket": "2026-04-08T00:00:00Z",
        "last_seen_bucket": "2026-04-08T14:00:00Z",
        "confirmed_fp_rate": 0.0,
    }


def test_valid_payload_serialises_cleanly():
    contribution = _import_contribution()
    payload = _make_valid_payload()
    serialised = contribution.serialise_contribution(payload)
    assert isinstance(serialised, (bytes, str))


@pytest.mark.parametrize(
    "extra_field,extra_value",
    [
        ("source_ip", "192.0.2.1"),
        ("ip", "192.0.2.1"),
        ("client_ip", "192.0.2.1"),
        ("sni", "internal.corp.example"),
        ("host", "internal.corp.example"),
        ("url", "https://internal.corp.example/api/v1"),
        ("user_agent", "curl/7.85.0"),
        ("audit_log_id", "audit:0001"),
        ("enrichment_asn", 13335),
        ("country", "US"),
        ("timestamp", "2026-04-08T14:32:17.451Z"),  # finer than hour
        ("session_id", "abcdef"),
    ],
)
def test_disallowed_fields_raise_value_error(extra_field, extra_value):
    """The hard gate: any field not on the whitelist raises ValueError."""
    contribution = _import_contribution()
    payload = _make_valid_payload()
    payload[extra_field] = extra_value

    with pytest.raises(ValueError) as excinfo:
        contribution.serialise_contribution(payload)

    msg = str(excinfo.value).lower()
    assert "field" in msg or "allowed" in msg or "whitelist" in msg or extra_field in msg


def test_payload_missing_required_field_raises():
    contribution = _import_contribution()
    payload = _make_valid_payload()
    del payload["ja4"]
    with pytest.raises((ValueError, KeyError)):
        contribution.serialise_contribution(payload)


def test_serialised_payload_contains_only_allowed_fields():
    contribution = _import_contribution()
    payload = _make_valid_payload()
    out = contribution.serialise_contribution(payload)
    if isinstance(out, bytes):
        import json

        data = json.loads(out.decode())
    elif isinstance(out, str):
        import json

        data = json.loads(out)
    else:
        data = dict(out)
    assert set(data.keys()).issubset(_ALLOWED_FIELDS)


# ── Disabled by default ────────────────────────────────────────────────────────


def test_contribution_client_disabled_by_default():
    contribution = _import_contribution()
    client = contribution.ContributionClient()
    assert client.enabled is False


def test_disabled_client_does_not_post():
    contribution = _import_contribution()
    client = contribution.ContributionClient(enabled=False)
    posted: list = []

    async def _fake_post(url, json=None, headers=None, **kwargs):
        posted.append((url, json))
        return MagicMock(status=200)

    with patch.object(client, "_post", _fake_post):
        _run(client.contribute(_make_valid_payload()))

    assert posted == []


# ── Once-per-hour WARN ────────────────────────────────────────────────────────


def test_unreachable_endpoint_logs_warn_at_most_once_per_hour(caplog):
    """When enabled and endpoint unreachable, WARN at most once per hour."""
    contribution = _import_contribution()
    client = contribution.ContributionClient(
        enabled=True,
        endpoint="https://unreachable.test/api/v1/contribute",
        api_key="test",
    )

    async def _broken_post(url, json=None, headers=None, **kwargs):
        raise ConnectionError("simulated outage")

    times = [1000.0]

    def _now() -> float:
        return times[0]

    caplog.set_level(logging.WARNING)
    with patch.object(client, "_post", _broken_post), patch("time.monotonic", _now):
        _run(client.contribute(_make_valid_payload()))
        _run(client.contribute(_make_valid_payload()))
        _run(client.contribute(_make_valid_payload()))
        # Three failures within the same minute → only ONE WARN
        warns = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warns) == 1

        # Advance the clock past one hour and try again → a second WARN
        times[0] += 3601.0
        _run(client.contribute(_make_valid_payload()))
        warns = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warns) == 2
