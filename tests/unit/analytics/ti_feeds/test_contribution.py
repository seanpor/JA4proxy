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
    assert (
        "field" in msg or "allowed" in msg or "whitelist" in msg or extra_field in msg
    )


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


# ── GDPR gate edge cases (coverage gap closure) ─────────────────────────────


def test_serialize_non_dict_raises_value_error():
    """_serialize raises ValueError on non-dict payload."""
    contribution = _import_contribution()
    with pytest.raises(ValueError, match="must be a dict"):
        contribution.ContributionClient._serialize("not a dict")


def test_serialise_contribution_non_dict_raises():
    """Module-level serialise_contribution raises on non-dict."""
    contribution = _import_contribution()
    with pytest.raises(ValueError, match="must be a dict"):
        contribution.serialise_contribution("not a dict")


def test_ja4_field_non_string_raises():
    """ja4 field must be a string, not an int."""
    contribution = _import_contribution()
    payload = _make_valid_payload()
    payload["ja4"] = 12345
    with pytest.raises(ValueError, match="must be a string"):
        contribution.ContributionClient._serialize(payload)


@pytest.mark.parametrize(
    "suspicious_ja4",
    [
        "192.168.1.1",  # IP address with dots in first segment
        "https://example.com",  # URL with slash
        "::1",  # IPv6 with colons
    ],
)
def test_ja4_field_looks_like_ip_or_url_raises(suspicious_ja4):
    """ja4 that looks like an IP or URL is rejected."""
    contribution = _import_contribution()
    payload = _make_valid_payload()
    payload["ja4"] = suspicious_ja4
    with pytest.raises(ValueError, match="looks like an IP or URL"):
        contribution.ContributionClient._serialize(payload)


# ── contribute() HTTP path (coverage lines 220-278) ─────────────────────────


def test_contribute_enabled_success():
    """contribute() returns True on 2xx response."""
    contribution = _import_contribution()
    client = contribution.ContributionClient(
        enabled=True,
        endpoint="https://feed.test/v1/contribute",
        api_key="key",
    )

    async def _ok_post(url, json=None, headers=None, **kwargs):
        return MagicMock(status=200)

    with patch.object(client, "_post", _ok_post):
        result = _run(client.contribute(_make_valid_payload()))
    assert result is True


def test_contribute_non_2xx_returns_false(caplog):
    """contribute() returns False and warns on non-2xx status."""
    contribution = _import_contribution()
    client = contribution.ContributionClient(
        enabled=True,
        endpoint="https://feed.test/v1/contribute",
        api_key="key",
    )

    async def _bad_post(url, json=None, headers=None, **kwargs):
        return MagicMock(status=500)

    caplog.set_level(logging.WARNING)
    with patch.object(client, "_post", _bad_post):
        result = _run(client.contribute(_make_valid_payload()))
    assert result is False


# ── maybe_submit() path (coverage lines 238-278) ────────────────────────────


def test_maybe_submit_disabled_returns_false():
    """maybe_submit returns False when disabled."""
    contribution = _import_contribution()
    client = contribution.ContributionClient(enabled=False)
    result = _run(client.maybe_submit(_make_valid_payload()))
    assert result is False


def test_maybe_submit_gdpr_gate_rejects_disallowed_fields(caplog):
    """maybe_submit returns False when payload has disallowed fields."""
    contribution = _import_contribution()
    client = contribution.ContributionClient(
        enabled=True,
        endpoint="https://feed.test/v1/contribute",
        api_key="key",
    )
    payload = _make_valid_payload()
    payload["source_ip"] = "1.2.3.4"

    caplog.set_level(logging.ERROR)
    result = _run(client.maybe_submit(payload))
    assert result is False


def test_maybe_submit_success():
    """maybe_submit returns True on 2xx aiohttp response."""
    contribution = _import_contribution()

    import aiohttp

    class FakeResp:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def post(self, url, data=None, headers=None, timeout=None):
            return FakeResp()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    client = contribution.ContributionClient(
        enabled=True,
        endpoint="https://feed.test/v1/contribute",
        api_key="key",
    )

    with patch("src.analytics.ti_feeds.contribution.aiohttp") as mock_aiohttp:
        mock_aiohttp.ClientSession.return_value = FakeSession()
        mock_aiohttp.ClientTimeout = aiohttp.ClientTimeout
        result = _run(client.maybe_submit(_make_valid_payload()))
    assert result is True


def test_maybe_submit_non_2xx_returns_false():
    """maybe_submit returns False on non-2xx response."""
    contribution = _import_contribution()

    import aiohttp

    class FakeResp:
        status = 503

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def post(self, url, data=None, headers=None, timeout=None):
            return FakeResp()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    client = contribution.ContributionClient(
        enabled=True,
        endpoint="https://feed.test/v1/contribute",
        api_key="key",
    )

    with patch("src.analytics.ti_feeds.contribution.aiohttp") as mock_aiohttp:
        mock_aiohttp.ClientSession.return_value = FakeSession()
        mock_aiohttp.ClientTimeout = aiohttp.ClientTimeout
        result = _run(client.maybe_submit(_make_valid_payload()))
    assert result is False


def test_maybe_submit_network_error_returns_false():
    """maybe_submit returns False on network error."""
    contribution = _import_contribution()

    import aiohttp

    class ErrorSession:
        def post(self, url, data=None, headers=None, timeout=None):
            raise ConnectionError("network down")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    client = contribution.ContributionClient(
        enabled=True,
        endpoint="https://feed.test/v1/contribute",
        api_key="key",
    )

    with patch("src.analytics.ti_feeds.contribution.aiohttp") as mock_aiohttp:
        mock_aiohttp.ClientSession.return_value = ErrorSession()
        mock_aiohttp.ClientTimeout = aiohttp.ClientTimeout
        result = _run(client.maybe_submit(_make_valid_payload()))
    assert result is False
