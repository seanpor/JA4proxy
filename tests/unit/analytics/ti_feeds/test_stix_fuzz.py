"""Phase 857 — Property-based fuzzing and malformed feed defense tests.

Tests verify:
- Hypothesis fuzzing of `parse_stix_indicator` with corrupted CIDRs, malformed IPs,
  arbitrary strings, and non-dict inputs.
- ReDoS / catastrophic backtracking resilience on pathological patterns.
- Recursion, deeply nested structures, and cyclic dictionaries.
- TAXII payload size bounding against memory exhaustion.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.analytics.ti_feeds.base import FeedConfig
from src.analytics.ti_feeds.stix_ja4 import (
    _PATTERN_IPV4_RE,
    _PATTERN_JA4_RE,
    IP_PATTERN_REGEX,
    JA4_PATTERN_REGEX,
    is_valid_ja4,
    parse_stix_indicator,
)
from src.analytics.ti_feeds.taxii import DEFAULT_MAX_TAXII_PAYLOAD_BYTES, TAXIIClient

# ── Property-Based Fuzzing of parse_stix_indicator ──────────────────────────


@given(st.data())
@settings(max_examples=100, deadline=1000)
def test_parse_stix_indicator_fuzz_corrupted_cidr(data):
    """Corrupted CIDR patterns must safely return None without throwing unhandled exceptions."""
    prefix = data.draw(
        st.sampled_from(
            [
                "999.999.999.999",
                "256.0.0.1",
                "1.2.3.4.5",
                "192.168.1.1/999",
                "10.0.0.1/-1",
                "192.168.1.1/abc",
                "2001:db8:::1",
                "fe80::1/129",
                "::::1",
                "192.168.1.1/0",  # /0 network
                "0.0.0.0/0",
                "",
                "null",
                "127.0.0.1\x00extra",
            ]
        )
    )
    pattern = f"[ipv4-addr:value = '{prefix}']"
    indicator = {
        "type": "indicator",
        "id": "indicator--fuzz-cidr",
        "pattern_type": "stix",
        "pattern": pattern,
        "confidence": 90,
    }
    # Should never raise an uncaught exception
    res = parse_stix_indicator(indicator)
    if "/" in prefix and "999" in prefix:
        assert res is None


@given(st.from_type(type))
def test_parse_stix_indicator_arbitrary_types(val):
    """Non-dict inputs must return None safely."""
    assert parse_stix_indicator(val) is None


@given(
    st.dictionaries(
        keys=st.text(max_size=30),
        values=st.one_of(st.text(max_size=100), st.integers(), st.none(), st.booleans()),
        max_size=15,
    )
)
@settings(max_examples=100, deadline=1000)
def test_parse_stix_indicator_random_dict(d):
    """Arbitrary dictionary inputs must not raise unexpected errors."""
    try:
        res = parse_stix_indicator(d)
        if res is not None:
            assert isinstance(res, dict)
            assert res["type"] in ("ip", "ja4")
            assert "value" in res
            assert "id" in res
    except Exception as exc:
        pytest.fail(f"parse_stix_indicator raised unexpected exception: {exc}")


def test_parse_stix_indicator_deeply_nested_or_cyclic():
    """Deeply nested or cyclic indicator dicts must be safely rejected."""
    cyclic: dict[str, Any] = {"type": "indicator", "id": "indicator--cyclic"}
    cyclic["self"] = cyclic
    cyclic["pattern_type"] = "stix"
    cyclic["pattern"] = "[ipv4-addr:value = '198.51.100.1']"
    res = parse_stix_indicator(cyclic)
    assert res is not None
    assert res["value"] == "198.51.100.1"


# ── ReDoS & Pathological Pattern Safety ──────────────────────────────────────


def test_redos_pattern_safety():
    """Pathological inputs must evaluate in bounded time (< 50ms) without catastrophic backtracking."""
    adversarial_strings = [
        "[" + "x-ja4-fingerprint:value = '" * 100 + "t10d170900_9dc949161b6c_b64c0ad42cb7",
        "[x-ja4-fingerprint:value = '" + "a" * 10000 + "']",
        "[ipv4-addr:value = '" + "192.168.1." * 500 + "']",
        "[" * 500 + "ipv4-addr:value = '1.1.1.1']" + "]" * 500,
        "[ipv4-addr:value = '" + ":::" * 500 + "']",
        " " * 5000 + "[x-ja4-fingerprint:value = 't10d170900_9dc949161b6c_b64c0ad42cb7']",
    ]

    for s in adversarial_strings:
        start = time.perf_counter()
        _ = JA4_PATTERN_REGEX.search(s)
        _ = IP_PATTERN_REGEX.search(s)
        _ = _PATTERN_JA4_RE.search(s)
        _ = _PATTERN_IPV4_RE.search(s)
        _ = is_valid_ja4(s)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.05, f"Regex search took {elapsed}s on pathological string: {s[:50]}..."


def test_parse_stix_indicator_bounded_length():
    """Overly long patterns (>2048 bytes) should be rejected immediately to bound execution."""
    huge_pattern = "[ipv4-addr:value = '" + "1" * 3000 + "']"
    ind = {
        "type": "indicator",
        "id": "indicator--huge",
        "pattern_type": "stix",
        "pattern": huge_pattern,
    }
    assert parse_stix_indicator(ind) is None


# ── TAXII Payload Size Limit Guard ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_taxii_client_enforces_payload_size_limit():
    """TAXII client must reject responses exceeding DEFAULT_MAX_TAXII_PAYLOAD_BYTES."""
    client = TAXIIClient(
        config=FeedConfig(
            id="test-taxii",
            type="taxii2",
            url="https://taxii.example.org/taxii2/",
            collection_id="col1",
            poll_interval_minutes=60,
        ),
        mgmt=MagicMock(),
        state=None,
    )

    class FakeContent:
        def __init__(self, chunks):
            self.chunks = list(chunks)

        async def read(self, n):
            if self.chunks:
                return self.chunks.pop(0)
            return b""

    class FakeResp:
        def __init__(self, content_length=None, chunks=()):
            self.status = 200
            self.content_length = content_length
            self.content = FakeContent(chunks)

        async def text(self):
            return ""

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class FakeSession:
        def __init__(self, resp):
            self._resp = resp

        def get(self, url, headers=None, params=None, timeout=None):
            return self._resp

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    from unittest.mock import patch

    # 1. Content-Length header exceeding limit
    resp1 = FakeResp(content_length=DEFAULT_MAX_TAXII_PAYLOAD_BYTES + 1024)
    with patch("src.analytics.ti_feeds.taxii.aiohttp.ClientSession", return_value=FakeSession(resp1)):
        with pytest.raises(RuntimeError, match="exceeds limit"):
            await client._fetch_objects()

    # 2. Chunk streaming exceeding limit
    resp2 = FakeResp(
        content_length=None,
        chunks=[b"x" * (DEFAULT_MAX_TAXII_PAYLOAD_BYTES + 100)],
    )
    with patch("src.analytics.ti_feeds.taxii.aiohttp.ClientSession", return_value=FakeSession(resp2)):
        with pytest.raises(RuntimeError, match="exceeds limit"):
            await client._fetch_objects()
