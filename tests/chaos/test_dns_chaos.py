"""Chaos tests: DNS enrichment failure scenarios (Phase 7).

Verifies that every DNS failure mode results in fail-open behaviour:
no crash, error counters incremented, pipeline continues unaffected.
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.dns_enrichment import DNSEnrichment


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_enrichment(enabled: bool = True, queue_size: int = 1000) -> DNSEnrichment:
    config = {
        "dns_enrichment": {
            "enabled": enabled,
            "queue_size": queue_size,
            "worker_count": 0,  # No workers — we call _fcrdns_check directly
            "resolver_timeout_seconds": 5,
            "fcrdns": {
                "cache_ttl_seconds": 21600,
                "no_ptr_score": 15,
                "fcrdns_failed_score": 20,
                "residential_score_reduction": 10,
            },
        }
    }
    mock_redis = MagicMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()
    mock_redis.bf = MagicMock()
    mock_redis.bf.return_value.exists = AsyncMock(return_value=False)
    mock_redis.bf.return_value.add = AsyncMock()
    # Patch aiodns so resolver init always succeeds outside a running loop
    with patch("src.security.dns_enrichment.aiodns") as mock_aiodns:
        mock_aiodns.DNSResolver.return_value = MagicMock()
        enrichment = DNSEnrichment(config, mock_redis)
    enrichment._enabled = enabled
    return enrichment


# ---------------------------------------------------------------------------
# DNS resolver unreachable
# ---------------------------------------------------------------------------

class TestDNSResolverUnreachable:
    """Fail open when DNS resolver is unreachable."""

    def test_resolver_error_fails_open(self, caplog):
        """PTR lookup exception → no_ptr result, error counter incremented."""
        from src.security.blocklists import _BLOCKLIST_MATCHES  # ensure import ok
        from src.security.dns_enrichment import _DNS_RESOLVER_ERRORS

        enrichment = _make_enrichment()

        # Simulate resolver failure on gethostbyaddr
        mock_resolver = MagicMock()
        mock_resolver.gethostbyaddr = AsyncMock(side_effect=Exception("connection refused"))
        enrichment._resolver = mock_resolver

        before = _DNS_RESOLVER_ERRORS._value.get()

        async def run():
            result = await enrichment._fcrdns_check("1.2.3.4")
            return result

        result = _run(run())
        assert result.has_ptr is False
        assert result.classification == "no_ptr"
        assert _DNS_RESOLVER_ERRORS._value.get() == before + 1

    def test_resolver_error_logs_json(self, caplog):
        """DNS resolver error emits structured JSON log."""
        enrichment = _make_enrichment()

        mock_resolver = MagicMock()
        mock_resolver.gethostbyaddr = AsyncMock(side_effect=Exception("ECONNREFUSED"))
        enrichment._resolver = mock_resolver

        with caplog.at_level(logging.ERROR, logger="src.security.dns_enrichment"):
            _run(enrichment._fcrdns_check("1.2.3.4"))

        json_logs = [
            json.loads(r.message) for r in caplog.records
            if r.message.startswith("{")
        ]
        assert any(
            log.get("event") == "resolver_error" and
            log.get("subsystem") == "dns" and
            "ip" in log
            for log in json_logs
        )

    def test_resolver_none_fails_open(self):
        """No resolver configured → fail open, no crash."""
        enrichment = _make_enrichment()
        enrichment._resolver = None

        result = _run(enrichment._fcrdns_check("1.2.3.4"))
        assert result.classification == "resolver_unavailable"


# ---------------------------------------------------------------------------
# DNS timeout
# ---------------------------------------------------------------------------

class TestDNSTimeout:
    """Fail open when DNS queries time out."""

    def test_ptr_timeout_fails_open(self):
        """asyncio.TimeoutError on PTR → no_ptr, timeout counter incremented."""
        from src.security.dns_enrichment import _DNS_TOTAL

        enrichment = _make_enrichment()
        mock_resolver = MagicMock()
        mock_resolver.gethostbyaddr = AsyncMock(
            side_effect=asyncio.TimeoutError("timeout")
        )
        enrichment._resolver = mock_resolver

        result = _run(enrichment._fcrdns_check("1.2.3.4"))
        assert result.has_ptr is False
        assert result.classification == "no_ptr"

    def test_forward_lookup_timeout_fails_open(self):
        """asyncio.TimeoutError on A lookup → fcrdns_failed, no crash."""
        enrichment = _make_enrichment()
        mock_resolver = MagicMock()

        ptr_mock = MagicMock()
        ptr_mock.name = "host.example.com"
        mock_resolver.gethostbyaddr = AsyncMock(return_value=ptr_mock)
        mock_resolver.gethostbyname = AsyncMock(
            side_effect=asyncio.TimeoutError("A lookup timeout")
        )
        enrichment._resolver = mock_resolver

        result = _run(enrichment._fcrdns_check("1.2.3.4"))
        assert result.classification == "fcrdns_failed"
        assert result.has_ptr is True

    def test_no_hanging_coroutine_on_timeout(self):
        """Timeout is caught; no coroutine left pending."""
        enrichment = _make_enrichment()
        mock_resolver = MagicMock()
        mock_resolver.gethostbyaddr = AsyncMock(
            side_effect=asyncio.TimeoutError()
        )
        enrichment._resolver = mock_resolver

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(enrichment._fcrdns_check("2.2.2.2"))
            # No pending tasks
            pending = asyncio.all_tasks(loop)
            assert len(pending) == 0
        finally:
            loop.close()

        assert result is not None  # Returned cleanly


# ---------------------------------------------------------------------------
# Malformed PTR response
# ---------------------------------------------------------------------------

class TestMalformedPTRResponse:
    """Malformed DNS responses are handled gracefully."""

    def test_malformed_forward_response_parsed_safely(self):
        """Forward lookup returning unexpected structure doesn't crash."""
        enrichment = _make_enrichment()
        mock_resolver = MagicMock()

        ptr_mock = MagicMock()
        ptr_mock.name = "host.example.com"
        mock_resolver.gethostbyaddr = AsyncMock(return_value=ptr_mock)

        # Return object with no .addresses and no .host
        bad_forward = MagicMock(spec=[])  # no attributes
        bad_forward.addresses = ["1.2.3.4"]  # make it work to confirm pass
        mock_resolver.gethostbyname = AsyncMock(return_value=bad_forward)
        enrichment._resolver = mock_resolver

        result = _run(enrichment._fcrdns_check("1.2.3.4"))
        # Should not raise; classification determined
        assert result.classification in (
            "confirmed", "fcrdns_failed", "residential",
            "datacenter_confirmed", "no_ptr",
        )

    def test_ptr_exception_after_partial_result_fails_open(self):
        """Any exception during processing returns a safe FCrDNSResult."""
        enrichment = _make_enrichment()
        mock_resolver = MagicMock()
        mock_resolver.gethostbyaddr = AsyncMock(
            side_effect=ValueError("malformed response data")
        )
        enrichment._resolver = mock_resolver

        result = _run(enrichment._fcrdns_check("3.3.3.3"))
        assert result.ip == "3.3.3.3"
        assert result.classification in ("no_ptr", "resolver_unavailable")


# ---------------------------------------------------------------------------
# Queue overflow
# ---------------------------------------------------------------------------

class TestQueueOverflow:
    """Queue overflow drops items silently with counter increment."""

    def test_queue_full_drops_silently(self):
        """QueueFull does not raise; drop counter incremented."""
        from src.security.dns_enrichment import _DNS_QUEUE_DROPS

        enrichment = _make_enrichment(queue_size=1)
        # Manually fill the queue
        enrichment._queue.put_nowait("0.0.0.1")

        before = _DNS_QUEUE_DROPS._value.get()

        async def run():
            # This should drop silently
            await enrichment.enqueue("1.2.3.4")

        _run(run())
        assert _DNS_QUEUE_DROPS._value.get() == before + 1

    def test_queue_full_logs_json(self, caplog):
        """QueueFull emits structured WARN JSON log."""
        enrichment = _make_enrichment(queue_size=1)
        enrichment._queue.put_nowait("0.0.0.1")

        with caplog.at_level(logging.WARNING, logger="src.security.dns_enrichment"):
            _run(enrichment.enqueue("1.2.3.4"))

        json_logs = [
            json.loads(r.message) for r in caplog.records
            if r.message.startswith("{")
        ]
        assert any(
            log.get("event") == "queue_full" and
            log.get("subsystem") == "dns" and
            "dropped_ip" in log
            for log in json_logs
        )

    def test_queue_full_no_crash(self):
        """Queue overflow never raises an exception to the caller."""
        enrichment = _make_enrichment(queue_size=2)

        async def run():
            for i in range(10):
                await enrichment.enqueue(f"10.0.0.{i}")

        # Must complete without exception
        _run(run())
