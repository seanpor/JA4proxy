"""Chaos tests for Phase 14c: tarpit self-protection under failure conditions.

Acceptance criterion (PHASE_14.md §14c chaos gate):
  - Redis unavailable during background tarpit gauge update → no crash;
    in-process counter remains correct.

The tarpit counter (_tarpit_concurrent, _tarpit_per_ip) is purely in-process
and uses asyncio.Lock — no Redis calls.  The Prometheus Gauge is also
in-process.  These tests verify the isolation: even when every Redis call
raises an exception, the counter state is maintained correctly.
"""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from proxy import ProxyServer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server_stub(max_concurrent: int = 5, max_per_ip: int = 2) -> ProxyServer:
    s = object.__new__(ProxyServer)
    s.config = {
        "proxy": {
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "tarpit_host": "tarpit",
            "tarpit_port": 8888,
        },
        "tarpit": {
            "max_concurrent_connections": max_concurrent,
            "max_per_ip": max_per_ip,
            "overflow_action": "block",
        },
        "metrics": {"enabled": False},
        "logging": {"level": "INFO", "format": "%(message)s"},
        "geoip": {"country_whitelist": [], "country_blacklist": []},
    }
    s.logger = MagicMock()
    s._tarpit_concurrent = 0
    s._tarpit_per_ip = {}
    s._tarpit_lock = asyncio.Lock()

    # Redis raises on every call
    redis = MagicMock()
    redis.incr = AsyncMock(side_effect=ConnectionError("Redis down"))
    redis.decr = AsyncMock(side_effect=ConnectionError("Redis down"))
    redis.set = AsyncMock(side_effect=ConnectionError("Redis down"))
    redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
    s._redis = redis
    return s


def _writers():
    reader = MagicMock()
    reader.read = AsyncMock(return_value=b"")
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return reader, writer


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTarpitCounterIsolatedFromRedis:
    """In-process tarpit counters are unaffected by Redis availability."""

    def test_counter_incremented_and_decremented_with_redis_down(self):
        """Counter goes 0→1→0 even when Redis raises on every call."""
        server = _make_server_stub()
        reader, writer = _writers()

        # Tarpit forward also raises (simulating network failure) so we get
        # the decrement path without blocking on a real tarpit connection.
        with patch.object(
            server, "_forward_to_backend", new=AsyncMock(side_effect=OSError("network"))
        ):
            with patch("proxy._TARPIT_CONCURRENT") as mock_gauge:
                async def run():
                    # Patch the tarpit forwarding to raise immediately
                    try:
                        await server._redirect_to_tarpit(b"data", reader, writer, "1.2.3.4")
                    except Exception:
                        pass

                asyncio.run(run())

        # Counter must be back at 0 regardless of what Redis does
        assert server._tarpit_concurrent == 0
        assert "1.2.3.4" not in server._tarpit_per_ip

    def test_global_cap_enforced_without_redis(self):
        """Global cap check is in-process; Redis unavailability cannot bypass it."""
        server = _make_server_stub(max_concurrent=2)
        # Pre-fill to cap
        server._tarpit_concurrent = 2

        overflow_writer = MagicMock()
        overflow_writer.close = MagicMock()
        overflow_reader = MagicMock()
        overflow_reader.read = AsyncMock(return_value=b"")

        async def run():
            await server._redirect_to_tarpit(b"data", overflow_reader, overflow_writer, "9.9.9.9")

        asyncio.run(run())

        # Should have taken overflow_action (block → close), not incremented
        assert server._tarpit_concurrent == 2  # unchanged
        overflow_writer.close.assert_called_once()

    def test_per_ip_cap_enforced_without_redis(self):
        """Per-IP cap check is in-process; Redis errors cannot bypass it."""
        server = _make_server_stub(max_per_ip=1)
        server._tarpit_per_ip = {"5.5.5.5": 1}  # already at cap

        overflow_writer = MagicMock()
        overflow_writer.close = MagicMock()
        overflow_reader = MagicMock()
        overflow_reader.read = AsyncMock(return_value=b"")

        async def run():
            await server._redirect_to_tarpit(b"data", overflow_reader, overflow_writer, "5.5.5.5")

        asyncio.run(run())

        assert server._tarpit_per_ip.get("5.5.5.5", 0) == 1  # unchanged
        overflow_writer.close.assert_called_once()

    def test_counter_not_leaked_on_tarpit_network_error(self):
        """If the tarpit backend is unreachable, the counter is still decremented."""
        server = _make_server_stub()
        reader, writer = _writers()

        async def run():
            # Simulate tarpit host unreachable
            with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
                try:
                    await server._redirect_to_tarpit(b"data", reader, writer, "2.3.4.5")
                except Exception:
                    pass

        asyncio.run(run())

        assert server._tarpit_concurrent == 0
        assert "2.3.4.5" not in server._tarpit_per_ip

    def test_multiple_concurrent_connections_counter_correct_with_redis_down(self):
        """N concurrent tarpit connections → counter returns to 0 after all complete."""
        server = _make_server_stub(max_concurrent=10)

        async def run():
            tasks = []
            for i in range(5):
                r = MagicMock()
                r.read = AsyncMock(return_value=b"")
                w = MagicMock()
                w.close = MagicMock()
                w.wait_closed = AsyncMock()
                with patch("asyncio.open_connection", side_effect=OSError("down")):
                    tasks.append(
                        asyncio.create_task(
                            server._redirect_to_tarpit(b"x", r, w, f"10.0.0.{i}")
                        )
                    )
            # Run all tasks; swallow individual task exceptions
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results

        asyncio.run(run())

        assert server._tarpit_concurrent == 0
        assert server._tarpit_per_ip == {}
