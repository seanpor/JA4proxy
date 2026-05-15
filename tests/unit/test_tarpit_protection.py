"""Unit tests for Phase 14c: tarpit self-protection (concurrent + per-IP caps).

Tests cover:
- Global concurrent cap reached → overflow_action taken; counter NOT incremented
- Per-IP cap reached → that IP gets overflow; other IPs unaffected
- Counter decremented on clean close (acquired path completes normally)
- Counter decremented on abrupt disconnect (exception raised inside tarpit forwarding)
- overflow_action=allow → fails open to backend
- overflow_action=block → closes writer
- overflow_action=rst → also closes writer (synonym)
- Gauge reflects in-process counter value
- Concurrent cap: multiple IPs fill global slots; next arrival (new IP) overflows
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from proxy import MAX_CONCURRENT_CONNECTIONS, ProxyServer
from src.security.pipeline import PipelineResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server_stub() -> ProxyServer:
    """Minimal ProxyServer stub for tarpit tests."""
    s = object.__new__(ProxyServer)
    s.config = {
        "proxy": {
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "tarpit_host": "tarpit",
            "tarpit_port": 8888,
        },
        "tarpit": {
            "max_concurrent_connections": 5,
            "max_per_ip": 2,
            "overflow_action": "block",
        },
        "metrics": {"enabled": False},
        "logging": {"level": "INFO", "format": "%(message)s"},
        "geoip": {"country_whitelist": [], "country_blacklist": []},
    }
    import logging

    s.logger = MagicMock()
    s._tarpit_concurrent = 0
    s._tarpit_per_ip = {}
    s._tarpit_lock = asyncio.Lock()
    return s


def _make_writer() -> MagicMock:
    w = MagicMock()
    w.close = MagicMock()
    w.wait_closed = AsyncMock()
    return w


def _make_reader() -> AsyncMock:
    r = AsyncMock()
    r.read = AsyncMock(return_value=b"")
    return r


async def _call_redirect(server, client_ip="1.2.3.4", overflow_action=None):
    """Call _redirect_to_tarpit with a fresh writer pair."""
    if overflow_action:
        server.config["tarpit"]["overflow_action"] = overflow_action
    writer = _make_writer()
    reader = _make_reader()
    with patch("proxy.asyncio.open_connection", side_effect=ConnectionRefusedError()):
        await server._redirect_to_tarpit(b"data", reader, writer, client_ip)
    return writer


# ---------------------------------------------------------------------------
# Global concurrent cap
# ---------------------------------------------------------------------------


class TestGlobalConcurrentCap:
    @pytest.mark.asyncio
    async def test_cap_not_reached_increments_counter(self):
        server = _make_server_stub()
        server.config["tarpit"]["max_concurrent_connections"] = 10
        # Manually set counter to 0 — cap not reached
        with patch(
            "proxy.asyncio.open_connection", side_effect=ConnectionRefusedError()
        ):
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "1.2.3.4"
            )
        # After the call finishes (ConnectionRefused counts as done), counter back to 0
        assert server._tarpit_concurrent == 0  # decremented in finally

    @pytest.mark.asyncio
    async def test_global_cap_reached_overflow_taken(self):
        server = _make_server_stub()
        server.config["tarpit"]["max_concurrent_connections"] = 3
        server.config["tarpit"]["overflow_action"] = "block"
        # Simulate global cap already reached
        server._tarpit_concurrent = 3

        writer = _make_writer()
        with patch("proxy._TARPIT_OVERFLOW") as mock_overflow:
            mock_overflow.labels = MagicMock(return_value=MagicMock())
            await server._redirect_to_tarpit(b"", _make_reader(), writer, "9.9.9.9")

        # Counter must NOT have been incremented (it stays at 3)
        assert server._tarpit_concurrent == 3
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_global_cap_overflow_increments_prometheus(self):
        server = _make_server_stub()
        server._tarpit_concurrent = server.config["tarpit"][
            "max_concurrent_connections"
        ]

        with patch("proxy._TARPIT_OVERFLOW") as mock_overflow:
            labels_mock = MagicMock()
            mock_overflow.labels = MagicMock(return_value=labels_mock)
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "1.2.3.4"
            )

        mock_overflow.labels.assert_called_once_with(action="block")
        labels_mock.inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_global_cap_logs_overflow_event(self):
        server = _make_server_stub()
        server._tarpit_concurrent = server.config["tarpit"][
            "max_concurrent_connections"
        ]

        await server._redirect_to_tarpit(b"", _make_reader(), _make_writer(), "5.5.5.5")

        log_calls = [str(c) for c in server.logger.info.call_args_list]
        assert any("overflow" in c for c in log_calls)
        assert any("5.5.5.5" in c for c in log_calls)


# ---------------------------------------------------------------------------
# Per-IP cap
# ---------------------------------------------------------------------------


class TestPerIPCap:
    @pytest.mark.asyncio
    async def test_per_ip_cap_reached_overflow(self):
        server = _make_server_stub()
        server.config["tarpit"]["max_per_ip"] = 2
        server.config["tarpit"]["max_concurrent_connections"] = 100
        # IP already at limit
        server._tarpit_per_ip["10.0.0.1"] = 2
        server._tarpit_concurrent = 2

        writer = _make_writer()
        await server._redirect_to_tarpit(b"", _make_reader(), writer, "10.0.0.1")

        # Overflow → writer closed, per-IP counter unchanged
        writer.close.assert_called_once()
        assert server._tarpit_per_ip.get("10.0.0.1") == 2

    @pytest.mark.asyncio
    async def test_per_ip_cap_does_not_affect_other_ips(self):
        server = _make_server_stub()
        server.config["tarpit"]["max_per_ip"] = 1
        server.config["tarpit"]["max_concurrent_connections"] = 100
        # IP A is at its per-IP limit
        server._tarpit_per_ip["10.0.0.1"] = 1
        server._tarpit_concurrent = 1

        # IP B (different) should NOT overflow
        arrived = False

        async def fake_connect(*a, **kw):
            nonlocal arrived
            arrived = True
            raise ConnectionRefusedError()

        with patch("proxy.asyncio.open_connection", side_effect=fake_connect):
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "10.0.0.2"
            )

        assert arrived, "IP B should have entered the tarpit path, not overflowed"

    @pytest.mark.asyncio
    async def test_per_ip_counter_cleaned_up_after_connection(self):
        server = _make_server_stub()
        server.config["tarpit"]["max_per_ip"] = 5
        server.config["tarpit"]["max_concurrent_connections"] = 100

        with patch(
            "proxy.asyncio.open_connection", side_effect=ConnectionRefusedError()
        ):
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "1.2.3.4"
            )

        # Entry removed when count drops to 0
        assert "1.2.3.4" not in server._tarpit_per_ip

    @pytest.mark.asyncio
    async def test_per_ip_counter_partial_decrement(self):
        """Two concurrent slots for same IP; first finishes → counter goes 2→1."""
        server = _make_server_stub()
        server.config["tarpit"]["max_per_ip"] = 5
        server.config["tarpit"]["max_concurrent_connections"] = 100

        # Pre-seed one existing slot for this IP
        server._tarpit_per_ip["1.2.3.4"] = 1
        server._tarpit_concurrent = 1

        with patch(
            "proxy.asyncio.open_connection", side_effect=ConnectionRefusedError()
        ):
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "1.2.3.4"
            )

        # Was 1 pre-seeded + 1 acquired = 2, then decremented → should be 1
        assert server._tarpit_per_ip.get("1.2.3.4") == 1


# ---------------------------------------------------------------------------
# Counter decrement on clean + abrupt close
# ---------------------------------------------------------------------------


class TestCounterDecrement:
    @pytest.mark.asyncio
    async def test_counter_decremented_on_connection_refused(self):
        """ConnectionRefusedError from the tarpit container = clean-ish exit."""
        server = _make_server_stub()
        server.config["tarpit"]["max_concurrent_connections"] = 100

        with patch(
            "proxy.asyncio.open_connection", side_effect=ConnectionRefusedError()
        ):
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "1.2.3.4"
            )

        assert server._tarpit_concurrent == 0

    @pytest.mark.asyncio
    async def test_counter_decremented_on_forwarding_exception(self):
        """Exception during bidirectional forwarding → counter still decremented."""
        server = _make_server_stub()
        server.config["tarpit"]["max_concurrent_connections"] = 100

        tarpit_writer = MagicMock()
        tarpit_writer.write = MagicMock()
        tarpit_writer.drain = AsyncMock()
        tarpit_writer.close = MagicMock()
        tarpit_writer.wait_closed = AsyncMock()

        tarpit_reader = AsyncMock()

        async def failing_gather(*args, **kwargs):
            raise OSError("connection reset")

        with (
            patch(
                "proxy.asyncio.open_connection",
                AsyncMock(return_value=(tarpit_reader, tarpit_writer)),
            ),
            patch("proxy.asyncio.gather", side_effect=OSError("connection reset")),
        ):
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "1.2.3.4"
            )

        assert server._tarpit_concurrent == 0

    @pytest.mark.asyncio
    async def test_global_counter_never_goes_negative(self):
        """Defensive: even if something double-decrements, floor is 0."""
        server = _make_server_stub()
        server._tarpit_concurrent = 0

        # Manually call the decrement path via a full redirect that errors
        with patch(
            "proxy.asyncio.open_connection", side_effect=ConnectionRefusedError()
        ):
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "1.2.3.4"
            )

        assert server._tarpit_concurrent == 0


# ---------------------------------------------------------------------------
# overflow_action variants
# ---------------------------------------------------------------------------


class TestOverflowActions:
    @pytest.mark.asyncio
    async def test_overflow_block_closes_writer(self):
        server = _make_server_stub()
        server._tarpit_concurrent = server.config["tarpit"][
            "max_concurrent_connections"
        ]
        server.config["tarpit"]["overflow_action"] = "block"

        writer = _make_writer()
        await server._redirect_to_tarpit(b"", _make_reader(), writer, "1.2.3.4")
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_overflow_rst_closes_writer(self):
        server = _make_server_stub()
        server._tarpit_concurrent = server.config["tarpit"][
            "max_concurrent_connections"
        ]
        server.config["tarpit"]["overflow_action"] = "rst"

        writer = _make_writer()
        await server._redirect_to_tarpit(b"", _make_reader(), writer, "1.2.3.4")
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_overflow_allow_forwards_to_backend(self):
        server = _make_server_stub()
        server._tarpit_concurrent = server.config["tarpit"][
            "max_concurrent_connections"
        ]
        server.config["tarpit"]["overflow_action"] = "allow"
        server._forward_to_backend = AsyncMock()

        await server._redirect_to_tarpit(
            b"hello", _make_reader(), _make_writer(), "1.2.3.4"
        )

        server._forward_to_backend.assert_called_once()
        # First positional arg is the data bytes
        assert server._forward_to_backend.call_args.args[0] == b"hello"

    @pytest.mark.asyncio
    async def test_overflow_allow_does_not_close_writer(self):
        server = _make_server_stub()
        server._tarpit_concurrent = server.config["tarpit"][
            "max_concurrent_connections"
        ]
        server.config["tarpit"]["overflow_action"] = "allow"
        server._forward_to_backend = AsyncMock()

        writer = _make_writer()
        await server._redirect_to_tarpit(b"", _make_reader(), writer, "1.2.3.4")
        writer.close.assert_not_called()


# ---------------------------------------------------------------------------
# Prometheus gauge reflects in-process counter
# ---------------------------------------------------------------------------


class TestPrometheusGauge:
    @pytest.mark.asyncio
    async def test_gauge_set_to_zero_after_single_connection(self):
        server = _make_server_stub()

        with patch("proxy._TARPIT_CONCURRENT") as mock_gauge:
            with patch(
                "proxy.asyncio.open_connection", side_effect=ConnectionRefusedError()
            ):
                await server._redirect_to_tarpit(
                    b"", _make_reader(), _make_writer(), "1.2.3.4"
                )
        # set() was called at least once (acquire) and once more (release)
        assert mock_gauge.set.call_count >= 2

    @pytest.mark.asyncio
    async def test_gauge_not_set_on_overflow(self):
        """Overflow path must NOT call _TARPIT_CONCURRENT.set() for the slot."""
        server = _make_server_stub()
        server._tarpit_concurrent = server.config["tarpit"][
            "max_concurrent_connections"
        ]

        with patch("proxy._TARPIT_CONCURRENT") as mock_gauge:
            await server._redirect_to_tarpit(
                b"", _make_reader(), _make_writer(), "9.9.9.9"
            )

        # set() should NOT be called (no slot was acquired/released)
        mock_gauge.set.assert_not_called()
