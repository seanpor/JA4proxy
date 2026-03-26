"""Unit tests for Phase 14b: graceful SIGTERM shutdown and drain logic.

Tests cover:
- start() with no shutdown_event runs until externally cancelled (unchanged behaviour)
- SIGTERM with 0 active connections → drain loop skipped; shutdown_complete logged
- SIGTERM with connections that finish before timeout → all drained; forced_close=0
- Drain timeout exceeded with stuck connections → forced_close > 0 in log
- shutdown_initiated log includes the correct active_connections count at the moment
  shutdown was triggered
- Partial drain: some connections finish, some are forced; log counts correct
"""

import asyncio
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from proxy import MAX_CONCURRENT_CONNECTIONS, ProxyServer
from src.security.pipeline import PipelineResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server_stub(drain_timeout: float = 1.0) -> ProxyServer:
    """Minimal ProxyServer stub for shutdown tests.

    Uses object.__new__ to bypass __init__.  The drain_timeout is set short
    so tests don't actually wait 30 s.
    """
    s = object.__new__(ProxyServer)
    s.config = {
        "proxy": {
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "drain_timeout_seconds": drain_timeout,
        },
        "metrics": {"enabled": False},
        "logging": {"level": "INFO", "format": "%(message)s"},
        "geoip": {"country_whitelist": [], "country_blacklist": []},
    }
    s.logger = MagicMock()
    s.redis_client = MagicMock()
    s.active_connections = 0
    s._dial_manager = MagicMock()
    s._dial_manager.initialize = MagicMock(return_value=0)
    s._local_cache = MagicMock()
    s._local_cache.dial = 0
    s._abuseipdb_checker = None
    s._rdap_enricher = None
    s._aiohttp_session = None
    s._backup_scheduler = None
    return s


def _make_asyncio_server_mock():
    """Return a mock asyncio.Server whose serve_forever() blocks until close() is called."""
    close_event = asyncio.Event()

    mock_srv = MagicMock()

    async def _serve_forever():
        await close_event.wait()

    mock_srv.serve_forever = _serve_forever
    mock_srv.close = lambda: close_event.set()
    mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
    mock_srv.__aexit__ = AsyncMock(return_value=False)
    return mock_srv


def _shutdown_initiated_call(server):
    """Return the logger.info call_args for the shutdown_initiated event, or None."""
    for c in server.logger.info.call_args_list:
        if "shutdown_initiated" in str(c):
            return c
    return None


def _shutdown_complete_call(server):
    """Return the logger.info call_args for the shutdown_complete event, or None."""
    for c in server.logger.info.call_args_list:
        if "shutdown_complete" in str(c):
            return c
    return None


# ---------------------------------------------------------------------------
# No shutdown_event: unchanged behaviour
# ---------------------------------------------------------------------------


class TestNoShutdownEvent:
    @pytest.mark.asyncio
    async def test_cancelled_error_propagates_without_drain(self):
        """start(shutdown_event=None) propagates CancelledError unchanged."""
        server = _make_server_stub()
        mock_srv = AsyncMock()
        mock_srv.serve_forever = AsyncMock(side_effect=asyncio.CancelledError())
        mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
        mock_srv.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            with pytest.raises(asyncio.CancelledError):
                await server.start()  # no shutdown_event

        # Drain log lines must NOT appear — shutdown_event was None
        assert _shutdown_initiated_call(server) is None
        assert _shutdown_complete_call(server) is None

    @pytest.mark.asyncio
    async def test_serve_forever_exception_propagates(self):
        """An unexpected exception from serve_forever propagates as-is."""
        server = _make_server_stub()
        mock_srv = AsyncMock()
        mock_srv.serve_forever = AsyncMock(side_effect=RuntimeError("bang"))
        mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
        mock_srv.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            with pytest.raises(RuntimeError, match="bang"):
                await server.start()


# ---------------------------------------------------------------------------
# With shutdown_event: drain logic
# ---------------------------------------------------------------------------


class TestGracefulShutdownDrain:
    @pytest.mark.asyncio
    async def test_zero_connections_exits_cleanly(self):
        """SIGTERM with 0 active connections: drain loop is skipped entirely."""
        server = _make_server_stub(drain_timeout=1.0)
        server.active_connections = 0

        shutdown_event = asyncio.Event()
        mock_srv = _make_asyncio_server_mock()

        async def _trigger():
            await asyncio.sleep(0.01)
            shutdown_event.set()

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            asyncio.create_task(_trigger())
            await server.start(shutdown_event=shutdown_event)

        # Both log lines must be present
        assert _shutdown_initiated_call(server) is not None
        complete = _shutdown_complete_call(server)
        assert complete is not None

        # drained=0, forced_close=0
        assert complete.args[1] == 0  # drained
        assert complete.args[2] == 0  # forced_close

    @pytest.mark.asyncio
    async def test_connections_drain_before_timeout(self):
        """Connections that finish inside the window → forced_close=0."""
        server = _make_server_stub(drain_timeout=2.0)
        server.active_connections = 4

        shutdown_event = asyncio.Event()
        mock_srv = _make_asyncio_server_mock()

        async def _trigger():
            await asyncio.sleep(0.01)
            shutdown_event.set()

        async def _connections_complete():
            await asyncio.sleep(0.05)
            server.active_connections = 0

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            asyncio.create_task(_trigger())
            asyncio.create_task(_connections_complete())
            await server.start(shutdown_event=shutdown_event)

        complete = _shutdown_complete_call(server)
        assert complete is not None
        assert complete.args[1] == 4  # drained
        assert complete.args[2] == 0  # forced_close

    @pytest.mark.asyncio
    async def test_drain_timeout_exceeded_reports_forced_close(self):
        """Connections still open after timeout: forced_close equals the stuck count."""
        server = _make_server_stub(drain_timeout=0.05)  # 50 ms
        server.active_connections = 5  # will never finish

        shutdown_event = asyncio.Event()
        mock_srv = _make_asyncio_server_mock()

        async def _trigger():
            await asyncio.sleep(0.01)
            shutdown_event.set()

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            asyncio.create_task(_trigger())
            await server.start(shutdown_event=shutdown_event)

        complete = _shutdown_complete_call(server)
        assert complete is not None
        assert complete.args[1] == 0  # drained
        assert complete.args[2] == 5  # forced_close

    @pytest.mark.asyncio
    async def test_partial_drain_logs_correct_split(self):
        """Some finish before timeout; the rest are forced — log counts must match."""
        server = _make_server_stub(drain_timeout=0.20)
        server.active_connections = 10

        shutdown_event = asyncio.Event()
        mock_srv = _make_asyncio_server_mock()

        async def _trigger():
            await asyncio.sleep(0.01)
            shutdown_event.set()

        async def _partial_drain():
            await asyncio.sleep(0.05)
            server.active_connections = 3  # 7 drained, 3 stuck

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            asyncio.create_task(_trigger())
            asyncio.create_task(_partial_drain())
            await server.start(shutdown_event=shutdown_event)

        complete = _shutdown_complete_call(server)
        assert complete is not None
        assert complete.args[1] == 7  # drained
        assert complete.args[2] == 3  # forced_close

    @pytest.mark.asyncio
    async def test_shutdown_initiated_log_includes_connection_count(self):
        """shutdown_initiated must capture the active_connections count at shutdown time."""
        server = _make_server_stub(drain_timeout=2.0)
        server.active_connections = 7

        shutdown_event = asyncio.Event()
        mock_srv = _make_asyncio_server_mock()

        async def _trigger():
            await asyncio.sleep(0.01)
            shutdown_event.set()
            # Connections finish after the snapshot is taken
            await asyncio.sleep(0.01)
            server.active_connections = 0

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            asyncio.create_task(_trigger())
            await server.start(shutdown_event=shutdown_event)

        initiated = _shutdown_initiated_call(server)
        assert initiated is not None
        # The count logged must be 7 (the value at shutdown moment)
        assert initiated.args[1] == 7

    @pytest.mark.asyncio
    async def test_shutdown_event_not_set_no_drain_logs(self):
        """If shutdown_event exists but was never set (CancelledError path), no drain logs."""
        server = _make_server_stub(drain_timeout=1.0)
        server.active_connections = 2

        shutdown_event = asyncio.Event()  # never set
        mock_srv = AsyncMock()
        mock_srv.serve_forever = AsyncMock(side_effect=asyncio.CancelledError())
        mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
        mock_srv.__aexit__ = AsyncMock(return_value=False)

        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            with pytest.raises(asyncio.CancelledError):
                await server.start(shutdown_event=shutdown_event)

        # shutdown_event was not set → drain block skipped
        assert _shutdown_initiated_call(server) is None
        assert _shutdown_complete_call(server) is None
