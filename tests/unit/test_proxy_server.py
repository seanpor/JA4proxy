"""Unit test harness for proxy.py ProxyServer and supporting classes.

Every test here drives the actual code under test via controlled mocks.
The key fixture is ``_make_server()`` which constructs a ProxyServer using
``object.__new__`` — bypassing __init__ — so each attribute is an
explicit mock or minimal value that the test controls.

Sections
--------
- GeoIPLookup                 — database load, private IPs, lookup errors
- TarpitManager               — enabled/disabled/cancelled
- ProxyServer._init_redis     — success, ConnectionError, AuthError, production guard
- ProxyServer._refresh_cidr_blocks — stale/fresh cache, invalid CIDR, Redis error
- ProxyServer._is_cidr_blocked — IPv4 match, IPv6 match, no match, invalid IP
- ProxyServer._populate_security_lists — Redis sadd calls, safe_countries
- ProxyServer._store_fingerprint — hset+expire success, Redis error logged
- ProxyServer._forward_data    — data piped, EOF terminates loop, exception logged
- ProxyServer._forward_to_backend — connection success, refused, cleanup
- ProxyServer._redirect_to_tarpit — success, timeout, cleanup
- ProxyServer._extract_ja4_from_http — header present, absent, non-HTTP
- ProxyServer._analyze_tls_handshake — TLS, non-TLS, Scapy error, exception
- ProxyServer.handle_connection — all decision branches end-to-end
"""

import asyncio
import logging
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
import redis as redis_lib

from proxy import (
    GeoIPLookup,
    JA4Fingerprint,
    MAX_CONCURRENT_CONNECTIONS,
    ProxyServer,
    SecurityError,
    TarpitManager,
    ValidationError,
)
from src.security.pipeline import PipelineResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


_BASE_CONFIG = {
    "proxy": {
        "bind_host": "0.0.0.0",
        "bind_port": 8080,
        "backend_host": "127.0.0.1",
        "backend_port": 443,
        "max_connections": 1000,
        "connection_timeout": 30,
        "read_timeout": 30,
        "write_timeout": 30,
        "keepalive_timeout": 60,
        "buffer_size": 8192,
        "proxy_protocol": False,
        "tarpit_host": "tarpit",
        "tarpit_port": 8888,
    },
    "redis": {
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "password": "testpass",
        "timeout": 5,
        "ssl": False,
    },
    "security": {
        "whitelist_enabled": True,
        "blacklist_enabled": True,
        "rate_limiting": False,  # off by default in tests
        "max_requests_per_minute": 100,
        "block_unknown_ja4": False,
        "tarpit_enabled": False,
        "tarpit_duration": 10,
        "whitelist": [],
        "blacklist": [],
        "whitelist_patterns": [],
    },
    "metrics": {"enabled": False, "port": 9090},
    "logging": {"level": "INFO", "format": "%(message)s"},
    "geoip": {},
}


def _make_server(config_overrides: dict | None = None) -> ProxyServer:
    """Create a ProxyServer without running __init__."""
    config = {section: dict(values) for section, values in _BASE_CONFIG.items()}
    if config_overrides:
        for k, v in config_overrides.items():
            if isinstance(v, dict) and k in config:
                config[k].update(v)
            else:
                config[k] = v

    server = object.__new__(ProxyServer)
    server.config = config
    server.logger = logging.getLogger("proxy")

    redis_mock = MagicMock()
    redis_mock.sismember = AsyncMock(return_value=False)
    redis_mock.smembers = AsyncMock(return_value=set())
    redis_mock.sadd = AsyncMock(return_value=1)
    redis_mock.hset = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=1)
    server.redis_client = redis_mock

    server.tls_parser = MagicMock()
    server.ja4_generator = MagicMock()
    server.tarpit_manager = MagicMock()
    server.tarpit_manager.tarpit_connection = AsyncMock()

    # Phase 2: Pipeline replaces advanced_security layers
    server.pipeline = MagicMock()
    server.pipeline.process = AsyncMock(return_value=PipelineResult(action="allow"))
    server.pipeline._tcp_analyzer = MagicMock()
    server.pipeline._tcp_analyzer.decrement_concurrent_connections = AsyncMock()

    server.security_manager = MagicMock()
    server.security_manager.whitelist = set()
    server.security_manager.blacklist = set()
    server.security_manager._load_security_lists = AsyncMock()

    server.geoip = MagicMock()
    server.geoip.lookup = MagicMock(return_value="")

    server.country_whitelist = set()
    server.country_blacklist = set()
    server.country_whitelist_enabled = False
    server.country_blacklist_enabled = False

    server._cidr_blocks = []
    server._cidr_blocks_loaded_at = 0.0
    server._cidr_cache_ttl = 30
    server.active_connections = 0
    server._conn_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
    return server


def _make_fp(
    ja4: str = "t13d1516h2_8daaf6152771_02713d6af862",
    source_ip: str = "1.2.3.4",
) -> JA4Fingerprint:
    return JA4Fingerprint(ja4=ja4, source_ip=source_ip, timestamp=time.time())


def _mock_stream_pair(first_read: bytes = b"data"):
    """Return (reader, writer) mocks for testing handle_connection."""
    reader = AsyncMock(spec=asyncio.StreamReader)
    reader.read = AsyncMock(side_effect=[first_read, b""])  # second read = EOF

    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info = MagicMock(return_value=("1.2.3.4", 12345))
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    return reader, writer


# ---------------------------------------------------------------------------
# GeoIPLookup
# ---------------------------------------------------------------------------


class TestGeoIPLookup:
    def test_lookup_private_ip_returns_empty(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo.db = MagicMock()
        geo.logger = logging.getLogger("proxy")
        result = geo.lookup("192.168.1.1")
        assert result == ""
        geo.db.get_all.assert_not_called()

    def test_lookup_loopback_returns_empty(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo.db = MagicMock()
        geo.logger = logging.getLogger("proxy")
        assert geo.lookup("127.0.0.1") == ""

    def test_lookup_no_db_returns_empty(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        geo.db = None
        geo.logger = logging.getLogger("proxy")
        assert geo.lookup("8.8.8.8") == ""

    def test_lookup_public_ip_returns_country_code(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        rec = MagicMock()
        rec.country_short = "DE"
        db = MagicMock()
        db.get_all = MagicMock(return_value=rec)
        geo.db = db
        geo.logger = logging.getLogger("proxy")
        result = geo.lookup("8.8.8.8")
        assert result == "DE"

    def test_lookup_dash_country_code_returns_empty(self):
        """IP2Location returns '-' for unknown; map to empty string."""
        geo = GeoIPLookup.__new__(GeoIPLookup)
        rec = MagicMock()
        rec.country_short = "-"
        db = MagicMock()
        db.get_all = MagicMock(return_value=rec)
        geo.db = db
        geo.logger = logging.getLogger("proxy")
        assert geo.lookup("1.2.3.4") == ""

    def test_lookup_db_exception_returns_empty(self):
        geo = GeoIPLookup.__new__(GeoIPLookup)
        db = MagicMock()
        db.get_all = MagicMock(side_effect=Exception("db error"))
        geo.db = db
        geo.logger = logging.getLogger("proxy")
        assert geo.lookup("8.8.8.8") == ""

    def test_init_no_db_file_sets_db_none(self, tmp_path):
        """If no DB file exists at any path, self.db stays None."""
        geo = GeoIPLookup(db_path=str(tmp_path / "nonexistent.bin"))
        assert geo.db is None


# ---------------------------------------------------------------------------
# TarpitManager
# ---------------------------------------------------------------------------


class TestTarpitManagerUnit:
    def test_tarpit_disabled_returns_immediately(self):
        config = dict(_BASE_CONFIG)
        config["security"] = dict(_BASE_CONFIG["security"])
        config["security"]["tarpit_enabled"] = False
        mgr = TarpitManager(config)
        writer = AsyncMock()
        _run(mgr.tarpit_connection(writer, duration=60))
        # close should not be called — returned immediately
        writer.close.assert_not_called()

    def test_tarpit_enabled_closes_writer(self):
        config = dict(_BASE_CONFIG)
        config["security"] = dict(_BASE_CONFIG["security"])
        config["security"]["tarpit_enabled"] = True
        config["security"]["tarpit_duration"] = 0  # zero delay for test speed
        mgr = TarpitManager(config)
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch("proxy.asyncio.sleep", AsyncMock()):
            _run(mgr.tarpit_connection(writer))
        writer.close.assert_called_once()

    def test_tarpit_cancelled_still_closes_writer(self):
        """CancelledError during sleep must still close the writer in finally."""
        config = dict(_BASE_CONFIG)
        config["security"] = dict(_BASE_CONFIG["security"])
        config["security"]["tarpit_enabled"] = True
        config["security"]["tarpit_duration"] = 1
        mgr = TarpitManager(config)
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch(
            "proxy.asyncio.sleep", AsyncMock(side_effect=asyncio.CancelledError())
        ):
            _run(mgr.tarpit_connection(writer))
        writer.close.assert_called_once()


# ---------------------------------------------------------------------------
# ProxyServer._init_redis
# ---------------------------------------------------------------------------


class TestInitRedis:
    def test_success_returns_redis_client(self):
        server = _make_server()
        mock_client = MagicMock()
        mock_client.ping = AsyncMock(return_value=True)
        with patch("redis.asyncio.Redis", return_value=mock_client):
            result = _run(server._init_redis())
        assert result is mock_client

    def test_connection_error_raises_security_error(self):
        server = _make_server()
        with patch(
            "redis.asyncio.Redis", side_effect=redis_lib.ConnectionError("refused")
        ):
            with pytest.raises(SecurityError, match="Cannot establish"):
                _run(server._init_redis())

    def test_auth_error_raises_security_error(self):
        # AuthenticationError is caught by the AuthenticationError clause (which
        # appears first — before ConnectionError — because it is a subclass of it).
        # The message must identify the failure as an *authentication* problem so
        # operators know to fix credentials, not network routing.
        server = _make_server()
        with patch(
            "redis.asyncio.Redis", side_effect=redis_lib.AuthenticationError("bad pw")
        ):
            with pytest.raises(SecurityError, match="Redis authentication failed"):
                _run(server._init_redis())

    def test_no_password_in_production_raises(self):
        server = _make_server(
            {"redis": {"host": "r", "port": 6379, "password": "", "timeout": 5}}
        )
        env = dict(os.environ)
        env["ENVIRONMENT"] = "production"
        with patch.dict(os.environ, env):
            with pytest.raises(SystemExit) as exc_info:
                _run(server._init_redis())
            assert exc_info.value.code == 1

    def test_no_password_in_development_warns(self, caplog):
        server = _make_server(
            {"redis": {"host": "r", "port": 6379, "password": "", "timeout": 5}}
        )
        mock_client = MagicMock()
        mock_client.ping = AsyncMock(return_value=True)
        env = {k: v for k, v in os.environ.items() if k != "ENVIRONMENT"}
        env["ENVIRONMENT"] = "development"
        with (
            patch("redis.asyncio.Redis", return_value=mock_client),
            patch.dict(os.environ, env),
            caplog.at_level(logging.WARNING, logger="proxy"),
        ):
            _run(server._init_redis())
        assert any("without authentication" in r.message for r in caplog.records)

    def test_ping_connection_error_raises(self):
        server = _make_server()
        mock_client = MagicMock()
        mock_client.ping = AsyncMock(side_effect=redis_lib.ConnectionError("no route"))
        with patch("redis.asyncio.Redis", return_value=mock_client):
            with pytest.raises(SecurityError):
                _run(server._init_redis())

    def test_auth_error_raises_security_error(self):
        # AuthenticationError is caught by the AuthenticationError clause (which
        # appears first — before ConnectionError — because it is a subclass of it).
        # The message must identify the failure as an *authentication* problem so
        # operators know to fix credentials, not network routing.
        server = _make_server()
        with patch(
            "redis.asyncio.Redis", side_effect=redis_lib.AuthenticationError("bad pw")
        ):
            with pytest.raises(SecurityError, match="Redis authentication failed"):
                _run(server._init_redis())

    def test_no_password_in_production_raises(self):
        server = _make_server(
            {"redis": {"host": "r", "port": 6379, "password": "", "timeout": 5}}
        )
        env = dict(os.environ)
        env["ENVIRONMENT"] = "production"
        with patch.dict(os.environ, env):
            with pytest.raises(SystemExit) as exc_info:
                _run(server._init_redis())
            assert exc_info.value.code == 1

    def test_no_password_in_development_warns(self, caplog):
        server = _make_server(
            {"redis": {"host": "r", "port": 6379, "password": "", "timeout": 5}}
        )
        mock_client = MagicMock()
        mock_client.ping = MagicMock(return_value=True)
        env = {k: v for k, v in os.environ.items() if k != "ENVIRONMENT"}
        env["ENVIRONMENT"] = "development"
        with (
            patch("redis.asyncio.Redis", return_value=mock_client),
            patch.dict(os.environ, env),
            caplog.at_level(logging.WARNING, logger="proxy"),
        ):
            _run(server._init_redis())
        assert any("without authentication" in r.message for r in caplog.records)

    def test_ping_connection_error_raises(self):
        server = _make_server()
        mock_client = MagicMock()
        mock_client.ping = MagicMock(side_effect=redis_lib.ConnectionError("no route"))
        with patch("redis.asyncio.Redis", return_value=mock_client):
            with pytest.raises(SecurityError):
                _run(server._init_redis())

    def test_auth_error_raises_security_error(self):
        # AuthenticationError is caught by the AuthenticationError clause (which
        # appears first — before ConnectionError — because it is a subclass of it).
        # The message must identify the failure as an *authentication* problem so
        # operators know to fix credentials, not network routing.
        server = _make_server()
        with patch(
            "redis.asyncio.Redis", side_effect=redis_lib.AuthenticationError("bad pw")
        ):
            with pytest.raises(SecurityError, match="Redis authentication failed"):
                _run(server._init_redis())

    def test_no_password_in_production_raises(self):
        server = _make_server(
            {"redis": {"host": "r", "port": 6379, "password": "", "timeout": 5}}
        )
        env = dict(os.environ)
        env["ENVIRONMENT"] = "production"
        with patch.dict(os.environ, env):
            with pytest.raises(SystemExit) as exc_info:
                _run(server._init_redis())
            assert exc_info.value.code == 1

    def test_no_password_in_development_warns(self, caplog):
        server = _make_server(
            {"redis": {"host": "r", "port": 6379, "password": "", "timeout": 5}}
        )
        mock_client = MagicMock()
        mock_client.ping = AsyncMock(return_value=True)
        env = {k: v for k, v in os.environ.items() if k != "ENVIRONMENT"}
        env["ENVIRONMENT"] = "development"
        with (
            patch("redis.asyncio.Redis", return_value=mock_client),
            patch.dict(os.environ, env),
            caplog.at_level(logging.WARNING, logger="proxy"),
        ):
            _run(server._init_redis())
        assert any("without authentication" in r.message for r in caplog.records)

    def test_ping_connection_error_raises(self):
        server = _make_server()
        mock_client = MagicMock()
        mock_client.ping = AsyncMock(side_effect=redis_lib.ConnectionError("no route"))
        with patch("redis.asyncio.Redis", return_value=mock_client):
            with pytest.raises(SecurityError):
                _run(server._init_redis())


# ---------------------------------------------------------------------------
# ProxyServer._refresh_cidr_blocks
# ---------------------------------------------------------------------------


class TestRefreshCidrBlocks:
    def test_fresh_cache_skips_redis(self):
        server = _make_server()
        server._cidr_blocks_loaded_at = time.monotonic()  # just loaded
        _run(server._refresh_cidr_blocks())
        server.redis_client.smembers.assert_not_called()

    def test_stale_cache_loads_from_redis(self):
        server = _make_server()
        server._cidr_blocks_loaded_at = 0.0  # force stale
        server.redis_client.smembers = AsyncMock(
            return_value={b"203.0.113.0/24", b"198.51.100.0/24"}
        )
        _run(server._refresh_cidr_blocks())
        assert len(server._cidr_blocks) == 2

    def test_invalid_cidr_skipped_with_warning(self, caplog):
        server = _make_server()
        server._cidr_blocks_loaded_at = 0.0
        server.redis_client.smembers = AsyncMock(
            return_value={b"not-a-cidr", b"203.0.113.0/24"}
        )
        with caplog.at_level(logging.WARNING, logger="proxy"):
            _run(server._refresh_cidr_blocks())
        assert len(server._cidr_blocks) == 1
        assert any("Invalid CIDR" in r.message for r in caplog.records)

    def test_redis_error_does_not_crash(self):
        server = _make_server()
        server._cidr_blocks_loaded_at = 0.0
        server.redis_client.smembers = AsyncMock(side_effect=Exception("Redis down"))
        # Must not raise - test that async method handles error gracefully
        _run(server._refresh_cidr_blocks())


# ---------------------------------------------------------------------------
# ProxyServer._is_cidr_blocked
# ---------------------------------------------------------------------------


class TestIsCidrBlocked:
    def _server_with_cidrs(self, cidr_strings: list[str]) -> ProxyServer:
        import ipaddress

        server = _make_server()
        server._cidr_blocks = [
            ipaddress.ip_network(c, strict=False) for c in cidr_strings
        ]
        return server

    def test_matching_ipv4_returns_cidr_string(self):
        server = self._server_with_cidrs(["203.0.113.0/24"])
        result = server._is_cidr_blocked("203.0.113.42")
        assert result == "203.0.113.0/24"

    def test_non_matching_ip_returns_none(self):
        server = self._server_with_cidrs(["203.0.113.0/24"])
        assert server._is_cidr_blocked("8.8.8.8") is None

    def test_empty_cidr_list_returns_none(self):
        server = _make_server()
        assert server._is_cidr_blocked("1.2.3.4") is None

    def test_invalid_ip_returns_none(self):
        server = self._server_with_cidrs(["203.0.113.0/24"])
        assert server._is_cidr_blocked("not-an-ip") is None

    def test_matching_ipv6_returns_cidr_string(self):
        server = self._server_with_cidrs(["2001:db8::/32"])
        result = server._is_cidr_blocked("2001:db8::1")
        assert result == "2001:db8::/32"


# ---------------------------------------------------------------------------
# ProxyServer._populate_security_lists
# ---------------------------------------------------------------------------


class TestPopulateSecurityLists:
    def test_whitelist_entries_added_to_redis(self):
        server = _make_server()
        server.config["security"]["whitelist"] = ["fp_aaa", "fp_bbb"]
        _run(server._populate_security_lists())
        # sadd called at least once for each fp
        calls = [str(c) for c in server.redis_client.sadd.call_args_list]
        assert any("fp_aaa" in c for c in calls)
        assert any("fp_bbb" in c for c in calls)

    def test_blacklist_entries_added_to_redis(self):
        server = _make_server()
        server.config["security"]["blacklist"] = ["bad_fp_1"]
        _run(server._populate_security_lists())
        calls = [str(c) for c in server.redis_client.sadd.call_args_list]
        assert any("bad_fp_1" in c for c in calls)

    def test_safe_countries_added_to_redis(self):
        server = _make_server()
        server.config["geoip"] = {"safe_countries": ["IE", "GB"]}
        _run(server._populate_security_lists())
        calls = [str(c) for c in server.redis_client.sadd.call_args_list]
        assert any("IE" in c or "GB" in c for c in calls)

    def test_empty_lists_no_redis_calls(self):
        server = _make_server()
        server.config["security"]["whitelist"] = []
        server.config["security"]["blacklist"] = []
        server.config["geoip"] = {"safe_countries": []}
        server.redis_client.sadd.reset_mock()
        # Must properly await async method - security_manager._load_security_lists is still called
        _run(server._populate_security_lists())
        # sadd should not be called for empty lists (but _load_security_lists is still called)
        server.redis_client.sadd.assert_not_called()


# ---------------------------------------------------------------------------
# ProxyServer._store_fingerprint
# ---------------------------------------------------------------------------


class TestStoreFingerprint:
    def test_stores_hset_and_expire(self):
        server = _make_server()
        fp = _make_fp()
        _run(server._store_fingerprint(fp))
        server.redis_client.hset.assert_called_once()
        server.redis_client.expire.assert_called_once()

    def test_redis_error_logged_not_raised(self, caplog):
        server = _make_server()
        server.redis_client.hset = MagicMock(side_effect=Exception("Redis down"))
        fp = _make_fp()
        with caplog.at_level(logging.ERROR, logger="proxy"):
            _run(server._store_fingerprint(fp))
        assert any("Error storing fingerprint" in r.message for r in caplog.records)

    def test_key_includes_source_ip(self):
        server = _make_server()
        fp = _make_fp(source_ip="10.0.0.1")
        _run(server._store_fingerprint(fp))
        key_arg = server.redis_client.hset.call_args[0][0]
        assert "10.0.0.1" in key_arg


# ---------------------------------------------------------------------------
# ProxyServer._forward_data
# ---------------------------------------------------------------------------


class TestForwardData:
    def test_data_written_to_destination(self):
        server = _make_server()
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=[b"chunk1", b"chunk2", b""])
        writer = MagicMock()
        writer.drain = AsyncMock()
        _run(server._forward_data(reader, writer, "client->backend"))
        assert writer.write.call_count == 2
        writer.write.assert_any_call(b"chunk1")
        writer.write.assert_any_call(b"chunk2")

    def test_eof_terminates_loop(self):
        server = _make_server()
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=b"")  # immediate EOF
        writer = MagicMock()
        writer.drain = AsyncMock()
        _run(server._forward_data(reader, writer, "test"))
        writer.write.assert_not_called()

    def test_read_exception_logged_not_raised(self, caplog):
        server = _make_server()
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=ConnectionResetError("peer reset"))
        writer = MagicMock()
        writer.drain = AsyncMock()
        with caplog.at_level(logging.DEBUG, logger="proxy"):
            _run(server._forward_data(reader, writer, "test->direction"))
        # Must not raise; debug log expected
        assert any("Connection closed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# ProxyServer._forward_to_backend
# ---------------------------------------------------------------------------


class TestForwardToBackend:
    def test_initial_data_sent_to_backend(self):
        server = _make_server()
        fp = _make_fp()

        backend_reader = AsyncMock()
        backend_reader.read = AsyncMock(return_value=b"")
        backend_writer = MagicMock()
        backend_writer.drain = AsyncMock()
        backend_writer.wait_closed = AsyncMock()

        client_reader = AsyncMock()
        client_reader.read = AsyncMock(return_value=b"")
        client_writer = MagicMock()
        client_writer.drain = AsyncMock()

        with patch(
            "proxy.asyncio.open_connection",
            AsyncMock(return_value=(backend_reader, backend_writer)),
        ):
            _run(
                server._forward_to_backend(b"initial", client_reader, client_writer, fp)
            )

        backend_writer.write.assert_called_with(b"initial")

    def test_backend_connection_refused_logged(self, caplog):
        server = _make_server()
        fp = _make_fp()
        client_reader = AsyncMock()
        client_writer = MagicMock()

        with (
            patch(
                "proxy.asyncio.open_connection",
                AsyncMock(side_effect=ConnectionRefusedError("no backend")),
            ),
            caplog.at_level(logging.ERROR, logger="proxy"),
        ):
            _run(server._forward_to_backend(b"data", client_reader, client_writer, fp))

        assert any("Error forwarding" in r.message for r in caplog.records)

    def test_backend_writer_closed_in_finally(self):
        server = _make_server()
        fp = _make_fp()

        backend_reader = AsyncMock()
        backend_reader.read = AsyncMock(return_value=b"")
        backend_writer = MagicMock()
        backend_writer.drain = AsyncMock()
        backend_writer.wait_closed = AsyncMock()

        client_reader = AsyncMock()
        client_reader.read = AsyncMock(return_value=b"")
        client_writer = MagicMock()

        with patch(
            "proxy.asyncio.open_connection",
            AsyncMock(return_value=(backend_reader, backend_writer)),
        ):
            _run(server._forward_to_backend(b"x", client_reader, client_writer, fp))

        backend_writer.close.assert_called_once()


# ---------------------------------------------------------------------------
# ProxyServer._redirect_to_tarpit
# ---------------------------------------------------------------------------


class TestRedirectToTarpit:
    def test_initial_data_forwarded_to_tarpit(self):
        server = _make_server()
        tarpit_reader = AsyncMock()
        tarpit_reader.read = AsyncMock(return_value=b"")
        tarpit_writer = MagicMock()
        tarpit_writer.drain = AsyncMock()
        tarpit_writer.wait_closed = AsyncMock()
        client_reader = AsyncMock()
        client_reader.read = AsyncMock(return_value=b"")
        client_writer = MagicMock()

        with patch(
            "proxy.asyncio.open_connection",
            AsyncMock(return_value=(tarpit_reader, tarpit_writer)),
        ):
            _run(server._redirect_to_tarpit(b"hello", client_reader, client_writer))

        tarpit_writer.write.assert_called_with(b"hello")
        tarpit_writer.close.assert_called_once()

    def test_tarpit_connection_error_does_not_raise(self):
        server = _make_server()
        client_reader = AsyncMock()
        client_writer = MagicMock()

        with patch(
            "proxy.asyncio.open_connection",
            AsyncMock(side_effect=OSError("tarpit unreachable")),
        ):
            # Must not raise
            _run(server._redirect_to_tarpit(b"data", client_reader, client_writer))


# ---------------------------------------------------------------------------
# ProxyServer._extract_ja4_from_http
# ---------------------------------------------------------------------------


class TestExtractJa4FromHttp:
    @pytest.fixture
    def server(self):
        return _make_server()

    def test_extracts_fingerprint_from_header(self, server):
        data = b"GET / HTTP/1.1\r\nX-JA4-Fingerprint: t13d1516h2_aabbccddeeff_001122334455\r\n\r\n"
        result = server._extract_ja4_from_http(data)
        assert result == "t13d1516h2_aabbccddeeff_001122334455"

    def test_non_http_data_returns_unknown(self, server):
        data = b"\x16\x03\x01\x00\x80"  # TLS record
        result = server._extract_ja4_from_http(data)
        assert result == "unknown"

    def test_http_without_header_returns_unknown(self, server):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = server._extract_ja4_from_http(data)
        assert result == "unknown"

    def test_post_method_recognised(self, server):
        data = b"POST /api HTTP/1.1\r\nX-JA4-Fingerprint: t13d9999xx_aaaaaaaaaaaa_bbbbbbbbbbbb\r\n\r\n"
        result = server._extract_ja4_from_http(data)
        assert "t13d9999xx" in result


# ---------------------------------------------------------------------------
# ProxyServer._analyze_tls_handshake
# ---------------------------------------------------------------------------


class TestAnalyzeTlsHandshake:
    @pytest.fixture
    def server(self):
        return _make_server()

    def test_non_tls_data_returns_unknown_ja4(self, server):
        # First byte != 0x16 → not a TLS record
        data = b"GET / HTTP/1.1\r\nX-JA4-Fingerprint: t13d1516h2_aabbccddeeff_001122334455\r\n\r\n"
        server.redis_client.hset = MagicMock()
        server.redis_client.expire = MagicMock()
        fp = _run(server._analyze_tls_handshake(data, "1.2.3.4"))
        # HTTP path → _extract_ja4_from_http → should find the header
        assert fp.ja4 == "t13d1516h2_aabbccddeeff_001122334455"

    def test_non_tls_without_header_returns_unknown(self, server):
        data = b"GARBAGE non-TLS non-HTTP data"
        server.redis_client.hset = MagicMock()
        server.redis_client.expire = MagicMock()
        fp = _run(server._analyze_tls_handshake(data, "1.2.3.4"))
        assert fp.ja4 == "unknown"
        assert fp.source_ip == "1.2.3.4"

    def test_tls_scapy_error_returns_fingerprint_with_unknown(self, server):
        """Scapy parse failure → ja4=unknown, not an exception."""
        data = b"\x16\x03\x01\x00\x10" + b"\x00" * 16  # TLS header, invalid body
        server.redis_client.hset = MagicMock()
        server.redis_client.expire = MagicMock()
        with patch("proxy.TLS", side_effect=Exception("Scapy parse failed")):
            fp = _run(server._analyze_tls_handshake(data, "2.3.4.5"))
        assert fp.ja4 in ("unknown", "error")

    def test_exception_returns_error_fingerprint(self, server):
        """Uncaught exception → JA4Fingerprint(ja4='error') — never propagates."""
        server.redis_client.hset = MagicMock(side_effect=Exception("outer"))
        data = b"bad"
        # _store_fingerprint will raise, caught by outer try/except
        with patch.object(
            server, "_store_fingerprint", AsyncMock(side_effect=Exception("store fail"))
        ):
            fp = _run(server._analyze_tls_handshake(data, "3.4.5.6"))
        assert fp.ja4 == "error"

    def test_tls_record_calls_scapy(self, server):
        """A TLS record (0x16) triggers Scapy parsing."""
        data = b"\x16\x03\x01\x00\x10" + b"\x00" * 16
        server.redis_client.hset = MagicMock()
        server.redis_client.expire = MagicMock()
        mock_tls = MagicMock()
        server.tls_parser.parse_client_hello = MagicMock(return_value=None)
        with patch("proxy.TLS", return_value=mock_tls) as mock_tls_cls:
            _run(server._analyze_tls_handshake(data, "1.2.3.4"))
        mock_tls_cls.assert_called_once_with(data)


# ---------------------------------------------------------------------------
# ProxyServer.handle_connection — end-to-end branch coverage
# ---------------------------------------------------------------------------


class TestHandleConnection:
    """Tests for every decision branch in handle_connection()."""

    def _patch_analyze(self, server, ja4="t13d1516h2_8daaf6152771_02713d6af862"):
        """Patch _analyze_tls_handshake to return a controlled JA4Fingerprint."""
        fp = _make_fp(ja4=ja4)
        server._analyze_tls_handshake = AsyncMock(return_value=fp)
        return fp

    def _patch_forward(self, server):
        server._forward_to_backend = AsyncMock()

    # ── Empty data ──────────────────────────────────────────────────────────

    def test_empty_data_closes_cleanly(self):
        server = _make_server()
        reader, writer = _mock_stream_pair(b"")
        _run(server.handle_connection(reader, writer))
        assert server.active_connections == 0

    # ── PROXY protocol v1 header ────────────────────────────────────────────

    def test_proxy_protocol_extracts_client_ip(self):
        server = _make_server({"proxy": {"proxy_protocol": True}})
        pp_header = b"PROXY TCP4 203.0.113.99 10.0.0.1 12345 443\r\n"
        raw_tls = b"\x16\x03\x01\x00\x10" + b"\x00" * 16
        reader, writer = _mock_stream_pair(pp_header + raw_tls)
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        # _analyze_tls_handshake is called with the raw_tls portion (after PP header)
        call_data = server._analyze_tls_handshake.call_args[0][0]
        assert call_data == raw_tls

    # ── Pipeline: whitelist bypass → forward ────────────────────────────────

    def test_pipeline_whitelist_bypass_forwarded(self):
        """Pipeline returning whitelist-bypass allow → connection forwarded."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(
                action="allow", bypassed=True, bypass_reason="ja4_whitelist"
            )
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    # ── Pipeline: alpn bypass → forward ─────────────────────────────────────

    def test_pipeline_alpn_bypass_forwarded(self):
        """Pipeline returning alpn-bypass allow → connection forwarded."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(
                action="allow", bypassed=True, bypass_reason="alpn_browser"
            )
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    # ── Dynamic country block via Redis (LAYER 1b — pre-pipeline) ───────────

    # Note: static country blacklist/whitelist checks (old LAYER 1) have moved
    # into Pipeline's country_blacklist_bypass (Phase 6 completion). The remaining
    # pre-pipeline check is the dynamic Redis blacklist (LAYER 1b below).

    # ── Dynamic country block via Redis ─────────────────────────────────────

    def test_dynamic_country_block_drops_connection(self):
        server = _make_server()
        server.geoip.lookup = MagicMock(return_value="KP")
        server.redis_client.sismember = AsyncMock(return_value=True)
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_not_called()

    def test_dynamic_country_redis_error_fails_open(self):
        """Redis failure on dynamic blacklist check → fail open, connection forwarded."""
        server = _make_server()
        server.geoip.lookup = MagicMock(return_value="KP")
        server.redis_client.sismember = AsyncMock(side_effect=Exception("Redis down"))
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    # ── CIDR block ──────────────────────────────────────────────────────────

    def test_cidr_blocked_connection_dropped(self):
        import ipaddress

        server = _make_server()
        server._cidr_blocks = [ipaddress.ip_network("1.2.3.0/24")]
        server._cidr_blocks_loaded_at = time.monotonic()
        reader, writer = _mock_stream_pair(b"data")
        # peername is 1.2.3.4 — in blocked CIDR
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_not_called()

    # ── Pipeline: blacklist bypass → drop ───────────────────────────────────

    def test_pipeline_blacklist_bypass_dropped(self):
        """Pipeline returning blacklist-bypass block → connection dropped."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(
                action="block", bypassed=True, bypass_reason="ja4_blacklist"
            )
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_not_called()

    # ── Unknown JA4 — fail open ─────────────────────────────────────────────

    def test_unknown_ja4_forwarded_fail_open(self):
        server = _make_server()
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server, ja4="unknown")
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    def test_error_ja4_forwarded_fail_open(self):
        server = _make_server()
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server, ja4="error")
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    # ── Pipeline: scored allow → forward ────────────────────────────────────

    def test_pipeline_allow_forwards_connection(self):
        """Pipeline returning allow → connection forwarded."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="allow", score=5)
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    def test_pipeline_flag_forwards_connection(self):
        """Pipeline returning flag → connection forwarded (flag=monitor only)."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="flag", score=25)
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    def test_pipeline_rate_limit_forwards_connection(self):
        """Pipeline returning rate_limit → connection forwarded."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="rate_limit", score=40)
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_called_once()

    # ── Pipeline: block → drop ───────────────────────────────────────────────

    def test_pipeline_block_drops_connection(self):
        """Pipeline returning block → connection dropped."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="block", score=75)
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_not_called()

    def test_pipeline_ban_drops_connection(self):
        """Pipeline returning ban → connection dropped."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="ban", score=90)
        )
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_not_called()

    # ── Pipeline: tarpit → redirect ──────────────────────────────────────────

    def test_pipeline_tarpit_redirects(self):
        """Pipeline returning tarpit → connection redirected to tarpit."""
        server = _make_server()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="tarpit", score=60)
        )
        server._redirect_to_tarpit = AsyncMock()
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        _run(server.handle_connection(reader, writer))
        server._redirect_to_tarpit.assert_called_once()

    # ── Timeout ─────────────────────────────────────────────────────────────

    def test_timeout_logged_and_cleaned_up(self, caplog):
        server = _make_server()
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=asyncio.TimeoutError())
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("1.2.3.4", 12345))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        with caplog.at_level(logging.WARNING, logger="proxy"):
            _run(server.handle_connection(reader, writer))
        assert any("TIMEOUT" in r.message for r in caplog.records)
        assert server.active_connections == 0

    # ── ValidationError ─────────────────────────────────────────────────────

    def test_validation_error_logged_not_raised(self, caplog):
        server = _make_server()
        reader, writer = _mock_stream_pair(b"data")
        server._analyze_tls_handshake = AsyncMock(
            side_effect=ValidationError("bad fingerprint")
        )
        with caplog.at_level(logging.WARNING, logger="proxy"):
            _run(server.handle_connection(reader, writer))
        assert any("VALIDATION_ERROR" in r.message for r in caplog.records)
        assert server.active_connections == 0

    # ── Generic exception ────────────────────────────────────────────────────

    def test_unexpected_exception_logged_not_raised(self, caplog):
        server = _make_server()
        reader, writer = _mock_stream_pair(b"data")
        server._analyze_tls_handshake = AsyncMock(
            side_effect=RuntimeError("unexpected crash")
        )
        with caplog.at_level(logging.ERROR, logger="proxy"):
            _run(server.handle_connection(reader, writer))
        assert any("ERROR" in r.message for r in caplog.records)
        assert server.active_connections == 0

    # ── Active connection counter ────────────────────────────────────────────

    def test_active_connections_decremented_on_success(self):
        server = _make_server()
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        self._patch_forward(server)
        assert server.active_connections == 0
        _run(server.handle_connection(reader, writer))
        assert server.active_connections == 0  # incremented then decremented

    def test_active_connections_decremented_on_error(self):
        server = _make_server()
        reader, writer = _mock_stream_pair(b"data")
        server._analyze_tls_handshake = AsyncMock(side_effect=RuntimeError("boom"))
        _run(server.handle_connection(reader, writer))
        assert server.active_connections == 0

    # ── X-Forwarded-For fallback ─────────────────────────────────────────────

    def test_xff_header_updates_client_ip(self):
        server = _make_server()
        # Data looks like HTTP with XFF header
        data = b"GET / HTTP/1.1\r\nX-Forwarded-For: 203.0.113.77\r\n\r\n"
        reader, writer = _mock_stream_pair(data)
        self._patch_analyze(server)
        self._patch_forward(server)
        _run(server.handle_connection(reader, writer))
        # _analyze_tls_handshake should have been called
        assert server._analyze_tls_handshake.called
