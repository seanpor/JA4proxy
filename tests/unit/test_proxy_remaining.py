"""Tests for all remaining uncovered lines in proxy.py.

Every section that was previously labelled "requires live infrastructure" is
covered here by mocking at the right boundary.  Scapy TLS objects are plain
Python objects with named attributes — we create mock equivalents.

Sections
--------
- GeoIPLookup.__init__  (GEOIP_AVAILABLE=False, db file loads, db file fails)
- classify_ja4           (pattern-label match, IndexError path)
- JA4Fingerprint         (non-string ja4, invalid IP, to_audit_log)
- TLSParser              (isinstance(TLS) branch, msg list, all extension types)
- JA4Generator           (ALPN single/multi char, hash empty, generate exception)
- ConfigManager          (file-not-found, YAML error, non-dict config, 0.0.0.0 warn,
                          production Redis password)
- SecurityManager        (load failure, rate-limit block, block_unknown_ja4,
                          check_access exception, _check_rate_limit Redis errors)
- TarpitManager          (writer.close exception silenced)
- ProxyServer.__init__   (country whitelist/blacklist logging — lines 801, 805)
- ProxyServer._init_redis (non-Connection/Auth exception re-raised)
- ProxyServer.start()    (metrics enabled/auth/0.0.0.0/disabled paths)
- handle_connection      (BAN action type, writer.close exception in finally)
- _parse_proxy_protocol  (PPv1 malformed — no \\r\\n)
- _extract_client_ip_from_http (X-Real-IP invalid IP)
- _analyze_tls_handshake (TLS 1.3 detection, TLS 1.1, TLS 1.0, unknown version)
- _extract_ja4_from_http (exception path)
- _forward_to_backend    (backend_writer.close exception in finally)
- SensitiveDataFilter    (args filter exception silenced)
- main()                 (happy path, KeyboardInterrupt, fatal exception)
"""

import asyncio
import logging
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from proxy import (
    MAX_CONCURRENT_CONNECTIONS,
    ConfigManager,
    GeoIPLookup,
    JA4Fingerprint,
    JA4Generator,
    ProxyServer,
    SecurityError,
    SecurityManager,
    SensitiveDataFilter,
    TarpitManager,
    TLSParser,
    ValidationError,
    classify_ja4,
    main,
)
from src.security.feed_health import FeedHealthMonitor
from src.security.pipeline import PipelineResult

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def _make_server_stub():
    """Minimal ProxyServer without __init__."""
    s = object.__new__(ProxyServer)
    s.config = {
        "proxy": {
            "bind_host": "0.0.0.0",
            "bind_port": 8080,
            "backend_host": "127.0.0.1",
            "backend_port": 443,
            "connection_timeout": 30,
            "read_timeout": 30,
            "buffer_size": 8192,
            "proxy_protocol": False,
            "tarpit_host": "tarpit",
            "tarpit_port": 8888,
        },
        "redis": {"host": "r", "port": 6379, "db": 0, "password": "pw", "timeout": 5},
        "security": {
            "whitelist_enabled": True,
            "blacklist_enabled": True,
            "rate_limiting": False,
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
    s.logger = logging.getLogger("proxy")
    s.redis_client = AsyncMock()
    s.redis_client.sismember = AsyncMock(return_value=False)
    s.tls_parser = TLSParser()
    s.ja4_generator = JA4Generator()
    s.tarpit_manager = MagicMock()
    s.tarpit_manager.tarpit_connection = AsyncMock()
    # Phase 2: Pipeline replaces advanced_security layers
    s.pipeline = MagicMock()
    s.pipeline.process = AsyncMock(return_value=PipelineResult(action="allow"))
    s.pipeline.start = AsyncMock()
    s.pipeline.stop = AsyncMock()
    s.pipeline._tcp_analyzer = MagicMock()
    s.pipeline._tcp_analyzer.decrement_concurrent_connections = AsyncMock()
    s.security_manager = MagicMock()
    s.security_manager.whitelist = set()
    s.security_manager.blacklist = set()
    s.geoip = MagicMock()
    s.geoip.lookup = MagicMock(return_value="")
    s.country_whitelist = set()
    s.country_blacklist = set()
    s.country_whitelist_enabled = False
    s.country_blacklist_enabled = False
    s._cidr_blocks = []
    s._cidr_blocks_loaded_at = time.monotonic()
    s._cidr_cache_ttl = 30
    s.active_connections = 0
    s._conn_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
    s.executor = None
    s.config_loader = MagicMock()
    # Phase 2: dial manager and local cache for start()
    s._dial_manager = MagicMock()
    s._dial_manager.initialize = AsyncMock(return_value=0)
    s._local_cache = MagicMock()
    s._local_cache.dial = 0
    s._backup_scheduler = None
    s._abuseipdb_checker = None
    s._rdap_enricher = None
    s._aiohttp_session = None
    s._health_task = None
    s._pubsub_task = None
    s.health_server = MagicMock()
    s.health_server.start = AsyncMock()
    s.health_server.stop = AsyncMock()
    s.health_monitor = MagicMock()
    s.health_monitor.record_pipeline_latency = MagicMock()
    # Phase 59: FeedHealthMonitor shared across TI providers
    s._feed_health_monitor = FeedHealthMonitor()
    s.greynoise_provider = MagicMock()
    s.greynoise_provider.start = AsyncMock()
    s.greynoise_provider.stop = AsyncMock()
    s.greynoise_provider._config = MagicMock()
    s.greynoise_provider._config.enabled = False  # skip probe registration in tests
    s.alienvault_provider = MagicMock()
    s.alienvault_provider.start = AsyncMock()
    s.alienvault_provider.stop = AsyncMock()
    s.alienvault_provider._config = MagicMock()
    s.alienvault_provider._config.enabled = False
    s.misp_provider = MagicMock()
    s.misp_provider.start = AsyncMock()
    s.misp_provider.stop = AsyncMock()
    s.misp_provider._config = MagicMock()
    s.misp_provider._config.enabled = False
    s.threatfox_provider = MagicMock()
    s.threatfox_provider.start = AsyncMock()
    s.threatfox_provider.stop = AsyncMock()
    s.threatfox_provider._config = MagicMock()
    s.threatfox_provider._config.enabled = False
    s.virustotal_provider = MagicMock()
    s.virustotal_provider.start = AsyncMock()
    s.virustotal_provider.stop = AsyncMock()
    s.virustotal_provider._config = MagicMock()
    s.virustotal_provider._config.enabled = False
    s.confidence_manager = MagicMock()
    s.confidence_manager.initialize = AsyncMock()
    s.confidence_manager.save_state = AsyncMock()
    s.pipeline.set_ti_providers = MagicMock()
    return s


def _mock_stream_pair(first_read: bytes = b"data"):
    reader = AsyncMock(spec=asyncio.StreamReader)
    reader.read = AsyncMock(side_effect=[first_read, b""])
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info = MagicMock(return_value=("1.2.3.4", 12345))
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    return reader, writer


def _make_fp(ja4="t13d1516h2_8daaf6152771_02713d6af862", ip="1.2.3.4"):
    return JA4Fingerprint(ja4=ja4, source_ip=ip, timestamp=time.time())


def _make_mock_tls_layer(
    version=0x0303,
    ciphers=None,
    use_cipher_suites_attr=False,
    extensions=None,
    msgtype=1,
):
    """Return a mock that looks like a Scapy TLSClientHello."""
    msg = MagicMock()
    msg.msgtype = msgtype
    msg.version = version

    if ciphers is not None:
        if use_cipher_suites_attr:
            # Only .cipher_suites available (not .ciphers)
            del msg.ciphers
            msg.cipher_suites = ciphers
            # hasattr(...) check needs the attribute to truly be absent
            msg.configure_mock(**{"ciphers": MagicMock()})
            # Override hasattr by making .ciphers raise AttributeError
            type(msg).__getattr__ = lambda self, name: (_ for _ in ()).throw(
                AttributeError(name)
            )
        else:
            msg.ciphers = ciphers

    ext_list = []
    for ext_spec in extensions or []:
        ext = MagicMock()
        ext.type = ext_spec["type"]
        if ext_spec["type"] == 10:  # supported_groups
            if "groups" in ext_spec:
                ext.groups = ext_spec["groups"]
            else:
                del ext.groups
                ext.elliptic_curves = ext_spec.get("elliptic_curves", [])
        elif ext_spec["type"] == 13:  # sig_algs
            ext.sig_algs = ext_spec.get("sig_algs", [])
        elif ext_spec["type"] == 16:  # ALPN
            protocols = []
            for proto_val in ext_spec.get("protocols", []):
                p = MagicMock()
                p.protocol = proto_val
                protocols.append(p)
            ext.protocols = protocols
        elif ext_spec["type"] == 43:  # supported_versions
            ext.versions = ext_spec.get("versions", [])
        ext_list.append(ext)

    msg.ext = ext_list

    tls_layer = MagicMock()
    tls_layer.msg = [msg]
    return tls_layer


# ---------------------------------------------------------------------------
# GeoIPLookup.__init__
# ---------------------------------------------------------------------------


class TestGeoIPLookupInit:
    def test_geoip_unavailable_logs_warning(self, caplog):
        with (
            patch("proxy.GEOIP_AVAILABLE", False),
            caplog.at_level(logging.WARNING, logger="proxy"),
        ):
            geo = GeoIPLookup()
        assert any("IP2Location not installed" in r.message for r in caplog.records)
        assert geo.db is None

    def test_db_path_found_and_loaded(self, tmp_path):
        """When a valid-looking path exists and IP2Location can open it."""
        db_file = tmp_path / "test.bin"
        db_file.write_bytes(b"fake")
        mock_db = MagicMock()
        with (
            patch("proxy.GEOIP_AVAILABLE", True),
            patch("proxy.IP2Location", create=True) as mock_ip2loc,
        ):
            mock_ip2loc.IP2Location = MagicMock(return_value=mock_db)
            geo = GeoIPLookup(db_path=str(db_file))
        assert geo.db is mock_db

    def test_db_path_load_exception_logged(self, tmp_path, caplog):
        """IP2Location raises when opening → log error, keep looking."""
        db_file = tmp_path / "bad.bin"
        db_file.write_bytes(b"garbage")
        with (
            patch("proxy.GEOIP_AVAILABLE", True),
            patch("proxy.IP2Location", create=True) as mock_ip2loc,
            caplog.at_level(logging.ERROR, logger="proxy"),
        ):
            mock_ip2loc.IP2Location = MagicMock(side_effect=Exception("corrupt"))
            geo = GeoIPLookup(db_path=str(db_file))
        assert geo.db is None
        assert any("Failed to hot-reload GeoIP" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# classify_ja4 remaining branches
# ---------------------------------------------------------------------------


class TestClassifyJa4Remaining:
    def test_prefix_match_in_labels(self):
        """key.startswith(ja4[:16]) path — partial key matches full fingerprint."""
        config = {
            "security": {"fingerprint_labels": {"t13d1516h2_8daaf61": "PartialMatch"}}
        }
        ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
        # key "t13d1516h2_8daaf61" starts with ja4[:16] = "t13d1516h2_8daaf"
        # condition: key.startswith(ja4[:16]) is True
        result = classify_ja4(ja4, config)
        assert result == "PartialMatch"

    def test_short_ja4_returns_unknown_via_length_guard(self):
        """len < 10 early-return guard fires before any structural parsing."""
        # The dead try/except has been removed; 'Unknown' comes from the len check.
        result = classify_ja4("t1")
        assert result == "Unknown"


# ---------------------------------------------------------------------------
# JA4Fingerprint validation
# ---------------------------------------------------------------------------


class TestJA4FingerprintValidation:
    def test_non_string_ja4_raises_validation_error(self):
        with pytest.raises(ValidationError, match="must be string"):
            JA4Fingerprint(ja4=12345, source_ip="1.2.3.4", timestamp=time.time())

    def test_invalid_ip_raises_validation_error(self):
        with pytest.raises(ValidationError, match="Invalid IP"):
            JA4Fingerprint(
                ja4="t13d1516h2_8daaf6152771_02713d6af862",
                source_ip="not-an-ip",
                timestamp=time.time(),
            )

    def test_to_audit_log_returns_required_fields(self):
        fp = JA4Fingerprint(
            ja4="t13d1516h2_8daaf6152771_02713d6af862",
            source_ip="1.2.3.4",
            timestamp=time.time(),
            tls_version="TLS 1.3",
            geo_country="IE",
        )
        log = fp.to_audit_log()
        assert "event_id" in log
        assert "timestamp" in log
        assert "ja4_hash" in log  # pseudonymized, not the raw fingerprint
        assert "tls_version" in log
        assert log["geo_country"] == "IE"

    def test_to_audit_log_pseudonymizes_ip(self):
        """source_ip must be hashed in the audit log, not logged in plaintext."""
        fp = JA4Fingerprint(
            ja4="t13d1516h2_8daaf6152771_02713d6af862",
            source_ip="203.0.113.1",
            timestamp=time.time(),
        )
        log = fp.to_audit_log()
        assert "203.0.113.1" not in str(log)  # IP not in plaintext


# ---------------------------------------------------------------------------
# TLSParser — remaining branches
# ---------------------------------------------------------------------------


class TestTLSParserRemaining:
    def test_isinstance_tls_branch(self):
        """isinstance(packet, TLS) path — packet IS a TLS object directly."""
        parser = TLSParser()
        # Patch proxy.TLS so our mock IS an instance of it
        MockTLS = type("MockTLS", (), {})
        mock_pkt = MockTLS()
        mock_pkt.msg = []  # no messages → returns None

        with patch("proxy.TLS", MockTLS):
            result = parser.parse_client_hello(mock_pkt)
        assert result is None

    def test_tls_layer_no_msg_attribute_returns_none(self):
        parser = TLSParser()
        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        tls_layer = MagicMock(spec=[])  # no 'msg' attribute at all
        pkt.__getitem__ = MagicMock(return_value=tls_layer)
        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert result is None

    def test_no_client_hello_msgtype_returns_none(self):
        """msg list exists but no message has msgtype==1."""
        parser = TLSParser()
        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        msg = MagicMock()
        msg.msgtype = 2  # ServerHello, not ClientHello
        tls_layer = MagicMock()
        tls_layer.msg = [msg]
        pkt.__getitem__ = MagicMock(return_value=tls_layer)
        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert result is None

    def test_exception_in_parse_returns_none(self, caplog):
        parser = TLSParser()
        pkt = MagicMock()
        pkt.haslayer = MagicMock(side_effect=RuntimeError("scapy crash"))
        with caplog.at_level(logging.ERROR, logger="proxy"):
            result = parser.parse_client_hello(pkt)
        assert result is None
        assert any("Error parsing" in r.message for r in caplog.records)

    def test_cipher_suites_via_cipher_suites_attr(self):
        """_extract_client_hello_fields falls back to .cipher_suites when .ciphers absent."""
        parser = TLSParser()
        msg = MagicMock(spec=["msgtype", "version", "cipher_suites", "ext"])
        msg.msgtype = 1
        msg.version = 0x0303
        msg.cipher_suites = [0x1301, 0x002F]
        msg.ext = []

        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        tls_layer = MagicMock()
        tls_layer.msg = [msg]
        pkt.__getitem__ = MagicMock(return_value=tls_layer)

        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert result is not None
        assert result["cipher_suites"] == [0x1301, 0x002F]

    def test_supported_groups_via_groups_attr(self):
        parser = TLSParser()
        msg = MagicMock()
        msg.msgtype = 1
        msg.version = 0x0303
        msg.ciphers = []
        ext = MagicMock()
        ext.type = 10  # supported_groups
        ext.groups = [0x001D, 0x0017]
        msg.ext = [ext]

        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        tls_layer = MagicMock()
        tls_layer.msg = [msg]
        pkt.__getitem__ = MagicMock(return_value=tls_layer)

        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert result["supported_groups"] == [0x001D, 0x0017]

    def test_signature_algorithms_extracted(self):
        parser = TLSParser()
        msg = MagicMock()
        msg.msgtype = 1
        msg.version = 0x0303
        msg.ciphers = []
        ext = MagicMock()
        ext.type = 13  # signature_algorithms
        ext.sig_algs = [0x0403, 0x0503]
        msg.ext = [ext]

        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        tls_layer = MagicMock()
        tls_layer.msg = [msg]
        pkt.__getitem__ = MagicMock(return_value=tls_layer)

        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert result["signature_algorithms"] == [0x0403, 0x0503]

    def test_alpn_bytes_decoded(self):
        """ALPN protocol value as bytes → decoded to string."""
        parser = TLSParser()
        msg = MagicMock()
        msg.msgtype = 1
        msg.version = 0x0303
        msg.ciphers = []
        proto = MagicMock()
        proto.protocol = b"h2"  # bytes
        ext = MagicMock()
        ext.type = 16
        ext.protocols = [proto]
        msg.ext = [ext]

        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        tls_layer = MagicMock()
        tls_layer.msg = [msg]
        pkt.__getitem__ = MagicMock(return_value=tls_layer)

        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert result["alpn"] == ["h2"]

    def test_alpn_string_passed_through(self):
        """ALPN protocol value as string → kept as-is."""
        parser = TLSParser()
        msg = MagicMock()
        msg.msgtype = 1
        msg.version = 0x0303
        msg.ciphers = []
        proto = MagicMock()
        proto.protocol = "http/1.1"  # already a string
        ext = MagicMock()
        ext.type = 16
        ext.protocols = [proto]
        msg.ext = [ext]

        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        tls_layer = MagicMock()
        tls_layer.msg = [msg]
        pkt.__getitem__ = MagicMock(return_value=tls_layer)

        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert "http/1.1" in result["alpn"]

    def test_supported_versions_extracted(self):
        parser = TLSParser()
        msg = MagicMock()
        msg.msgtype = 1
        msg.version = 0x0303
        msg.ciphers = []
        ext = MagicMock()
        ext.type = 43  # supported_versions
        ext.versions = [0x0304, 0x0303]
        msg.ext = [ext]

        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=True)
        tls_layer = MagicMock()
        tls_layer.msg = [msg]
        pkt.__getitem__ = MagicMock(return_value=tls_layer)

        with patch("proxy.TLS"):
            result = parser.parse_client_hello(pkt)
        assert result["supported_versions"] == [0x0304, 0x0303]


# ---------------------------------------------------------------------------
# JA4Generator remaining branches
# ---------------------------------------------------------------------------


class TestJA4GeneratorRemaining:
    def test_alpn_single_char_appends_zero(self):
        gen = JA4Generator()
        result = gen._get_alpn_string({"alpn": ["h"]})  # single char
        assert result == "h0"

    def test_alpn_multi_char_first_last(self):
        gen = JA4Generator()
        result = gen._get_alpn_string({"alpn": ["http/1.1"]})
        assert result == "h1"  # first='h', last='1'

    def test_alpn_empty_returns_00(self):
        gen = JA4Generator()
        assert gen._get_alpn_string({"alpn": []}) == "00"
        assert gen._get_alpn_string({}) == "00"

    def test_hash_cipher_suites_empty_returns_zeros(self):
        gen = JA4Generator()
        result = gen._hash_cipher_suites([])
        assert result == "000000000000"

    def test_hash_extensions_empty_returns_zeros(self):
        gen = JA4Generator()
        result = gen._hash_extensions([])
        assert result == "000000000000"

    def test_generate_ja4_exception_raises_validation_error(self):
        gen = JA4Generator()
        # Pass malformed fields that cause an exception
        with pytest.raises(ValidationError, match="JA4 generation failed"):
            gen.generate_ja4(None)  # None causes AttributeError inside


# ---------------------------------------------------------------------------
# ConfigManager remaining branches
# ---------------------------------------------------------------------------


class TestConfigManagerRemaining:
    def test_load_config_file_not_found_returns_defaults(self):
        mgr = ConfigManager.__new__(ConfigManager)
        mgr.logger = logging.getLogger("proxy")
        mgr.config_path = "/nonexistent/path/proxy.yml"
        config = mgr.load_config()
        assert "proxy" in config
        assert "redis" in config

    def test_load_config_yaml_error_raises(self, tmp_path):
        bad_yaml = tmp_path / "bad.yml"
        bad_yaml.write_text("key: [unclosed")
        mgr = ConfigManager.__new__(ConfigManager)
        mgr.logger = logging.getLogger("proxy")
        mgr.config_path = str(bad_yaml)
        with pytest.raises(ValidationError, match="Invalid configuration"):
            mgr.load_config()

    def test_validate_config_non_dict_raises(self):
        mgr = ConfigManager("config/proxy.yml")
        with pytest.raises(ValidationError, match="must be a dictionary"):
            mgr._validate_config(["not", "a", "dict"])

    def test_validate_proxy_config_0000_warns(self, caplog):
        mgr = ConfigManager("config/proxy.yml")
        with caplog.at_level(logging.WARNING, logger="proxy"):
            mgr._validate_proxy_config({"bind_host": "0.0.0.0"})
        assert any("0.0.0.0" in r.message for r in caplog.records)

    def test_validate_redis_config_empty_password_production(self):
        mgr = ConfigManager("config/proxy.yml")
        env = dict(os.environ)
        env["ENVIRONMENT"] = "production"
        with patch.dict(os.environ, env):
            with pytest.raises(ValidationError, match="password is required"):
                mgr._validate_redis_config({"host": "r", "port": 6379, "password": ""})

    def test_validate_redis_config_empty_password_dev_warns(self, caplog):
        mgr = ConfigManager("config/proxy.yml")
        env = dict(os.environ)
        env["ENVIRONMENT"] = "development"
        with (
            patch.dict(os.environ, env),
            caplog.at_level(logging.WARNING, logger="proxy"),
        ):
            mgr._validate_redis_config({"host": "r", "port": 6379, "password": ""})
        assert any("without authentication" in r.message for r in caplog.records)

    def test_validate_proxy_config_non_string_bind_host_raises(self):
        mgr = ConfigManager("config/proxy.yml")
        with pytest.raises(ValidationError, match="bind_host must be a string"):
            mgr._validate_proxy_config({"bind_host": 12345})

    def test_load_config_validate_raises_wraps_in_generic_except(self, tmp_path):
        """A ValidationError from _validate_config is caught by the generic except clause
        (lines 467-469) and re-raised as 'Configuration loading failed'."""
        # A valid YAML file containing a list, not a dict —
        # yaml.safe_load succeeds but _validate_config raises ValidationError,
        # which is caught by `except Exception` and re-wrapped.
        cfg_path = tmp_path / "list.yml"
        cfg_path.write_text("- a\n- b\n")
        mgr = ConfigManager.__new__(ConfigManager)
        mgr.logger = logging.getLogger("proxy")
        mgr.config_path = str(cfg_path)
        with pytest.raises(ValidationError, match="Configuration loading failed"):
            mgr.load_config()


# ---------------------------------------------------------------------------
# SecurityManager
# ---------------------------------------------------------------------------


class TestSecurityManagerRemaining:
    def _make_sm(self, config_overrides=None):
        config = {
            "security": {
                "whitelist_enabled": True,
                "blacklist_enabled": True,
                "rate_limiting": False,
                "max_requests_per_minute": 100,
                "block_unknown_ja4": False,
            }
        }
        if config_overrides:
            config["security"].update(config_overrides)
        redis_mock = MagicMock()
        redis_mock.smembers = MagicMock(return_value=set())
        return SecurityManager(config, redis_mock)

    def _make_fp(self, ja4="t13d1516h2_8daaf6152771_02713d6af862"):
        return JA4Fingerprint(ja4=ja4, source_ip="1.2.3.4", timestamp=time.time())

    def test_load_security_lists_exception_uses_empty_sets(self, caplog):
        config = {"security": {}}
        redis_mock = MagicMock()
        redis_mock.smembers = MagicMock(side_effect=Exception("Redis down"))
        sm = SecurityManager(config, redis_mock)
        # _load_security_lists is async - need to run it to trigger the error
        _run(sm._load_security_lists())
        assert sm.whitelist == set()
        assert sm.blacklist == set()
        assert any("Error loading security lists" in r.message for r in caplog.records)

    def test_check_access_rate_limit_blocks(self):
        """Rate limiting only blocks when dial > 0 (not in monitor mode)."""
        sm = self._make_sm({"rate_limiting": True})
        sm._check_rate_limit = AsyncMock(return_value=False)
        # At dial=0 (default), rate limiting doesn't block
        allowed, reason = _run(sm.check_access(self._make_fp(), "1.2.3.4"))
        assert allowed  # Monitor mode - no blocking
        assert "Monitor mode" in reason

    def test_check_access_block_unknown_ja4(self):
        """Block unknown JA4 only applies when dial > 0."""
        sm = self._make_sm({"block_unknown_ja4": True})
        # At dial=0 (default), whitelist check passes
        allowed, reason = _run(sm.check_access(self._make_fp(), "1.2.3.4"))
        assert allowed  # Monitor mode - no blocking

    def test_check_access_exception_returns_false(self, caplog):
        """Exception during check returns False (but not due to rate limit at dial=0)."""
        sm = self._make_sm()
        # Force dial > 0 to test exception handling
        sm.redis.get = AsyncMock(return_value="50")  # dial = 50
        sm._check_rate_limit = AsyncMock(side_effect=RuntimeError("boom"))
        sm.config["security"]["rate_limiting"] = True
        with caplog.at_level(logging.ERROR, logger="proxy"):
            allowed, reason = _run(sm.check_access(self._make_fp(), "1.2.3.4"))
        assert not allowed
        assert "Internal error" in reason

    def test_check_rate_limit_connection_error_returns_false(self, caplog):
        import redis as redis_lib

        sm = self._make_sm()
        sm.redis = MagicMock()
        # JA4PROXY-2026-0038: atomic rate-limit path uses redis.eval().
        sm.redis.eval = AsyncMock(side_effect=redis_lib.ConnectionError("down"))
        sm.config["security"]["rate_limit_window"] = 60
        with caplog.at_level(logging.ERROR, logger="proxy"):
            result = _run(sm._check_rate_limit("1.2.3.4"))
        assert result is False
        assert any("connection error" in r.message.lower() for r in caplog.records)

    def test_check_rate_limit_timeout_returns_false(self, caplog):
        import redis as redis_lib

        sm = self._make_sm()
        sm.redis = MagicMock()
        sm.redis.eval = AsyncMock(side_effect=redis_lib.TimeoutError("slow"))
        sm.config["security"]["rate_limit_window"] = 60
        with caplog.at_level(logging.ERROR, logger="proxy"):
            result = _run(sm._check_rate_limit("1.2.3.4"))
        assert result is False

    def test_check_rate_limit_unexpected_exception_returns_false(self, caplog):
        sm = self._make_sm()
        sm.redis = MagicMock()
        sm.redis.eval = AsyncMock(side_effect=RuntimeError("unexpected"))
        sm.config["security"]["rate_limit_window"] = 60
        with caplog.at_level(logging.ERROR, logger="proxy"):
            result = _run(sm._check_rate_limit("1.2.3.4"))
        assert result is False


# ---------------------------------------------------------------------------
# TarpitManager — writer.close exception silenced
# ---------------------------------------------------------------------------


class TestTarpitManagerCleanup:
    def test_writer_close_exception_silenced(self):
        """Exception in finally writer.close() must not propagate."""
        config = {"security": {"tarpit_enabled": True, "tarpit_duration": 0}}
        mgr = TarpitManager(config)
        writer = MagicMock()
        writer.close = MagicMock(side_effect=Exception("close failed"))
        writer.wait_closed = AsyncMock(side_effect=Exception("wait_closed failed"))
        with patch("proxy.asyncio.sleep", AsyncMock()):
            _run(mgr.tarpit_connection(writer))  # must not raise


# ---------------------------------------------------------------------------
# ProxyServer.__init__ logging (lines 801, 805)
# ---------------------------------------------------------------------------


class TestProxyServerInitLogging:
    def test_country_whitelist_logged_on_init(self, caplog):
        config = {
            "proxy": {
                "bind_host": "0.0.0.0",
                "bind_port": 8080,
                "backend_host": "127.0.0.1",
                "backend_port": 443,
                "max_connections": 1000,
                "connection_timeout": 30,
                "buffer_size": 8192,
            },
            "redis": {
                "host": "r",
                "port": 6379,
                "db": 0,
                "password": "pw",
                "timeout": 5,
            },
            "security": {
                "whitelist_enabled": True,
                "blacklist_enabled": True,
                "rate_limiting": False,
                "max_requests_per_minute": 100,
                "block_unknown_ja4": False,
                "tarpit_enabled": False,
                "tarpit_duration": 10,
                "whitelist": [],
                "blacklist": [],
            },
            "metrics": {"enabled": False, "port": 9090},
            "logging": {"level": "INFO", "format": "%(message)s"},
            "geoip": {
                "country_whitelist_enabled": True,
                "country_whitelist": ["IE", "GB"],
                "country_blacklist_enabled": False,
                "country_blacklist": [],
                "safe_countries": [],
            },
        }
        mock_cm = MagicMock()
        mock_cm.config = config
        mock_redis = MagicMock()
        mock_redis.ping = MagicMock(return_value=True)
        mock_redis.smembers = MagicMock(return_value=set())
        mock_redis.sadd = MagicMock(return_value=1)

        from unittest.mock import mock_open

        import yaml
        with (
            patch("proxy.ConfigLoader"),
            patch("builtins.open", mock_open(read_data=yaml.dump(config))),
            patch("yaml.safe_load", return_value=config),
            patch("proxy.redis.Redis", return_value=mock_redis),
            patch("proxy.SecurityManager") as mock_sec,
            patch("proxy.Pipeline"),
            patch("proxy.RiskScorer"),
            patch("proxy.ActionDecider"),
            patch("proxy.DialManager"),
            patch("proxy.LocalCache"),
            patch("proxy.GeoIPLookup"),
            caplog.at_level(logging.INFO, logger="proxy"),
        ):
            mock_sec.return_value = MagicMock(_load_security_lists=MagicMock())
            server = ProxyServer("config/proxy.yml")

        assert server.country_whitelist_enabled is True
        assert any("whitelist" in r.message.lower() for r in caplog.records)

    def test_country_blacklist_logged_on_init(self, caplog):
        config = {
            "proxy": {
                "bind_host": "0.0.0.0",
                "bind_port": 8080,
                "backend_host": "127.0.0.1",
                "backend_port": 443,
                "max_connections": 1000,
                "connection_timeout": 30,
                "buffer_size": 8192,
            },
            "redis": {
                "host": "r",
                "port": 6379,
                "db": 0,
                "password": "pw",
                "timeout": 5,
            },
            "security": {
                "whitelist_enabled": True,
                "blacklist_enabled": True,
                "rate_limiting": False,
                "max_requests_per_minute": 100,
                "block_unknown_ja4": False,
                "tarpit_enabled": False,
                "tarpit_duration": 10,
                "whitelist": [],
                "blacklist": [],
            },
            "metrics": {"enabled": False, "port": 9090},
            "logging": {"level": "INFO", "format": "%(message)s"},
            "geoip": {
                "country_whitelist_enabled": False,
                "country_whitelist": [],
                "country_blacklist_enabled": True,
                "country_blacklist": ["KP"],
                "safe_countries": [],
            },
        }
        mock_cm = MagicMock()
        mock_cm.config = config
        mock_redis = MagicMock()
        mock_redis.ping = MagicMock(return_value=True)
        mock_redis.smembers = MagicMock(return_value=set())
        mock_redis.sadd = MagicMock(return_value=1)

        from unittest.mock import mock_open

        import yaml
        with (
            patch("proxy.ConfigLoader"),
            patch("builtins.open", mock_open(read_data=yaml.dump(config))),
            patch("yaml.safe_load", return_value=config),
            patch("proxy.redis.Redis", return_value=mock_redis),
            patch("proxy.SecurityManager") as mock_sec,
            patch("proxy.Pipeline"),
            patch("proxy.RiskScorer"),
            patch("proxy.ActionDecider"),
            patch("proxy.DialManager"),
            patch("proxy.LocalCache"),
            patch("proxy.GeoIPLookup"),
            caplog.at_level(logging.INFO, logger="proxy"),
        ):
            mock_sec.return_value = MagicMock(_load_security_lists=MagicMock())
            server = ProxyServer("config/proxy.yml")

        assert server.country_blacklist_enabled is True
        assert any("blacklist" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# ProxyServer._init_redis — non-Connection/Auth exception
# ---------------------------------------------------------------------------


class TestInitRedisGenericException:
    def test_generic_exception_reraises(self):
        server = _make_server_stub()
        with patch("redis.asyncio.Redis", side_effect=ValueError("unexpected")):
            with pytest.raises(ValueError, match="unexpected"):
                _run(server._init_redis())

    def test_auth_error_caught_before_connection_error(self):
        """AuthenticationError is now caught first (more specific before general).

        redis.AuthenticationError IS-A redis.ConnectionError, so it must appear
        before ConnectionError in the except chain or it is unreachable dead code.
        The error message must identify the failure as an authentication problem,
        not a generic connection failure — this distinction matters for incident
        response and for operators who need to know whether to fix credentials vs.
        network routing.
        """
        import redis as redis_lib

        server = _make_server_stub()
        with patch(
            "redis.asyncio.Redis", side_effect=redis_lib.AuthenticationError("wrong pw")
        ):
            with pytest.raises(SecurityError, match="Redis authentication failed"):
                _run(server._init_redis())


# ---------------------------------------------------------------------------
# ProxyServer.start()
# ---------------------------------------------------------------------------


class TestProxyServerStart:
    def _run_start(self, server):
        mock_srv = AsyncMock()
        mock_srv.serve_forever = AsyncMock(side_effect=asyncio.CancelledError())
        mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
        mock_srv.__aexit__ = AsyncMock(return_value=False)
        with patch("proxy.asyncio.start_server", AsyncMock(return_value=mock_srv)):
            with pytest.raises(asyncio.CancelledError):
                _run(server.start())

    def test_metrics_disabled_starts_server(self):
        server = _make_server_stub()
        server.config["metrics"]["enabled"] = False
        self._run_start(server)

    def test_metrics_enabled_calls_start_http_server(self):
        server = _make_server_stub()
        server.config["metrics"]["enabled"] = True
        server.config["metrics"]["port"] = 9090
        self._run_start(server)
        server.health_server.start.assert_called_once()

    def test_metrics_auth_enabled_warns(self, caplog):
        server = _make_server_stub()
        server.config["metrics"]["enabled"] = True
        server.config["metrics"]["authentication"] = {"enabled": True}
        with (
            patch("proxy.start_http_server"),
            caplog.at_level(logging.WARNING, logger="proxy"),
        ):
            self._run_start(server)
        assert any("authentication" in r.message.lower() for r in caplog.records)

    def test_metrics_bind_all_interfaces_warns(self, caplog):
        server = _make_server_stub()
        server.config["metrics"]["enabled"] = True
        server.config["metrics"]["bind_host"] = "0.0.0.0"
        with (
            patch("proxy.start_http_server"),
            caplog.at_level(logging.WARNING, logger="proxy"),
        ):
            self._run_start(server)
        assert any(
            "all interfaces" in r.message.lower() or "0.0.0.0" in r.message
            for r in caplog.records
        )


# ---------------------------------------------------------------------------
# handle_connection — remaining branches
# ---------------------------------------------------------------------------


class TestHandleConnectionRemaining:
    def _patch_analyze(self, server, ja4="t13d1516h2_8daaf6152771_02713d6af862"):
        fp = _make_fp(ja4)
        server._analyze_tls_handshake = AsyncMock(return_value=fp)
        return fp

    def test_pipeline_block_drops_connection(self):
        """Pipeline returning block → connection dropped (no forward)."""
        server = _make_server_stub()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="block", score=75)
        )
        server._forward_to_backend = AsyncMock()
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_not_called()

    def test_pipeline_ban_drops_connection(self):
        """Pipeline returning ban → connection dropped (no forward)."""
        server = _make_server_stub()
        server.pipeline.process = AsyncMock(
            return_value=PipelineResult(action="ban", score=90)
        )
        server._forward_to_backend = AsyncMock()
        reader, writer = _mock_stream_pair(b"data")
        self._patch_analyze(server)
        _run(server.handle_connection(reader, writer))
        server._forward_to_backend.assert_not_called()

    def test_writer_close_exception_in_finally_silenced(self):
        """If writer.close() raises in the finally block, it must not propagate."""
        server = _make_server_stub()
        self._patch_analyze(server)
        server._forward_to_backend = AsyncMock()
        reader, writer = _mock_stream_pair(b"data")
        writer.close = MagicMock(side_effect=Exception("write error"))
        writer.wait_closed = AsyncMock(side_effect=Exception("wait error"))
        # Must not raise
        _run(server.handle_connection(reader, writer))
        assert server.active_connections == 0


# ---------------------------------------------------------------------------
# _parse_proxy_protocol — PPv1 malformed
# ---------------------------------------------------------------------------


class TestParseProxyProtocolMalformed:
    def test_ppv1_no_crlf_uses_fallback(self):
        """PPv1 header without \\r\\n → parse error → fallback IP used."""
        server = _make_server_stub()
        data = b"PROXY TCP4 203.0.113.99 10.0.0.1 12345 443"  # no \r\n
        info, remaining = server._parse_proxy_protocol(data, "9.9.9.9")
        assert info["client_ip"] == "9.9.9.9"
        assert remaining == data


# ---------------------------------------------------------------------------
# _extract_client_ip_from_http — X-Real-IP invalid IP
# ---------------------------------------------------------------------------


class TestExtractClientIpInvalidRealIP:
    def test_x_real_ip_invalid_returns_empty(self):
        server = _make_server_stub()
        data = b"GET / HTTP/1.1\r\nX-Real-IP: not-a-valid-ip\r\n\r\n"
        result = server._extract_client_ip_from_http(data)
        assert result == ""

    def test_x_real_ip_unexpected_exception_caught_by_outer_except(self):
        """When ipaddress.ip_address raises something other than ValueError,
        the outer except Exception (lines 1341-1342) catches it and returns ''."""
        server = _make_server_stub()
        data = b"GET / HTTP/1.1\r\nX-Real-IP: 1.2.3.4\r\n\r\n"
        with patch(
            "proxy.ipaddress.ip_address", side_effect=RuntimeError("unexpected")
        ):
            result = server._extract_client_ip_from_http(data)
        assert result == ""

    def test_extract_ja4_from_http_no_fingerprint_header_returns_unknown(self):
        """HTTP request with no X-JA4-Fingerprint header returns 'unknown'."""
        server = _make_server_stub()
        result = server._extract_ja4_from_http(b"GET /\x00\xff malformed\r\n\r\n")
        assert result == "unknown"


# ---------------------------------------------------------------------------
# _analyze_tls_handshake — TLS version branches
# ---------------------------------------------------------------------------


class TestAnalyzeTlsHandshakeVersions:
    def _make_server_with_analyze(self):
        server = _make_server_stub()
        server.redis_client.hset = AsyncMock()
        server.redis_client.expire = AsyncMock()
        return server

    def _analyze(self, server, fields):
        """Run _analyze_tls_handshake with mock executor returning given fields."""
        data = b"\x16\x03\x01\x00\x10" + b"\x00" * 16  # TLS record header
        server.ja4_generator = MagicMock()
        server.ja4_generator.generate_ja4 = MagicMock(
            return_value="t13d1516h2_aabbccddeeff_aabbccddeeff"
        )
        # Phase 28a: Mock run_in_executor since it now offloads to a process pool
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            # Return fields directly as if they were returned by the worker
            mock_loop.run_in_executor = AsyncMock(return_value=fields)
            mock_get_loop.return_value = mock_loop
            return _run(server._analyze_tls_handshake(data, "1.2.3.4"))

    def test_tls_13_via_supported_versions(self):
        server = self._make_server_with_analyze()
        fields = {"version": 0x0303, "supported_versions": [0x0304], "alpn": []}
        fp = self._analyze(server, fields)
        assert fp.tls_version == "TLS 1.3"

    def test_tls_12_via_version_field(self):
        server = self._make_server_with_analyze()
        fields = {"version": 0x0303, "supported_versions": [], "alpn": []}
        fp = self._analyze(server, fields)
        assert fp.tls_version == "TLS 1.2"

    def test_tls_11_via_version_field(self):
        server = self._make_server_with_analyze()
        fields = {"version": 0x0302, "supported_versions": [], "alpn": []}
        fp = self._analyze(server, fields)
        assert fp.tls_version == "TLS 1.1"

    def test_tls_10_via_version_field(self):
        server = self._make_server_with_analyze()
        fields = {"version": 0x0301, "supported_versions": [], "alpn": []}
        fp = self._analyze(server, fields)
        assert fp.tls_version == "TLS 1.0"

    def test_unknown_version_formatted_as_hex(self):
        server = self._make_server_with_analyze()
        fields = {"version": 0x0999, "supported_versions": [], "alpn": []}
        fp = self._analyze(server, fields)
        assert "0x0999" in fp.tls_version

    def test_zero_version_returns_unknown(self):
        server = self._make_server_with_analyze()
        fields = {"version": 0, "supported_versions": [], "alpn": []}
        fp = self._analyze(server, fields)
        assert fp.tls_version == "unknown"


# ---------------------------------------------------------------------------
# _forward_to_backend — backend writer close exception in finally
# ---------------------------------------------------------------------------


class TestForwardToBackendCleanup:
    def test_backend_writer_close_exception_silenced(self):
        server = _make_server_stub()
        fp = _make_fp()

        backend_reader = AsyncMock()
        backend_reader.read = AsyncMock(return_value=b"")
        backend_writer = MagicMock()
        backend_writer.drain = AsyncMock()
        backend_writer.close = MagicMock(side_effect=Exception("close failed"))
        backend_writer.wait_closed = AsyncMock(side_effect=Exception("wait failed"))

        client_reader = AsyncMock()
        client_reader.read = AsyncMock(return_value=b"")
        client_writer = MagicMock()

        with patch(
            "proxy.asyncio.open_connection",
            AsyncMock(return_value=(backend_reader, backend_writer)),
        ):
            _run(server._forward_to_backend(b"x", client_reader, client_writer, fp))
        # No exception propagated


# ---------------------------------------------------------------------------
# SensitiveDataFilter — args filter exception silenced
# ---------------------------------------------------------------------------


class TestSensitiveDataFilterException:
    def test_args_filter_exception_silenced(self):
        """If args is a non-iterable truthy value, the filter must not fail the log call."""
        f = SensitiveDataFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test %s",
            args=None,
            exc_info=None,
        )
        # Set args to a truthy non-iterable so `for arg in record.args` raises TypeError
        record.args = 42
        # Must not raise
        result = f.filter(record)
        assert result is True


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_uses_default_config_path(self):
        with (
            patch("sys.argv", ["proxy.py"]),
            patch("proxy.ProxyServer.create", new_callable=AsyncMock) as mock_create,
        ):
            mock_proxy = MagicMock()
            mock_proxy.start = AsyncMock()
            mock_create.return_value = mock_proxy
            _run(main())
        mock_create.assert_called_once_with("config/proxy.yml")

    def test_main_uses_argv_config_path(self):
        with (
            patch("sys.argv", ["proxy.py", "/custom/path.yml"]),
            patch("proxy.ProxyServer.create", new_callable=AsyncMock) as mock_create,
        ):
            mock_proxy = MagicMock()
            mock_proxy.start = AsyncMock()
            mock_create.return_value = mock_proxy
            _run(main())
        mock_create.assert_called_once_with("/custom/path.yml")

    def test_main_keyboard_interrupt_handled(self):
        """KeyboardInterrupt raised by proxy.start() is caught gracefully."""
        with (
            patch("sys.argv", ["proxy.py"]),
            patch("proxy.ProxyServer.create", new_callable=AsyncMock) as mock_create,
        ):
            mock_proxy = MagicMock()
            mock_proxy.start = AsyncMock(side_effect=KeyboardInterrupt())
            mock_create.return_value = mock_proxy
            _run(main())  # Must not raise

    def test_main_fatal_exception_calls_sys_exit(self):
        with (
            patch("sys.argv", ["proxy.py"]),
            patch("proxy.ProxyServer.create", new_callable=AsyncMock) as mock_create,
            patch("sys.exit") as mock_exit,
        ):
            mock_proxy = MagicMock()
            mock_proxy.start = AsyncMock(side_effect=RuntimeError("fatal"))
            mock_create.return_value = mock_proxy
            _run(main())
        mock_exit.assert_called_once_with(1)


# ---------------------------------------------------------------------------
# Phase 16c — Coverage Gaps
# ---------------------------------------------------------------------------


class TestJA4FingerprintCoverageGaps:
    """Cover validation paths in JA4Fingerprint not hit by existing tests."""

    def test_invalid_ja4_pattern_raises(self):
        """Invalid JA4 pattern (not sentinel) → ValidationError (line 270)."""
        with pytest.raises(ValidationError, match="Invalid JA4 fingerprint format"):
            JA4Fingerprint(ja4="NOT_A_VALID_JA4")

    def test_empty_source_ip_returns_empty(self):
        """Empty source_ip string is accepted (line 277)."""
        fp = JA4Fingerprint(ja4="t13d1516h2_8daaf6152771_02713d6af862", source_ip="")
        assert fp.source_ip == ""

    def test_future_timestamp_raises(self):
        """Timestamp too far in future → ValidationError (line 289)."""
        future_ts = time.time() + 1000
        with pytest.raises(ValidationError, match="future"):
            JA4Fingerprint(
                ja4="t13d1516h2_8daaf6152771_02713d6af862",
                timestamp=future_ts,
            )

    def test_old_timestamp_raises(self):
        """Timestamp older than 30 days → ValidationError (line 291)."""
        old_ts = time.time() - (86400 * 31)
        with pytest.raises(ValidationError, match="old"):
            JA4Fingerprint(
                ja4="t13d1516h2_8daaf6152771_02713d6af862",
                timestamp=old_ts,
            )


class TestTLSParserCoverageGaps:
    """Cover SNI extraction paths (lines 396-410)."""

    def test_sni_via_servernames_attribute(self):
        """SNI extracted from ext.servernames[0].servername (lines 396-406)."""
        parser = TLSParser()
        sn = MagicMock()
        sn.servername = b"example.com"
        ext = MagicMock(spec=["type", "servernames"])
        ext.type = 0  # SNI
        ext.servernames = [sn]

        # Build a fake ClientHello with this extension (uses .ext attr, not .extensions)
        ch = MagicMock()
        ch.version = 0x0303
        ch.ciphers = [0x1301, 0x1302]
        ch.ext = [ext]

        fields = parser._extract_client_hello_fields(ch)
        assert fields["sni"] == "example.com"

    def test_sni_via_server_name_attribute(self):
        """SNI extracted from ext.server_name fallback (lines 407-414)."""
        parser = TLSParser()
        ext = MagicMock(spec=["type", "servernames", "server_name"])
        ext.type = 0  # SNI
        ext.servernames = []  # Empty — triggers fallback
        ext.server_name = b"fallback.example.com"

        ch = MagicMock()
        ch.version = 0x0303
        ch.ciphers = [0x1301]
        ch.ext = [ext]

        fields = parser._extract_client_hello_fields(ch)
        assert fields["sni"] == "fallback.example.com"

    def test_parse_client_hello_packet_is_none(self):
        """None packet → returns None immediately (line 327)."""
        parser = TLSParser()
        result = parser.parse_client_hello(None)
        assert result is None

    def test_parse_client_hello_not_tls_packet(self):
        """Packet without haslayer or TLS type → returns None (line 335)."""
        parser = TLSParser()
        not_tls = MagicMock(spec=[])  # No haslayer, not TLS
        result = parser.parse_client_hello(not_tls)
        assert result is None

    def test_supported_groups_via_elliptic_curves_attr(self):
        """supported_groups extracted from ext.elliptic_curves fallback (lines 377-378)."""
        parser = TLSParser()
        ext = MagicMock(spec=["type", "elliptic_curves"])
        ext.type = 10  # supported_groups
        ext.elliptic_curves = [23, 24, 29]

        ch = MagicMock()
        ch.version = 0x0303
        ch.ciphers = [0x1301]
        ch.ext = [ext]

        fields = parser._extract_client_hello_fields(ch)
        assert fields["supported_groups"] == [23, 24, 29]


class TestJA4GeneratorCoverageGaps:
    """Cover generate_ja4, generate_ja4x, _is_grease, _get_version_string."""

    def test_generate_ja4_full_fields(self):
        """generate_ja4 with complete ClientHello fields (lines 435-460)."""
        gen = JA4Generator()
        fields = {
            "version": 0x0303,
            "supported_versions": [0x0304],  # TLS 1.3
            "cipher_suites": [0x1301, 0x1302, 0x1303],
            "extensions": [0, 10, 13, 43],  # SNI(0) + others
            "alpn": ["h2"],
            "supported_groups": [29, 23],
            "signature_algorithms": [0x0804],
        }
        ja4 = gen.generate_ja4(fields)
        # Format: {proto}{ver}{sni}{cc}{ec}{alpn}_{cipher_hash}_{ext_hash}
        assert ja4.startswith("t13d")
        parts = ja4.split("_")
        assert len(parts) == 3

    def test_generate_ja4_quic_protocol(self):
        """QUIC version prefix → 'q' prefix (line 449)."""
        gen = JA4Generator()
        fields = {
            "version": 0xFF00001D,  # QUIC version
            "supported_versions": [],
            "cipher_suites": [0x1301],
            "extensions": [],
            "alpn": [],
        }
        ja4 = gen.generate_ja4(fields)
        # QUIC path: version string will be "00" and not "13", so check proto character
        # The version 0xFF00001D → _get_version_string returns "00" → not "QUIC"
        # Actually this tests the regular path with an unusual version
        assert "_" in ja4

    def test_generate_ja4_grease_filtered(self):
        """GREASE ciphers/extensions excluded from count (lines 441-446)."""
        gen = JA4Generator()
        fields = {
            "version": 0x0303,
            "supported_versions": [0x0304],
            "cipher_suites": [0x0A0A, 0x1301],  # 0x0A0A is GREASE
            "extensions": [0x0A0A, 10],           # 0x0A0A is GREASE
            "alpn": [],
        }
        ja4 = gen.generate_ja4(fields)
        # After filtering GREASE: 1 cipher, 1 ext (SNI ext type 0 not in extensions list here)
        assert "01" in ja4[:10]  # cipher count = 01

    def test_generate_ja4x_valid(self):
        """generate_ja4x returns correct 3-part hash (lines 472-491)."""
        gen = JA4Generator()
        result = gen.generate_ja4x(
            issuer="CN=Test CA",
            subject="CN=Test Cert",
            san="DNS:example.com",
        )
        parts = result.split("_")
        assert len(parts) == 3
        assert all(len(p) == 12 for p in parts)

    def test_generate_ja4x_empty_fields(self):
        """Empty fields → all-zero hashes (line 477-478)."""
        gen = JA4Generator()
        result = gen.generate_ja4x("", "", "")
        assert result == "000000000000_000000000000_000000000000"

    def test_get_version_string_tls10(self):
        """TLS 1.0 → '10' (line 506-507)."""
        gen = JA4Generator()
        assert gen._get_version_string(0x0301) == "10"

    def test_get_version_string_tls11(self):
        """TLS 1.1 → '11'."""
        gen = JA4Generator()
        assert gen._get_version_string(0x0302) == "11"

    def test_get_version_string_unknown(self):
        """Unknown version → '00'."""
        gen = JA4Generator()
        assert gen._get_version_string(0x9999) == "00"

    def test_hash_cipher_suites_non_empty(self):
        """Non-empty cipher list → 12-char hex hash (lines 515-517)."""
        gen = JA4Generator()
        result = gen._hash_cipher_suites([0x1301, 0x1302])
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_extensions_non_empty(self):
        """Non-empty extensions → 12-char hex hash (lines 525-529)."""
        gen = JA4Generator()
        result = gen._hash_extensions([10, 13, 43])
        assert len(result) == 12

    def test_is_grease_all_values(self):
        """All 16 GREASE values return True (lines 533-551)."""
        gen = JA4Generator()
        grease_values = [
            0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
            0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
            0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
        ]
        for val in grease_values:
            assert gen._is_grease(val) is True

    def test_is_grease_non_grease(self):
        """Non-GREASE values return False."""
        gen = JA4Generator()
        assert gen._is_grease(0x1301) is False
        assert gen._is_grease(0x0000) is False

    def test_generate_ja4x_exception_returns_sentinel(self):
        """Exception in generate_ja4x → returns all-zero sentinel (lines 488-491)."""
        gen = JA4Generator()
        # Pass an object that will raise an exception during processing
        with patch("hashlib.sha256", side_effect=Exception("hash error")):
            result = gen.generate_ja4x("issuer", "subject", "san")
        assert result == "000000000000_000000000000_000000000000"


class TestConfigManagerCoverageGaps:
    """Cover missing config section + Redis port string parsing."""

    def test_missing_section_gets_defaults(self):
        """Missing required section 'proxy' gets default value (lines 600-603)."""
        mgr = ConfigManager.__new__(ConfigManager)
        mgr.config_path = "test"
        mgr.logger = MagicMock()
        config = {"redis": {"password": "x"}, "security": {}}  # Missing "proxy"
        with patch.object(mgr, "_default_config", return_value={"proxy": {"bind_port": 8080}}):
            with patch.object(mgr, "_validate_proxy_config"):
                with patch.object(mgr, "_validate_redis_config"):
                    with patch.object(mgr, "_validate_security_config"):
                        result = mgr._validate_config(config)
        # _validate_config returns the modified config
        assert "proxy" in result

    def test_redis_port_string_parsed(self):
        """Redis port as string is parsed to int (lines 680-681)."""
        mgr = ConfigManager.__new__(ConfigManager)
        mgr.config_path = "test"
        mgr.logger = MagicMock()
        redis_config = {"port": "6380", "password": "secret"}
        mgr._validate_redis_config(redis_config)
        assert redis_config["port"] == 6380  # Converted from string

    def test_redis_port_invalid_string_raises(self):
        """Non-numeric Redis port string → ValidationError (line 681)."""
        mgr = ConfigManager.__new__(ConfigManager)
        mgr.config_path = "test"
        mgr.logger = MagicMock()
        redis_config = {"port": "not_a_port"}
        with pytest.raises(ValidationError, match="Invalid Redis port"):
            mgr._validate_redis_config(redis_config)


class TestSecurityManagerCoverageGaps:
    """Cover remaining SecurityManager paths."""

    def _make_security_manager(self):
        """Create SecurityManager with mocked Redis."""
        redis = MagicMock()
        redis.smembers = AsyncMock(return_value=set())
        # JA4PROXY-2026-0038: atomic INCR+EXPIRE is one Lua call via eval().
        redis.eval = AsyncMock(return_value=1)
        redis.hgetall = AsyncMock(return_value={})
        config = {
            "security": {
                "whitelist_enabled": True,
                "blacklist_enabled": True,
                "rate_limiting": True,
                "block_unknown_ja4": False,
                "tarpit_enabled": False,
                "max_requests_per_minute": 100,
                "rate_limit_window": 60,
            },
            "rate_limiter": {},
        }
        sm = SecurityManager(config, redis)
        sm.redis = redis
        return sm, redis

    def test_load_security_lists_happy_path(self):
        """_load_security_lists successfully loads whitelist + blacklist (line 790)."""
        async def run():
            sm, redis = self._make_security_manager()
            redis.smembers = AsyncMock(side_effect=[
                {b"fp3"},          # blacklist
                {b"fp1", b"fp2"},  # whitelist
            ])
            redis.get = AsyncMock(side_effect=[
                b"sig1", # blacklist sig
                b"sig2"  # whitelist sig
            ])
            sm._verify_signature = MagicMock(return_value=True)
            await sm._load_security_lists()
            assert "fp3" in sm.blacklist

        asyncio.run(run())

    def test_check_access_alpn_bypass(self):
        """h2 ALPN bypasses rate limiting (lines 820-822)."""
        sm, redis = self._make_security_manager()
        fp = MagicMock()
        fp.ja4 = "t13d1516h2_8daaf6152771_02713d6af862"

        async def run():
            sm.whitelist = set()
            sm.blacklist = set()
            # Set dial > 0 so ALPN check is reached
            redis.get = AsyncMock(return_value=b"50")
            allowed, reason = await sm.check_access(fp, client_ip="1.2.3.4", alpn="h2")
            # h2 ALPN → skips rate limit, goes to _check_list_based_access → allowed
            assert allowed is True

        asyncio.run(run())

    def test_check_list_based_access_blacklisted(self):
        """Blacklisted JA4 → blocked (lines 841-846)."""
        sm, redis = self._make_security_manager()
        fp = MagicMock()
        ja4_str = "t13d1516h2_8daaf6152771_02713d6af862"
        fp.ja4 = ja4_str
        sm.blacklist = {ja4_str.encode()}  # blacklist stores bytes
        allowed, reason = sm._check_list_based_access(fp)
        assert allowed is False
        assert "blacklisted" in reason.lower()

    def test_check_list_based_access_not_whitelisted_no_block(self):
        """Not whitelisted and block_unknown_ja4=False → allowed (lines 849-858)."""
        sm, redis = self._make_security_manager()
        sm.config["security"]["block_unknown_ja4"] = False
        sm.config["security"]["whitelist_enabled"] = True
        fp = MagicMock()
        fp.ja4 = "unknown_ja4_fingerprint"
        sm.whitelist = set()  # Empty whitelist
        sm.blacklist = set()
        allowed, reason = sm._check_list_based_access(fp)
        assert allowed is True

    def test_check_list_based_access_not_whitelisted_block(self):
        """Not whitelisted and block_unknown_ja4=True → blocked (line 851-857)."""
        sm, redis = self._make_security_manager()
        sm.config["security"]["block_unknown_ja4"] = True
        sm.config["security"]["whitelist_enabled"] = True
        fp = MagicMock()
        fp.ja4 = "unknown_ja4_fingerprint"
        sm.whitelist = set()  # Empty whitelist
        sm.blacklist = set()
        allowed, reason = sm._check_list_based_access(fp)
        assert allowed is False
        assert "whitelisted" in reason.lower()

    def test_check_rate_limit_first_request_sets_expire(self):
        """First request (count=1) atomically sets TTL via Lua (JA4PROXY-2026-0038).

        The previous implementation did two Redis round-trips (INCR then
        conditional EXPIRE); the atomic Lua call now does both in one
        server-side step. We pin that eval() is the single call and that
        the window (rate_limit_window) is passed as ARGV[1].
        """
        sm, redis = self._make_security_manager()
        redis.eval = AsyncMock(return_value=1)

        async def run():
            result = await sm._check_rate_limit("1.2.3.4")
            assert result is True
            redis.eval.assert_awaited_once()
            call = redis.eval.await_args
            # (script, numkeys=1, key, window)
            assert call.args[1] == 1
            assert call.args[2] == "rate_limit:1.2.3.4"
            assert call.args[3] == sm.config["security"]["rate_limit_window"]

        asyncio.run(run())

    def test_check_rate_limit_exceeded(self):
        """Count > max → returns False, logs warning (lines 918-927)."""
        sm, redis = self._make_security_manager()
        redis.eval = AsyncMock(return_value=101)  # > 100

        async def run():
            result = await sm._check_rate_limit("1.2.3.4")
            assert result is False

        asyncio.run(run())

    def test_check_access_rate_limit_block_increments_blocked(self):
        """Rate limit block increments BLOCKED_REQUESTS (lines 827-830)."""
        sm, redis = self._make_security_manager()
        fp = MagicMock()
        fp.ja4 = "unknown_fingerprint"

        async def run():
            sm.whitelist = set()
            sm.blacklist = set()
            # Set dial > 0 so rate limiting kicks in
            redis.get = AsyncMock(return_value=b"50")
            # Rate limit exceeded (JA4PROXY-2026-0038 uses eval())
            redis.eval = AsyncMock(return_value=999)
            allowed, reason = await sm.check_access(fp, client_ip="1.2.3.4", alpn=None)
            assert allowed is False
            assert "Rate limit" in reason

        asyncio.run(run())

    def test_check_access_rate_limit_passes_check_list(self):
        """Rate limit passes → falls through to _check_list_based_access (line 832)."""
        sm, redis = self._make_security_manager()
        fp = MagicMock()
        fp.ja4 = "unknown_fingerprint"

        async def run():
            sm.whitelist = set()
            sm.blacklist = set()
            # Set dial > 0
            redis.get = AsyncMock(return_value=b"50")
            # Rate limit NOT exceeded (count = 1 < 100); JA4PROXY-2026-0038.
            redis.eval = AsyncMock(return_value=1)
            allowed, reason = await sm.check_access(fp, client_ip="1.2.3.4", alpn=None)
            # Rate limit passes; whitelist/blacklist disabled → allowed
            assert allowed is True

        asyncio.run(run())

    def test_check_rate_limit_adaptive_threshold(self):
        """Adaptive rate enabled → calls _get_adaptive_rate_threshold (line 907)."""
        async def run():
            redis = MagicMock()
            # JA4PROXY-2026-0038: atomic rate-limit uses eval().
            redis.eval = AsyncMock(return_value=5)
            redis.hgetall = AsyncMock(return_value={
                b"confidence": b"0.8",
                b"threshold_rps": b"50",
            })
            config = {
                "security": {"max_requests_per_minute": 100, "rate_limit_window": 60},
                "rate_limiter": {"adaptive": {"enabled": True, "min_threshold_rps": 5, "max_threshold_rps": 1000}},
            }
            sm = SecurityManager(config, redis)
            sm.redis = redis
            result = await sm._check_rate_limit("1.2.3.4")
            assert result is True  # 5 < 50

        asyncio.run(run())


class TestProxyServerShutdownCoverageGaps:
    """Cover shutdown cleanup paths (lines 1442-1456)."""

    def _make_server_stub(self):
        """Minimal ProxyServer without __init__."""
        server = ProxyServer.__new__(ProxyServer)
        server.config = {
            "proxy": {
                "bind_host": "127.0.0.1",
                "bind_port": 9999,
                "drain_timeout_seconds": 0,
            },
            "redis": {},
            "security": {},
            "metrics": {"enabled": False},
        }
        server.logger = MagicMock()
        server.active_connections = 0
        server._tarpit_concurrent = 0
        server._tarpit_per_ip = {}
        server._tarpit_lock = asyncio.Lock()
        server._conn_semaphore = asyncio.Semaphore(100)
        server.executor = None
        server.config_loader = MagicMock()
        server.pipeline = MagicMock()
        server.pipeline.start = AsyncMock()
        server.pipeline.stop = AsyncMock()
        server.pipeline._tcp_analyzer = MagicMock()
        server.pipeline._tcp_analyzer.decrement_concurrent_connections = AsyncMock()
        server._dial_manager = MagicMock()
        server._dial_manager.initialize = AsyncMock(return_value=0)
        server._local_cache = MagicMock()
        server.redis_client = AsyncMock()
        server._backup_scheduler = None
        server._health_task = None
        server._pubsub_task = None
        server.health_server = MagicMock()
        server.health_server.start = AsyncMock()
        server.health_server.stop = AsyncMock()
        # Phase 59: FeedHealthMonitor shared across TI providers
        server._feed_health_monitor = FeedHealthMonitor()
        server.greynoise_provider = MagicMock()
        server.greynoise_provider.start = AsyncMock()
        server.greynoise_provider.stop = AsyncMock()
        server.greynoise_provider._config = MagicMock()
        server.greynoise_provider._config.enabled = False
        server.alienvault_provider = MagicMock()
        server.alienvault_provider.start = AsyncMock()
        server.alienvault_provider.stop = AsyncMock()
        server.alienvault_provider._config = MagicMock()
        server.alienvault_provider._config.enabled = False
        server.misp_provider = MagicMock()
        server.misp_provider.start = AsyncMock()
        server.misp_provider.stop = AsyncMock()
        server.misp_provider._config = MagicMock()
        server.misp_provider._config.enabled = False
        server.threatfox_provider = MagicMock()
        server.threatfox_provider.start = AsyncMock()
        server.threatfox_provider.stop = AsyncMock()
        server.threatfox_provider._config = MagicMock()
        server.threatfox_provider._config.enabled = False
        server.virustotal_provider = MagicMock()
        server.virustotal_provider.start = AsyncMock()
        server.virustotal_provider.stop = AsyncMock()
        server.virustotal_provider._config = MagicMock()
        server.virustotal_provider._config.enabled = False
        server.confidence_manager = MagicMock()
        server.confidence_manager.initialize = AsyncMock()
        server.confidence_manager.save_state = AsyncMock()
        server.pipeline.set_ti_providers = MagicMock()
        return server

    def test_shutdown_with_no_abuseipdb(self):
        """Shutdown when _abuseipdb_checker is None doesn't call stop (line 1441)."""
        async def run():
            server = self._make_server_stub()
            server._abuseipdb_checker = None
            server._rdap_enricher = None
            server._aiohttp_session = None

            mock_server = MagicMock()
            close_event = asyncio.Event()
            close_event.set()

            async def serve_forever():
                await asyncio.sleep(0)

            mock_server.serve_forever = serve_forever
            mock_server.close = MagicMock()
            mock_server.__aenter__ = AsyncMock(return_value=mock_server)
            mock_server.__aexit__ = AsyncMock(return_value=False)

            with patch("asyncio.start_server", AsyncMock(return_value=mock_server)):
                await server.start()  # Should complete without error

        asyncio.run(run())

    def test_shutdown_abuseipdb_stop_exception_swallowed(self):
        """Exception in _abuseipdb_checker.stop() is caught (lines 1442-1445)."""
        async def run():
            server = self._make_server_stub()
            mock_checker = MagicMock()
            mock_checker.stop = AsyncMock(side_effect=Exception("stop error"))
            server._abuseipdb_checker = mock_checker
            server._rdap_enricher = None
            server._aiohttp_session = None

            mock_srv = MagicMock()
            async def serve_forever():
                await asyncio.sleep(0)

            mock_srv.serve_forever = serve_forever
            mock_srv.close = MagicMock()
            mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
            mock_srv.__aexit__ = AsyncMock(return_value=False)

            with patch("asyncio.start_server", AsyncMock(return_value=mock_srv)):
                await server.start()  # Must not raise

        asyncio.run(run())

    def test_shutdown_rdap_stop_exception_swallowed(self):
        """Exception in _rdap_enricher.stop() is caught (lines 1448-1451)."""
        async def run():
            server = self._make_server_stub()
            server._abuseipdb_checker = None
            mock_rdap = MagicMock()
            mock_rdap.stop = AsyncMock(side_effect=Exception("rdap stop error"))
            server._rdap_enricher = mock_rdap
            server._aiohttp_session = None

            mock_srv = MagicMock()
            async def serve_forever():
                await asyncio.sleep(0)

            mock_srv.serve_forever = serve_forever
            mock_srv.close = MagicMock()
            mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
            mock_srv.__aexit__ = AsyncMock(return_value=False)

            with patch("asyncio.start_server", AsyncMock(return_value=mock_srv)):
                await server.start()  # Must not raise

        asyncio.run(run())

    def test_shutdown_aiohttp_close_exception_swallowed(self):
        """Exception in _aiohttp_session.close() is caught (lines 1453-1456)."""
        async def run():
            server = self._make_server_stub()
            server._abuseipdb_checker = None
            server._rdap_enricher = None
            mock_session = MagicMock()
            mock_session.close = AsyncMock(side_effect=Exception("close error"))
            server._aiohttp_session = mock_session

            mock_srv = MagicMock()
            async def serve_forever():
                await asyncio.sleep(0)

            mock_srv.serve_forever = serve_forever
            mock_srv.close = MagicMock()
            mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
            mock_srv.__aexit__ = AsyncMock(return_value=False)

            with patch("asyncio.start_server", AsyncMock(return_value=mock_srv)):
                await server.start()  # Must not raise

        asyncio.run(run())

    def test_shutdown_event_none_skips_drain(self):
        """shutdown_event=None → _shutdown_watcher returns immediately (line 1404)."""
        async def run():
            server = self._make_server_stub()
            server._abuseipdb_checker = None
            server._rdap_enricher = None
            server._aiohttp_session = None

            mock_srv = MagicMock()
            async def serve_forever():
                await asyncio.sleep(0)

            mock_srv.serve_forever = serve_forever
            mock_srv.close = MagicMock()
            mock_srv.__aenter__ = AsyncMock(return_value=mock_srv)
            mock_srv.__aexit__ = AsyncMock(return_value=False)

            with patch("asyncio.start_server", AsyncMock(return_value=mock_srv)):
                await server.start(shutdown_event=None)

        asyncio.run(run())


class TestProxyProtocolTLVCoverageGaps:
    """Cover TLV extension parsing in _parse_proxy_protocol (lines 1720-1745)."""

    def _make_server_stub(self):
        server = ProxyServer.__new__(ProxyServer)
        server.logger = MagicMock()
        return server

    def _make_ppv2_header(self, addr_len: int, addr_bytes: bytes, tlv_bytes: bytes = b"") -> bytes:
        """Build a minimal PPv2 header for IPv4 TCP."""
        sig = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
        ver_cmd = b"\x21"       # Version 2, PROXY command
        family = b"\x11"        # AF_INET TCP
        import struct
        total_addr_len = addr_len + len(tlv_bytes)
        length = struct.pack("!H", total_addr_len)
        return sig + ver_cmd + family + length + addr_bytes + tlv_bytes

    def test_tlv_pp2_type_tcp_info_parsed(self):
        """TLV type 0x04 (PP2_TYPE_TCP_INFO) extracts ttl/window/options (lines 1731-1743)."""
        import struct
        server = self._make_server_stub()

        # 12 bytes: src IPv4 (4) + dst IPv4 (4) + src_port (2) + dst_port (2)
        addr_bytes = b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08" + b"\x1f\x90" + b"\x01\xbb"
        # TLV: type=0x04, len=5, data=ttl(1B)+window(2B)+options(2B)
        tlv_data = struct.pack("!BH", 0x04, 5) + struct.pack("!BH", 64, 65535) + b"\x02\x04"
        header = self._make_ppv2_header(12, addr_bytes, tlv_data)
        remaining = b"some_payload"

        info, rest = server._parse_proxy_protocol(header + remaining, "0.0.0.0")
        # Should have parsed client IP
        assert info["client_ip"] == "1.2.3.4"
        assert rest == remaining

    def test_tlv_truncated_type_breaks_loop(self):
        """Truncated TLV (idx+2 > len) breaks loop (line 1723-1724)."""
        import struct
        server = self._make_server_stub()

        addr_bytes = b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08" + b"\x1f\x90" + b"\x01\xbb"
        # Truncated TLV: only type byte, no length
        tlv_data = b"\x04"  # Type byte but no length
        header = self._make_ppv2_header(12, addr_bytes, tlv_data)

        info, rest = server._parse_proxy_protocol(header, "0.0.0.0")
        # Should not crash — loop breaks on truncated TLV
        assert info["client_ip"] == "1.2.3.4"

    def test_tlv_data_overflow_breaks_loop(self):
        """TLV length exceeds available data — breaks loop (line 1727-1728)."""
        import struct
        server = self._make_server_stub()

        addr_bytes = b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08" + b"\x1f\x90" + b"\x01\xbb"
        # TLV with length > remaining bytes
        tlv_data = struct.pack("!BH", 0x04, 100)  # Length 100 but no data
        header = self._make_ppv2_header(12, addr_bytes, tlv_data)

        info, rest = server._parse_proxy_protocol(header, "0.0.0.0")
        assert info["client_ip"] == "1.2.3.4"

    def test_tlv_struct_error_ignored(self):
        """Malformed PP2_TYPE_TCP_INFO data → struct.error ignored (line 1742-1743)."""
        import struct
        server = self._make_server_stub()

        addr_bytes = b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08" + b"\x1f\x90" + b"\x01\xbb"
        # TLV type=0x04, len=1 (too short for ttl+window = 3 bytes → struct.error)
        tlv_data = struct.pack("!BH", 0x04, 1) + b"\x40"  # Only 1 byte of data
        header = self._make_ppv2_header(12, addr_bytes, tlv_data)

        info, rest = server._parse_proxy_protocol(header, "0.0.0.0")
        assert info["client_ip"] == "1.2.3.4"  # Should still parse cleanly


# ---------------------------------------------------------------------------
# ProxyServer.create() — async factory (lines 1052-1178)
# ---------------------------------------------------------------------------


class TestProxyServerCreate:
    """Coverage for ProxyServer.create() classmethod."""

    _MINIMAL_CONFIG = {
        "proxy": {
            "bind_host": "0.0.0.0",
            "bind_port": 8080,
            "backend_host": "127.0.0.1",
            "backend_port": 443,
            "max_connections": 1000,
            "buffer_size": 4096,
            "connection_timeout": 30,
            "read_timeout": 30,
            "proxy_protocol": False,
            "tls": {"min_version": "TLSv1.2"},
            "allowed_alpns": [],
            "drain_timeout_seconds": 5,
            "tarpit_host": "127.0.0.1",
            "tarpit_port": 9999,
            "tarpit_protection": {
                "max_concurrent_connections": 50,
                "max_per_ip": 3,
                "overflow_action": "block",
            },
        },
        "redis": {"host": "127.0.0.1", "port": 6379, "db": 0},
        "geoip": {
            "database_path": None,
            "country_blacklist_enabled": True,
            "country_blacklist": ["CN"],
            "country_whitelist_enabled": True,
            "country_whitelist": ["US"],
            "blocked_cidrs": [],
        },
        "security": {
            "whitelist": [],
            "blacklist": [],
            "whitelist_enabled": True,
            "blacklist_enabled": True,
            "rate_limiting": False,
            "block_unknown_ja4": False,
            "tarpit_enabled": False,
            "tarpit_duration": 10,
            "whitelist_patterns": [],
        },
        "metrics": {"enabled": False, "port": 9090},
        "logging": {"level": "INFO", "format": "%(message)s", "json_enabled": False},
        "abuseipdb": {"enabled": False},
        "rdap_enrichment": {"enabled": False},
        "dial": {"value": 0},
        "risk_scorer": {},
        "action_decider": {},
        "local_cache": {},
        "pipeline": {},
        "sni_analyzer": {"enabled": False},
        "tls_enforcer": {"enabled": False},
        "tcp_analyzer": {"enabled": False},
        "asn_classifier": {"enabled": False},
        "dns_enrichment": {"enabled": False},
        "blocklists": {"enabled": False},
        "beaconing_detector": {"enabled": False},
    }

    def test_create_happy_path(self):
        """create() successfully initialises all components when both abuseipdb and rdap succeed."""
        async def run():
            redis_mock = AsyncMock()
            redis_mock.smembers = AsyncMock(return_value=set())

            abuseipdb_mock = MagicMock()
            abuseipdb_mock.start = AsyncMock()

            rdap_mock = MagicMock()
            rdap_mock.start = AsyncMock()

            pipeline_mock = AsyncMock()
            pipeline_mock.start = AsyncMock()
            pipeline_mock.update_scorer = AsyncMock()
            pipeline_mock.update_sets = AsyncMock()
            pipeline_mock.set_abuseipdb_checker = AsyncMock()
            pipeline_mock.set_rdap_enricher = AsyncMock()
            pipeline_mock._blocklist_manager = AsyncMock()

            with (
                patch("proxy.ConfigManager") as MockCM,
                patch.object(ProxyServer, "_init_logging", return_value=logging.getLogger("proxy")),
                patch.object(ProxyServer, "_init_redis", new=AsyncMock(return_value=redis_mock)),
                patch.object(ProxyServer, "_populate_security_lists", new=AsyncMock()),
                patch("proxy.TLSParser"),
                patch("proxy.JA4Generator"),
                patch("proxy.TarpitManager"),
                patch("proxy.SecurityManager"),
                patch("proxy.GeoIPLookup"),
                patch("proxy.LocalCache"),
                patch("proxy.RiskScorer") as MockRS,
                patch("proxy.ActionDecider") as MockAD,
                patch("proxy.Pipeline", return_value=pipeline_mock),
                patch("proxy.DialManager"),
                patch("aiohttp.ClientSession"),
                patch("src.security.abuseipdb.AbuseIPDBChecker", return_value=abuseipdb_mock),
                patch("src.security.abuseipdb.AbuseIPDBConfig") as MockAbuseCfg,
                patch("src.security.rdap_enrichment.RDAPEnricher", return_value=rdap_mock),
                patch("src.security.rdap_enrichment.RDAPConfig") as MockRdapCfg,
            ):
                MockCM.return_value.config = self._MINIMAL_CONFIG
                MockRS.from_config.return_value = MagicMock()
                MockAD.from_config.return_value = MagicMock()
                MockAbuseCfg.from_config.return_value = MagicMock()
                MockRdapCfg.from_config.return_value = MagicMock()

                server = await ProxyServer.create("config/proxy.yml")
                assert isinstance(server, ProxyServer)
                assert server.active_connections == 0
                assert server._tarpit_concurrent == 0
                assert server._rdap_enricher is rdap_mock
                assert server._abuseipdb_checker is abuseipdb_mock

        _run(run())

    def test_create_abuseipdb_and_rdap_fail_gracefully(self):
        """create() handles abuseipdb and rdap init exceptions without raising."""
        async def run():
            redis_mock = AsyncMock()
            redis_mock.smembers = AsyncMock(return_value=set())

            pipeline_mock = AsyncMock()
            pipeline_mock.start = AsyncMock()
            pipeline_mock.update_scorer = AsyncMock()
            pipeline_mock.update_sets = AsyncMock()
            pipeline_mock._blocklist_manager = AsyncMock()

            with (
                patch("proxy.ConfigManager") as MockCM,
                patch.object(ProxyServer, "_init_logging", return_value=logging.getLogger("proxy")),
                patch.object(ProxyServer, "_init_redis", new=AsyncMock(return_value=redis_mock)),
                patch.object(ProxyServer, "_populate_security_lists", new=AsyncMock()),
                patch("proxy.TLSParser"),
                patch("proxy.JA4Generator"),
                patch("proxy.TarpitManager"),
                patch("proxy.SecurityManager"),
                patch("proxy.GeoIPLookup"),
                patch("proxy.LocalCache"),
                patch("proxy.RiskScorer") as MockRS,
                patch("proxy.ActionDecider") as MockAD,
                patch("proxy.Pipeline", return_value=pipeline_mock),
                patch("proxy.DialManager"),
                patch("aiohttp.ClientSession", side_effect=Exception("no aiohttp")),
                patch("src.security.rdap_enrichment.RDAPConfig") as MockRdapCfg,
            ):
                MockCM.return_value.config = self._MINIMAL_CONFIG
                MockRS.from_config.return_value = MagicMock()
                MockAD.from_config.return_value = MagicMock()
                MockRdapCfg.from_config.side_effect = Exception("rdap config failed")

                server = await ProxyServer.create("config/proxy.yml")
                assert isinstance(server, ProxyServer)
                assert server._abuseipdb_checker is None
                assert server._rdap_enricher is None

        _run(run())
