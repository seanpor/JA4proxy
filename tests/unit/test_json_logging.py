"""Unit tests for Phase 14a: JSON logging and startup secrets hardening.

Tests cover:
- JSONFormatter: every log line is parseable JSON
- JSONFormatter: correct fields (timestamp, level, subsystem, message)
- JSONFormatter: SensitiveDataFilter strips secrets before JSON output
- JSONFormatter: exception text included when present; no full traceback in production
- _init_logging: selects JSONFormatter when json_enabled=true
- _init_logging: selects JSONFormatter when ENVIRONMENT=production
- _init_logging: selects SecureFormatter when json_enabled=false + non-production
- Startup: ENVIRONMENT=production + no Redis password → sys.exit(1)
"""

import json
import logging
import os
import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from proxy import JSONFormatter, SensitiveDataFilter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    msg: str,
    level: int = logging.INFO,
    name: str = "proxy",
    args: tuple = (),
    exc_info=None,
) -> logging.LogRecord:
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="proxy.py",
        lineno=1,
        msg=msg,
        args=args,
        exc_info=exc_info,
    )
    return record


def _filtered_record(msg: str, **kwargs) -> logging.LogRecord:
    """Return a LogRecord that has been run through SensitiveDataFilter."""
    record = _make_record(msg, **kwargs)
    f = SensitiveDataFilter()
    f.filter(record)
    return record


# ---------------------------------------------------------------------------
# JSONFormatter: output is valid JSON
# ---------------------------------------------------------------------------


class TestJSONFormatterOutputIsValidJSON:
    def test_simple_message_parses(self):
        fmt = JSONFormatter()
        record = _make_record("hello world")
        output = fmt.format(record)
        parsed = json.loads(output)  # must not raise
        assert parsed["message"] == "hello world"

    def test_message_with_format_args(self):
        fmt = JSONFormatter()
        record = _make_record("ip=%s action=%s", args=("1.2.3.4", "block"))
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "ip=1.2.3.4" in parsed["message"]
        assert "action=block" in parsed["message"]

    def test_100_lines_all_parse(self):
        fmt = JSONFormatter()
        for i in range(100):
            record = _make_record(f"connection {i} | ip=10.0.0.{i % 256} | score={i}")
            output = fmt.format(record)
            json.loads(output)  # raises if invalid

    def test_message_with_special_characters(self):
        fmt = JSONFormatter()
        record = _make_record('reason="quota exceeded" url="https://example.com/path?q=1&r=2"')
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "quota exceeded" in parsed["message"]


# ---------------------------------------------------------------------------
# JSONFormatter: required fields
# ---------------------------------------------------------------------------


class TestJSONFormatterFields:
    def test_has_timestamp_field(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg")))
        assert "timestamp" in parsed

    def test_timestamp_is_iso8601_with_z(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg")))
        ts = parsed["timestamp"]
        # Must end with Z and contain T separator
        assert ts.endswith("Z")
        assert "T" in ts
        # Must have milliseconds: 2026-03-15T14:30:01.234Z
        assert len(ts) == len("2026-03-15T14:30:01.234Z")

    def test_level_field_info(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", level=logging.INFO)))
        assert parsed["level"] == "INFO"

    def test_level_field_warning(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", level=logging.WARNING)))
        assert parsed["level"] == "WARNING"

    def test_level_field_critical(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", level=logging.CRITICAL)))
        assert parsed["level"] == "CRITICAL"

    def test_subsystem_field(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", name="proxy.pipeline")))
        assert parsed["subsystem"] == "proxy.pipeline"

    def test_message_field(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("the message")))
        assert parsed["message"] == "the message"

    def test_no_exception_field_when_no_exc(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg")))
        assert "exception" not in parsed


# ---------------------------------------------------------------------------
# JSONFormatter: exception handling
# ---------------------------------------------------------------------------


class TestJSONFormatterExceptions:
    def test_exception_field_present_when_exc(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("something broke")
        except ValueError:
            exc_info = sys.exc_info()
        record = _make_record("error occurred", exc_info=exc_info)
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]

    def test_no_stack_trace_in_production(self):
        fmt = JSONFormatter()
        try:
            raise RuntimeError("oops")
        except RuntimeError:
            exc_info = sys.exc_info()
        record = _make_record("error occurred", exc_info=exc_info)
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            output = fmt.format(record)
        parsed = json.loads(output)
        # Should have exception field with type:message only — no Traceback lines
        assert "exception" in parsed
        assert "Traceback" not in parsed["exception"]
        assert "RuntimeError" in parsed["exception"]

    def test_full_traceback_in_development(self):
        fmt = JSONFormatter()
        try:
            raise RuntimeError("oops")
        except RuntimeError:
            exc_info = sys.exc_info()
        record = _make_record("error occurred", exc_info=exc_info)
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            output = fmt.format(record)
        parsed = json.loads(output)
        # In dev, exc_text includes traceback
        assert "exception" in parsed
        assert "RuntimeError" in parsed["exception"]


# ---------------------------------------------------------------------------
# JSONFormatter: SensitiveDataFilter strips secrets before JSON output
# ---------------------------------------------------------------------------


class TestJSONFormatterSensitiveData:
    """SensitiveDataFilter runs before JSONFormatter (as a handler Filter).
    These tests simulate that pipeline: filter the record first, then format.
    """

    def test_password_not_in_json_output(self):
        fmt = JSONFormatter()
        record = _filtered_record("connecting with password=s3cr3t to redis")
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "s3cr3t" not in parsed["message"]
        assert "***REDACTED***" in parsed["message"]

    def test_api_key_not_in_json_output(self):
        fmt = JSONFormatter()
        record = _filtered_record("api_key=abc123xyz loaded")
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "abc123xyz" not in parsed["message"]

    def test_clean_message_passes_through(self):
        fmt = JSONFormatter()
        record = _filtered_record("connection allowed | ip=1.2.3.4 | score=12")
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "1.2.3.4" in parsed["message"]
        assert parsed["message"] == "connection allowed | ip=1.2.3.4 | score=12"


# ---------------------------------------------------------------------------
# _init_logging: formatter selection
# ---------------------------------------------------------------------------


class TestInitLoggingFormatterSelection:
    """Tests that modify the global 'proxy' logger.

    Each test saves/restores the logger's handler list and level so no state
    leaks to other test modules.
    """

    def setup_method(self):
        logger = logging.getLogger("proxy")
        self._saved_handlers = logger.handlers[:]
        self._saved_level = logger.level

    def teardown_method(self):
        logger = logging.getLogger("proxy")
        logger.handlers = self._saved_handlers
        logger.level = self._saved_level

    def _make_server_with_config(self, log_config: dict, env: dict = None):
        """Build a minimal ProxyServer stub with the given logging config."""
        from proxy import ProxyServer

        server = object.__new__(ProxyServer)
        server.config = {
            "logging": log_config,
            "geoip": {"country_whitelist": [], "country_blacklist": []},
        }
        env = env or {}
        with patch.dict(os.environ, env, clear=False):
            server.logger = server._init_logging()
        return server

    def _get_formatter(self, server) -> logging.Formatter:
        logger = server.logger
        for handler in logger.handlers:
            return handler.formatter
        return None

    def test_json_enabled_true_uses_json_formatter(self):
        from proxy import JSONFormatter

        server = self._make_server_with_config({"level": "INFO", "json_enabled": True})
        assert isinstance(self._get_formatter(server), JSONFormatter)

    def test_json_enabled_false_uses_secure_formatter(self):
        from proxy import SecureFormatter

        with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=False):
            server = self._make_server_with_config(
                {"level": "INFO", "json_enabled": False},
                env={"ENVIRONMENT": "development"},
            )
        assert isinstance(self._get_formatter(server), SecureFormatter)

    def test_production_env_auto_enables_json(self):
        from proxy import JSONFormatter

        server = self._make_server_with_config(
            {"level": "INFO", "json_enabled": False},
            env={"ENVIRONMENT": "production"},
        )
        assert isinstance(self._get_formatter(server), JSONFormatter)

    def test_sensitive_filter_always_present(self):
        from proxy import SensitiveDataFilter

        server = self._make_server_with_config({"level": "INFO", "json_enabled": True})
        logger = server.logger
        for handler in logger.handlers:
            filters = handler.filters
            assert any(isinstance(f, SensitiveDataFilter) for f in filters), (
                "SensitiveDataFilter must be on the handler regardless of formatter"
            )


# ---------------------------------------------------------------------------
# Startup: production + no password → sys.exit(1)
# ---------------------------------------------------------------------------


class TestStartupPasswordValidation:
    def _make_server_stub(self):
        from proxy import ProxyServer

        server = object.__new__(ProxyServer)
        server.config = {
            "logging": {"level": "INFO", "json_enabled": True},
            "redis": {"host": "redis", "port": 6379, "password": ""},
            "geoip": {"country_whitelist": [], "country_blacklist": []},
        }
        server.logger = MagicMock()
        return server

    @pytest.mark.asyncio
    async def test_missing_password_in_production_exits(self):
        server = self._make_server_stub()
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            with pytest.raises(SystemExit) as exc_info:
                await server._init_redis()
        assert exc_info.value.code == 1

    @pytest.mark.asyncio
    async def test_missing_password_in_production_logs_critical(self):
        server = self._make_server_stub()
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            with pytest.raises(SystemExit):
                await server._init_redis()
        server.logger.critical.assert_called_once()
        log_msg = server.logger.critical.call_args[0][0]
        assert "FATAL" in log_msg
        assert "startup_failed" in log_msg

    @pytest.mark.asyncio
    async def test_missing_password_in_development_only_warns(self):
        """In development, missing password is a warning — not a fatal."""
        server = self._make_server_stub()
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            # Will try to connect to Redis and fail — that's fine,
            # we just want to verify no sys.exit is called first.
            with pytest.raises(Exception) as exc_info:
                await server._init_redis()
        # Must NOT be a SystemExit
        assert not isinstance(exc_info.value, SystemExit)
        server.logger.warning.assert_called()
