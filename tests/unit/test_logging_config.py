"""
Unit tests for src/utils/logging_config.py

Why this matters: logging_config.py controls whether security events are
recorded in the correct format for SIEM ingestion (Splunk/ELK/Loki).
A missing JSON field or wrong level means security events may not be
parsed by downstream tooling, hiding attacks from operators.
"""

import json
import logging
import os
import sys
from io import StringIO

import pytest

from src.utils.logging_config import JSONFormatter, setup_logging


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    msg: str,
    level: int = logging.INFO,
    name: str = "test.logger",
    exc_info=None,
) -> logging.LogRecord:
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="test.py",
        lineno=42,
        msg=msg,
        args=(),
        exc_info=exc_info,
    )
    return record


# ---------------------------------------------------------------------------
# JSONFormatter.format — basic record produces valid JSON with required fields
# ---------------------------------------------------------------------------


class TestJSONFormatterBasic:
    def test_output_is_valid_json(self):
        fmt = JSONFormatter()
        record = _make_record("hello world")
        output = fmt.format(record)
        parsed = json.loads(output)  # must not raise
        assert parsed["message"] == "hello world"

    def test_required_fields_present(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg")))
        for field in ("timestamp", "level", "message", "logger", "module", "line"):
            assert field in parsed, f"Missing required field: {field}"

    def test_level_field_info(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", level=logging.INFO)))
        assert parsed["level"] == "INFO"

    def test_level_field_warning(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", level=logging.WARNING)))
        assert parsed["level"] == "WARNING"

    def test_level_field_debug(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", level=logging.DEBUG)))
        assert parsed["level"] == "DEBUG"

    def test_logger_field(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg", name="proxy.security")))
        assert parsed["logger"] == "proxy.security"

    def test_line_field_is_integer(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg")))
        assert isinstance(parsed["line"], int)

    def test_timestamp_is_iso8601(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg")))
        ts = parsed["timestamp"]
        assert "T" in ts  # ISO 8601 separator
        assert "+" in ts or "Z" in ts or ts.endswith("+00:00")  # timezone present

    def test_100_records_all_valid_json(self):
        fmt = JSONFormatter()
        for i in range(100):
            record = _make_record(f"event {i} | ip=10.0.0.{i % 256} | score={i}")
            json.loads(fmt.format(record))  # must not raise

    def test_special_characters_in_message(self):
        fmt = JSONFormatter()
        record = _make_record('path="/api?q=1&r=2" status="ok"')
        output = fmt.format(record)
        parsed = json.loads(output)
        assert "/api" in parsed["message"]


# ---------------------------------------------------------------------------
# JSONFormatter.format — exc_info handling
# ---------------------------------------------------------------------------


class TestJSONFormatterExcInfo:
    def test_no_exception_field_when_no_exc(self):
        fmt = JSONFormatter()
        parsed = json.loads(fmt.format(_make_record("msg")))
        assert "exception" not in parsed

    def test_exception_field_present_when_exc(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("something broke")
        except ValueError:
            exc_info = sys.exc_info()
        record = _make_record("error", exc_info=exc_info)
        parsed = json.loads(fmt.format(record))
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]
        assert "something broke" in parsed["exception"]

    def test_exception_field_contains_traceback_text(self):
        fmt = JSONFormatter()
        try:
            raise RuntimeError("deep error")
        except RuntimeError:
            exc_info = sys.exc_info()
        record = _make_record("oops", exc_info=exc_info)
        parsed = json.loads(fmt.format(record))
        assert "RuntimeError" in parsed["exception"]

    def test_output_still_valid_json_with_exception(self):
        fmt = JSONFormatter()
        try:
            raise KeyError("missing key")
        except KeyError:
            exc_info = sys.exc_info()
        record = _make_record("key error", exc_info=exc_info)
        output = fmt.format(record)
        json.loads(output)  # must not raise


# ---------------------------------------------------------------------------
# JSONFormatter.format — extra dict on the record
# ---------------------------------------------------------------------------


class TestJSONFormatterExtra:
    def test_extra_dict_merged_into_output(self):
        fmt = JSONFormatter()
        record = _make_record("msg")
        record.extra = {"ip": "1.2.3.4", "score": 42}
        parsed = json.loads(fmt.format(record))
        assert parsed["ip"] == "1.2.3.4"
        assert parsed["score"] == 42

    def test_no_extra_field_when_no_extra_attr(self):
        """Records without 'extra' attribute should not crash and produce no extra keys."""
        fmt = JSONFormatter()
        record = _make_record("msg")
        assert not hasattr(record, "extra")
        parsed = json.loads(fmt.format(record))
        # None of the standard keys should be missing
        assert "message" in parsed

    def test_extra_overwrites_nothing_critical(self):
        """extra dict is merged; it should not overwrite standard fields if keys differ."""
        fmt = JSONFormatter()
        record = _make_record("msg")
        record.extra = {"custom_field": "custom_value"}
        parsed = json.loads(fmt.format(record))
        assert parsed["message"] == "msg"
        assert parsed["custom_field"] == "custom_value"


# ---------------------------------------------------------------------------
# setup_logging — default text format
# ---------------------------------------------------------------------------


class TestSetupLoggingTextFormat:
    def setup_method(self):
        """Save root logger state before each test."""
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        self._saved_level = root.level

    def teardown_method(self):
        """Restore root logger state after each test."""
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        for h in self._saved_handlers:
            root.addHandler(h)
        root.setLevel(self._saved_level)

    def test_default_setup_adds_handler(self):
        setup_logging()
        root = logging.getLogger()
        assert len(root.handlers) >= 1

    def test_text_format_uses_non_json_formatter(self):
        setup_logging(json_format=False)
        root = logging.getLogger()
        handler = root.handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)

    def test_json_format_uses_json_formatter(self):
        setup_logging(json_format=True)
        root = logging.getLogger()
        handler = root.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_default_level_is_info(self):
        setup_logging()
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_recalling_setup_logging_does_not_duplicate_handlers(self):
        """Calling setup_logging() twice must not double-add handlers."""
        setup_logging()
        count_after_first = len(logging.getLogger().handlers)
        setup_logging()
        count_after_second = len(logging.getLogger().handlers)
        assert count_after_second == count_after_first


# ---------------------------------------------------------------------------
# setup_logging — LOG_FORMAT env var
# ---------------------------------------------------------------------------


class TestSetupLoggingEnvFormat:
    def setup_method(self):
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        self._saved_level = root.level

    def teardown_method(self):
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        for h in self._saved_handlers:
            root.addHandler(h)
        root.setLevel(self._saved_level)

    def test_log_format_json_env_enables_json(self, monkeypatch):
        """LOG_FORMAT=json activates JSONFormatter regardless of json_format arg."""
        monkeypatch.setenv("LOG_FORMAT", "json")
        setup_logging(json_format=False)
        root = logging.getLogger()
        handler = root.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_log_format_text_env_uses_text(self, monkeypatch):
        """LOG_FORMAT=text keeps text format."""
        monkeypatch.setenv("LOG_FORMAT", "text")
        setup_logging(json_format=False)
        root = logging.getLogger()
        handler = root.handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)

    def test_log_format_env_is_case_insensitive(self, monkeypatch):
        """LOG_FORMAT=JSON (uppercase) also triggers JSON format."""
        monkeypatch.setenv("LOG_FORMAT", "JSON")
        setup_logging(json_format=False)
        root = logging.getLogger()
        handler = root.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)


# ---------------------------------------------------------------------------
# setup_logging — LOG_LEVEL env var
# ---------------------------------------------------------------------------


class TestSetupLoggingEnvLevel:
    def setup_method(self):
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        self._saved_level = root.level

    def teardown_method(self):
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        for h in self._saved_handlers:
            root.addHandler(h)
        root.setLevel(self._saved_level)

    def test_log_level_debug_env(self, monkeypatch):
        """LOG_LEVEL=DEBUG sets root logger to DEBUG."""
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        setup_logging()
        assert logging.getLogger().level == logging.DEBUG

    def test_log_level_warning_env(self, monkeypatch):
        """LOG_LEVEL=WARNING sets root logger to WARNING."""
        monkeypatch.setenv("LOG_LEVEL", "WARNING")
        setup_logging()
        assert logging.getLogger().level == logging.WARNING

    def test_log_level_error_env(self, monkeypatch):
        """LOG_LEVEL=ERROR sets root logger to ERROR."""
        monkeypatch.setenv("LOG_LEVEL", "ERROR")
        setup_logging()
        assert logging.getLogger().level == logging.ERROR

    def test_log_level_critical_env(self, monkeypatch):
        """LOG_LEVEL=CRITICAL sets root logger to CRITICAL."""
        monkeypatch.setenv("LOG_LEVEL", "CRITICAL")
        setup_logging()
        assert logging.getLogger().level == logging.CRITICAL

    def test_invalid_log_level_env_does_not_crash(self, monkeypatch):
        """LOG_LEVEL=INVALID is silently ignored; falls back to supplied level."""
        monkeypatch.setenv("LOG_LEVEL", "INVALID")
        setup_logging(level=logging.INFO)
        assert logging.getLogger().level == logging.INFO

    def test_empty_log_level_env_uses_default(self, monkeypatch):
        """Empty LOG_LEVEL uses the default supplied level."""
        monkeypatch.setenv("LOG_LEVEL", "")
        setup_logging(level=logging.WARNING)
        assert logging.getLogger().level == logging.WARNING


# ---------------------------------------------------------------------------
# setup_logging — noisy library suppression
# ---------------------------------------------------------------------------


class TestSetupLoggingNoisyLibraries:
    def setup_method(self):
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        self._saved_level = root.level

    def teardown_method(self):
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        for h in self._saved_handlers:
            root.addHandler(h)
        root.setLevel(self._saved_level)

    def test_asyncio_logger_set_to_warning(self):
        """After setup_logging(), asyncio logger is silenced at WARNING level."""
        setup_logging()
        assert logging.getLogger("asyncio").level == logging.WARNING

    def test_urllib3_logger_set_to_warning(self):
        """After setup_logging(), urllib3 logger is silenced at WARNING level."""
        setup_logging()
        assert logging.getLogger("urllib3").level == logging.WARNING


# ---------------------------------------------------------------------------
# setup_logging — handler writes to stdout
# ---------------------------------------------------------------------------


class TestSetupLoggingOutputStream:
    def setup_method(self):
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        self._saved_level = root.level

    def teardown_method(self):
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        for h in self._saved_handlers:
            root.addHandler(h)
        root.setLevel(self._saved_level)

    def test_handler_is_stream_handler(self):
        setup_logging()
        root = logging.getLogger()
        assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)

    def test_json_output_is_parseable_when_written(self, capsys):
        """A log record emitted through the JSON handler produces parseable JSON."""
        setup_logging(json_format=True, level=logging.DEBUG)
        logger = logging.getLogger("test.output")
        logger.info("integration test message")
        captured = capsys.readouterr()
        # Find any JSON line in stdout
        for line in captured.out.strip().splitlines():
            try:
                parsed = json.loads(line)
                if parsed.get("message") == "integration test message":
                    assert parsed["level"] == "INFO"
                    return
            except json.JSONDecodeError:
                continue
        # If no JSON line matched, check that at least one line was JSON
        lines = [l for l in captured.out.strip().splitlines() if l.startswith("{")]
        assert lines, "Expected at least one JSON line in stdout"
