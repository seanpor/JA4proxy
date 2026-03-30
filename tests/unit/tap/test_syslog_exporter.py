"""
Unit tests for src/tap/export/syslog_exporter.py — Phase 20, Group 9.
"""
import socket
from unittest.mock import MagicMock, patch

import pytest

from src.tap.export.syslog_exporter import SyslogExporter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> dict:
    cfg = {
        "host": "127.0.0.1",
        "port": 514,
        "format": "cef",
        "facility": 1,
        "app_name": "ja4proxy",
        "send_observe": True,
    }
    cfg.update(overrides)
    return cfg


def _make_exporter(**overrides) -> SyslogExporter:
    with patch("socket.socket"):
        exporter = SyslogExporter(_make_config(**overrides))
    return exporter


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCEFFormat:
    def test_cef_format_is_valid(self):
        """_format_cef must return a string starting with 'CEF:0'."""
        exporter = _make_exporter()
        result = exporter._format_cef("ban", "1.2.3.4", 80, "signal_ban", "t13d_abc")
        assert result.startswith("CEF:0")

    def test_cef_severity_mapping_signal_ban_is_9(self):
        """signal_ban event must map to CEF severity 9."""
        exporter = _make_exporter()
        result = exporter._format_cef("signal_ban", "1.2.3.4", 90, "signal_ban", None)
        # Severity appears as the 7th |-separated field
        parts = result.split("|")
        assert parts[6] == "9", f"Expected severity 9, got: {parts[6]}"

    def test_cef_severity_mapping_observe_is_3(self):
        """observe event must map to CEF severity 3."""
        exporter = _make_exporter()
        result = exporter._format_cef("observe", "1.2.3.4", 10, "observe", None)
        parts = result.split("|")
        assert parts[6] == "3", f"Expected severity 3, got: {parts[6]}"

    def test_cef_severity_mapping_signal_block_is_7(self):
        """signal_block event must map to CEF severity 7."""
        exporter = _make_exporter()
        result = exporter._format_cef("signal_block", "1.2.3.4", 70, "signal_block", None)
        parts = result.split("|")
        assert parts[6] == "7"

    def test_cef_includes_src_ip(self):
        """CEF extension must include src={ip}."""
        exporter = _make_exporter()
        result = exporter._format_cef("ban", "10.0.0.1", 80, "signal_ban", None)
        assert "src=10.0.0.1" in result

    def test_cef_includes_ja4_when_provided(self):
        """CEF extension must include ja4 when provided."""
        exporter = _make_exporter()
        result = exporter._format_cef("ban", "1.2.3.4", 80, "signal_ban", "t13d_abc")
        assert "ja4=t13d_abc" in result


class TestRFC5424Format:
    def test_rfc5424_format_valid(self):
        """_format_rfc5424 must return a string starting with '<' (priority field)."""
        exporter = _make_exporter()
        result = exporter._format_rfc5424("ban", "1.2.3.4", 80, "signal_ban", None)
        assert result.startswith("<"), f"RFC 5424 must start with priority: {result[:20]}"

    def test_rfc5424_contains_ip(self):
        """RFC 5424 message must contain the IP address."""
        exporter = _make_exporter()
        result = exporter._format_rfc5424("ban", "1.2.3.4", 80, "signal_ban", None)
        assert "1.2.3.4" in result

    def test_rfc5424_contains_json_body(self):
        """RFC 5424 message must contain a JSON body with event field."""
        exporter = _make_exporter()
        result = exporter._format_rfc5424("ban", "1.2.3.4", 80, "signal_ban", None)
        # Extract JSON part (after last space)
        assert '"event"' in result


class TestSendBehavior:
    def test_observe_not_sent_when_send_observe_false(self):
        """When send_observe=False, events with action='observe' must NOT be sent."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            exporter = SyslogExporter(_make_config(send_observe=False))
            exporter._sock = mock_sock

            exporter.send("observe", "1.2.3.4", 10, "observe", None)

            mock_sock.sendto.assert_not_called()

    def test_observe_sent_when_send_observe_true(self):
        """When send_observe=True, events with action='observe' must be sent."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            exporter = SyslogExporter(_make_config(send_observe=True))
            exporter._sock = mock_sock

            exporter.send("observe", "1.2.3.4", 10, "observe", None)

            mock_sock.sendto.assert_called_once()

    def test_signal_ban_always_sent(self):
        """signal_ban events must be sent regardless of send_observe setting."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            exporter = SyslogExporter(_make_config(send_observe=False))
            exporter._sock = mock_sock

            exporter.send("signal_ban", "1.2.3.4", 90, "signal_ban", None)

            mock_sock.sendto.assert_called_once()

    def test_close_closes_socket(self):
        """close() must close the underlying socket."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            exporter = SyslogExporter(_make_config())
            exporter._sock = mock_sock

            exporter.close()

            mock_sock.close.assert_called_once()
            assert exporter._sock is None
