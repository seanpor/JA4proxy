"""
Phase 80 — ECS 8.x logging tests for src/utils/logging_config.py

These tests verify the ECS mode of JSONFormatter. They MUST FAIL
until the ECS mode is implemented in production code, since the current
JSONFormatter only produces legacy format (with 'timestamp', 'level',
'message' at top level, no '@timestamp' or ECS namespace fields).

ECS field name reference: https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
"""

from __future__ import annotations

import json
import logging

import pytest

from src.utils.logging_config import JSONFormatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    msg: str,
    level: int = logging.INFO,
    name: str = "test.logger",
    **extra_attrs,
) -> logging.LogRecord:
    """Create a LogRecord with optional extra attributes set directly on it."""
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="test_ecs_logging.py",
        lineno=10,
        msg=msg,
        args=(),
        exc_info=None,
    )
    for key, value in extra_attrs.items():
        setattr(record, key, value)
    return record


def _ecs_format(fields: dict, msg: str = "test event") -> dict:
    """
    Create an ECS-mode JSONFormatter, format the record, and return parsed JSON.
    Adds the given fields as direct record attributes (simulating logrus-style
    WithFields — in Python loggers, extra fields are passed via 'extra' dict
    which adds them as attributes).
    """
    fmt = JSONFormatter(format="ecs")
    record = _make_record(msg, **fields)
    output = fmt.format(record)
    return json.loads(output)


def _legacy_format(fields: dict, msg: str = "test event") -> dict:
    """Create a legacy JSONFormatter and return parsed JSON."""
    fmt = JSONFormatter()  # default = legacy
    record = _make_record(msg, **fields)
    return json.loads(fmt.format(record))


# ---------------------------------------------------------------------------
# @timestamp
# ---------------------------------------------------------------------------


class TestECSFormatterAtTimestamp:
    def test_ecs_formatter_at_timestamp_field(self):
        """ECS output must have '@timestamp', not 'timestamp'."""
        out = _ecs_format({})
        assert "@timestamp" in out, "ECS output missing '@timestamp' field"

    def test_ecs_formatter_no_legacy_timestamp(self):
        """ECS output must NOT have the legacy 'timestamp' field."""
        out = _ecs_format({})
        assert "timestamp" not in out, (
            "ECS output should not have 'timestamp' — use '@timestamp' instead"
        )

    def test_ecs_formatter_timestamp_is_rfc3339(self):
        """The @timestamp value must be a valid RFC3339/ISO8601 string with timezone."""
        from datetime import datetime

        out = _ecs_format({})
        ts = out["@timestamp"]
        assert isinstance(ts, str), f"@timestamp should be a string, got {type(ts)}"
        assert "T" in ts, f"@timestamp '{ts}' does not contain ISO8601 'T' separator"
        # Must have timezone information
        assert "+" in ts or "Z" in ts or ts.endswith("+00:00"), (
            f"@timestamp '{ts}' missing timezone information"
        )


# ---------------------------------------------------------------------------
# source.ip
# ---------------------------------------------------------------------------


class TestECSFormatterSourceIP:
    def test_ecs_formatter_source_ip(self):
        """'client_ip' log field maps to 'source.ip' in ECS output."""
        out = _ecs_format({"client_ip": "203.0.113.42"})
        assert out.get("source.ip") == "203.0.113.42", (
            f"source.ip = {out.get('source.ip')!r}, want '203.0.113.42'"
        )

    def test_ecs_formatter_source_ip_ipv6(self):
        """IPv6 client addresses are preserved in 'source.ip'."""
        out = _ecs_format({"client_ip": "2001:db8::1"})
        assert out.get("source.ip") == "2001:db8::1"

    def test_ecs_formatter_source_ip_absent_when_no_client_ip(self):
        """When client_ip is not set, source.ip must not appear in output."""
        out = _ecs_format({})
        assert "source.ip" not in out, "source.ip should not be present when client_ip is absent"

    def test_ecs_formatter_client_ip_not_at_top_level(self):
        """The raw 'client_ip' field should be remapped, not kept at top level."""
        out = _ecs_format({"client_ip": "10.0.0.1"})
        assert "client_ip" not in out, (
            "'client_ip' should be remapped to 'source.ip', not kept at top level"
        )


# ---------------------------------------------------------------------------
# event.action
# ---------------------------------------------------------------------------


class TestECSFormatterEventAction:
    def test_ecs_formatter_event_action(self):
        """'action' log field maps to 'event.action' in ECS output."""
        out = _ecs_format({"action": "block"})
        assert out.get("event.action") == "block", (
            f"event.action = {out.get('event.action')!r}, want 'block'"
        )

    def test_ecs_formatter_event_action_all_values(self):
        """All JA4proxy action values are passed through as event.action."""
        for action in ("allow", "block", "ban", "tarpit", "flagged", "rate_limited"):
            out = _ecs_format({"action": action})
            assert out.get("event.action") == action, (
                f"For action={action!r}: event.action = {out.get('event.action')!r}"
            )

    def test_ecs_formatter_action_not_at_top_level(self):
        """The raw 'action' field should be remapped to event.action, not remain at top level."""
        out = _ecs_format({"action": "allow"})
        assert "action" not in out, (
            "'action' should be remapped to 'event.action', not kept at top level"
        )

    def test_ecs_formatter_event_outcome_allow(self):
        """allow action produces event.outcome='success'."""
        out = _ecs_format({"action": "allow"})
        assert out.get("event.outcome") == "success", (
            f"event.outcome for allow = {out.get('event.outcome')!r}, want 'success'"
        )

    def test_ecs_formatter_event_outcome_block(self):
        """block/ban/tarpit actions produce event.outcome='failure'."""
        for action in ("block", "ban", "tarpit"):
            out = _ecs_format({"action": action})
            assert out.get("event.outcome") == "failure", (
                f"event.outcome for {action} = {out.get('event.outcome')!r}, want 'failure'"
            )


# ---------------------------------------------------------------------------
# ja4proxy namespace
# ---------------------------------------------------------------------------


class TestECSFormatterJA4ProxyNamespace:
    def test_ecs_formatter_ja4proxy_namespace(self):
        """JA4 fingerprint is nested in 'ja4proxy.fingerprint.ja4'."""
        ja4 = "t13d1516h2_aabbccddeeff_aabbccddeeff"
        out = _ecs_format({"ja4": ja4})
        assert out.get("ja4proxy.fingerprint.ja4") == ja4, (
            f"ja4proxy.fingerprint.ja4 = {out.get('ja4proxy.fingerprint.ja4')!r}, want {ja4!r}"
        )

    def test_ecs_formatter_ja4x_namespace(self):
        """JA4X fingerprint is nested in 'ja4proxy.fingerprint.ja4x'."""
        ja4x = "aabbccddee11_ffeeddccbb22_112233445566"
        out = _ecs_format({"ja4x": ja4x})
        assert out.get("ja4proxy.fingerprint.ja4x") == ja4x

    def test_ecs_formatter_sni_field(self):
        """SNI is available as 'ja4proxy.sni'."""
        out = _ecs_format({"sni": "example.com"})
        assert out.get("ja4proxy.sni") == "example.com"

    def test_ecs_formatter_alpn_field(self):
        """ALPN is available as 'ja4proxy.alpn'."""
        out = _ecs_format({"alpn": "h2"})
        assert out.get("ja4proxy.alpn") == "h2"

    def test_ecs_formatter_country_code_field(self):
        """Country code is available as 'ja4proxy.country_code'."""
        out = _ecs_format({"country": "DE"})
        assert out.get("ja4proxy.country_code") == "DE"

    def test_ecs_formatter_score_field(self):
        """Risk score is available as 'ja4proxy.score' (integer)."""
        out = _ecs_format({"score": 77})
        assert out.get("ja4proxy.score") == 77, (
            f"ja4proxy.score = {out.get('ja4proxy.score')!r}, want 77"
        )


# ---------------------------------------------------------------------------
# signals array
# ---------------------------------------------------------------------------


class TestECSFormatterSignals:
    def test_ecs_formatter_signals_array(self):
        """Signals list is serialised as an array under 'ja4proxy.signals'."""
        signals = [
            {"name": "tor_exit", "score": 40, "reason": "Known Tor exit node"},
            {"name": "missing_sni", "score": 15, "reason": "No SNI in ClientHello"},
        ]
        out = _ecs_format({"signals": signals})
        assert "ja4proxy.signals" in out, "ECS output missing 'ja4proxy.signals'"
        arr = out["ja4proxy.signals"]
        assert isinstance(arr, list), f"ja4proxy.signals should be a list, got {type(arr)}"
        assert len(arr) == 2

    def test_ecs_formatter_signals_use_reason_key(self):
        """Each signal element uses 'reason' key, not 'detail'."""
        signals = [{"name": "test_signal", "score": 10, "reason": "test reason"}]
        out = _ecs_format({"signals": signals})
        arr = out["ja4proxy.signals"]
        assert "reason" in arr[0], "signal element missing 'reason' key"
        assert "detail" not in arr[0], "signal element should use 'reason' not 'detail'"

    def test_ecs_formatter_signals_have_required_keys(self):
        """Each signal element must have 'name', 'score', and 'reason'."""
        signals = [
            {"name": "asn_datacenter", "score": 20, "reason": "Datacenter ASN"},
        ]
        out = _ecs_format({"signals": signals})
        arr = out["ja4proxy.signals"]
        for key in ("name", "score", "reason"):
            assert key in arr[0], f"signal element missing '{key}' key"


# ---------------------------------------------------------------------------
# service.name and network fields
# ---------------------------------------------------------------------------


class TestECSFormatterStaticFields:
    def test_ecs_formatter_validates_against_schema(self):
        """All mandatory ECS fields are present when action and client_ip are set."""
        out = _ecs_format({"client_ip": "1.2.3.4", "action": "allow", "score": 50})
        required = (
            "@timestamp",
            "event.action",
            "service.name",
            "network.transport",
        )
        for field in required:
            assert field in out, f"Required ECS field '{field}' is missing"

    def test_ecs_formatter_service_name(self):
        """service.name must be 'ja4proxy'."""
        out = _ecs_format({})
        assert out.get("service.name") == "ja4proxy", (
            f"service.name = {out.get('service.name')!r}, want 'ja4proxy'"
        )

    def test_ecs_formatter_network_transport(self):
        """network.transport must be 'tcp'."""
        out = _ecs_format({})
        assert out.get("network.transport") == "tcp", (
            f"network.transport = {out.get('network.transport')!r}, want 'tcp'"
        )

    def test_ecs_formatter_network_protocol(self):
        """network.protocol must be 'tls'."""
        out = _ecs_format({})
        assert out.get("network.protocol") == "tls", (
            f"network.protocol = {out.get('network.protocol')!r}, want 'tls'"
        )

    def test_ecs_formatter_event_kind(self):
        """event.kind must be 'event'."""
        out = _ecs_format({})
        assert out.get("event.kind") == "event", (
            f"event.kind = {out.get('event.kind')!r}, want 'event'"
        )


# ---------------------------------------------------------------------------
# Legacy mode preservation
# ---------------------------------------------------------------------------


class TestECSFormatterLegacyMode:
    def test_ecs_formatter_legacy_mode_unchanged(self):
        """Legacy mode (no format= arg) produces 'timestamp', 'level', 'message' at top level."""
        out = _legacy_format({"action": "block"}, msg="legacy event")
        assert "timestamp" in out, "legacy mode missing 'timestamp'"
        assert "level" in out, "legacy mode missing 'level'"
        assert "message" in out, "legacy mode missing 'message'"

    def test_ecs_formatter_legacy_mode_no_at_timestamp(self):
        """Legacy mode must NOT produce '@timestamp'."""
        out = _legacy_format({}, msg="legacy")
        assert "@timestamp" not in out, "legacy mode should not have '@timestamp'"

    def test_ecs_formatter_legacy_mode_explicit_parameter(self):
        """JSONFormatter(format='legacy') is identical to JSONFormatter()."""
        fmt_default = JSONFormatter()
        fmt_legacy = JSONFormatter(format="legacy")
        record = _make_record("test message")
        out_default = json.loads(fmt_default.format(record))
        out_legacy = json.loads(fmt_legacy.format(record))
        # Both should have 'timestamp' not '@timestamp'
        assert "timestamp" in out_default
        assert "timestamp" in out_legacy
        assert "@timestamp" not in out_default
        assert "@timestamp" not in out_legacy


# ---------------------------------------------------------------------------
# Dual output mode
# ---------------------------------------------------------------------------


class TestECSDualOutputMode:
    def test_ecs_dual_output_mode(self):
        """
        When dual_output=True, format() returns two JSON lines separated by newline:
        the first is legacy format, the second is ECS format.
        """
        fmt = JSONFormatter(format="ecs", dual_output=True)
        record = _make_record("dual mode event")
        output = fmt.format(record)
        lines = [line for line in output.strip().splitlines() if line.strip()]
        assert len(lines) == 2, (
            f"dual_output=True should produce 2 JSON lines, got {len(lines)}: {output!r}"
        )
        legacy = json.loads(lines[0])
        ecs = json.loads(lines[1])
        # First line: legacy format
        assert "timestamp" in legacy, "first line (legacy) missing 'timestamp'"
        assert "@timestamp" not in legacy, "first line (legacy) should not have '@timestamp'"
        # Second line: ECS format
        assert "@timestamp" in ecs, "second line (ECS) missing '@timestamp'"
        assert "timestamp" not in ecs, "second line (ECS) should not have 'timestamp'"

    def test_ecs_dual_output_both_lines_valid_json(self):
        """Both lines in dual output mode must be independently parseable JSON."""
        fmt = JSONFormatter(format="ecs", dual_output=True)
        record = _make_record("both valid", client_ip="10.0.0.5", action="block")
        output = fmt.format(record)
        lines = [line for line in output.strip().splitlines() if line.strip()]
        for i, line in enumerate(lines):
            try:
                json.loads(line)
            except json.JSONDecodeError as e:
                pytest.fail(f"Line {i} is not valid JSON: {e}\nraw: {line!r}")
