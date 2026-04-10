"""Phase 86f — Tests for Nagios check plugin."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

CHECK_PATH = Path(__file__).parent.parent.parent / "deploy" / "nagios" / "check_ja4proxy.py"


def _run_check(check_type, data, url="http://test", token="", extra_args=None):
    """Simulate calling check_ja4proxy.py with a mocked urllib response."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_ja4proxy", CHECK_PATH)
    mod = importlib.util.module_from_spec(spec)

    # Mock urllib to return our test data
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(data).encode()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    sys_args = ["--url", url, "--check", check_type]
    if token:
        sys_args += ["--token", token]
    if extra_args:
        sys_args += extra_args

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with patch.object(sys, "argv", ["check_ja4proxy.py"] + sys_args):
            with patch("sys.exit") as mock_exit:
                try:
                    spec.loader.exec_module(mod)
                    mod.main()
                except SystemExit:
                    pass
                return mock_exit.call_args[0][0] if mock_exit.call_args else None


# ── Health check ──────────────────────────────────────────────────────────────

def test_health_ok():
    rc = _run_check("health", {"status": "ok", "redis_latency_ms": 5.0,
                                "active_connections": 10, "dial": 25,
                                "cert_days_remaining": 90.0,
                                "block_rate_pct": 1.0, "active_bans": 100,
                                "redis_connected": True,
                                "connections_total": 1000})
    assert rc == 0


def test_health_degraded():
    rc = _run_check("health", {"status": "degraded", "redis_latency_ms": 55.0,
                                "active_connections": 10, "dial": 25,
                                "cert_days_remaining": 90.0,
                                "block_rate_pct": 1.0, "active_bans": 100,
                                "redis_connected": True,
                                "connections_total": 1000})
    assert rc == 1


def test_health_critical():
    rc = _run_check("health", {"status": "error", "redis_latency_ms": 0,
                                "active_connections": 0, "dial": 0,
                                "cert_days_remaining": None,
                                "block_rate_pct": 0, "active_bans": 0,
                                "redis_connected": False,
                                "connections_total": 0})
    assert rc == 2


# ── Redis check ───────────────────────────────────────────────────────────────

def test_redis_ok():
    rc = _run_check("redis", {"status": "ok", "redis_latency_ms": 5.0,
                               "active_connections": 10, "dial": 25,
                               "cert_days_remaining": 90.0,
                               "block_rate_pct": 1.0, "active_bans": 100,
                               "redis_connected": True,
                               "connections_total": 1000})
    assert rc == 0


def test_redis_warn():
    rc = _run_check("redis", {"status": "degraded", "redis_latency_ms": 25.0,
                               "active_connections": 10, "dial": 25,
                               "cert_days_remaining": 90.0,
                               "block_rate_pct": 1.0, "active_bans": 100,
                               "redis_connected": True,
                               "connections_total": 1000})
    assert rc == 1


def test_redis_critical():
    rc = _run_check("redis", {"status": "error", "redis_latency_ms": 0,
                               "active_connections": 0, "dial": 0,
                               "cert_days_remaining": None,
                               "block_rate_pct": 0, "active_bans": 0,
                               "redis_connected": False,
                               "connections_total": 0})
    assert rc == 2


def test_redis_latency_critical():
    rc = _run_check("redis", {"status": "degraded", "redis_latency_ms": 60.0,
                               "active_connections": 10, "dial": 25,
                               "cert_days_remaining": 90.0,
                               "block_rate_pct": 1.0, "active_bans": 100,
                               "redis_connected": True,
                               "connections_total": 1000})
    assert rc == 2


# ── Cert check ────────────────────────────────────────────────────────────────

def test_cert_ok():
    rc = _run_check("cert", {"status": "ok", "redis_latency_ms": 5.0,
                              "active_connections": 10, "dial": 25,
                              "cert_days_remaining": 90.0,
                              "block_rate_pct": 1.0, "active_bans": 100,
                              "redis_connected": True,
                              "connections_total": 1000})
    assert rc == 0


def test_cert_warn():
    rc = _run_check("cert", {"status": "ok", "redis_latency_ms": 5.0,
                              "active_connections": 10, "dial": 25,
                              "cert_days_remaining": 20.0,
                              "block_rate_pct": 1.0, "active_bans": 100,
                              "redis_connected": True,
                              "connections_total": 1000})
    assert rc == 1


def test_cert_critical():
    rc = _run_check("cert", {"status": "ok", "redis_latency_ms": 5.0,
                              "active_connections": 10, "dial": 25,
                              "cert_days_remaining": 3.0,
                              "block_rate_pct": 1.0, "active_bans": 100,
                              "redis_connected": True,
                              "connections_total": 1000})
    assert rc == 2


def test_cert_expired():
    rc = _run_check("cert", {"status": "ok", "redis_latency_ms": 5.0,
                              "active_connections": 10, "dial": 25,
                              "cert_days_remaining": -5.0,
                              "block_rate_pct": 1.0, "active_bans": 100,
                              "redis_connected": True,
                              "connections_total": 1000})
    assert rc == 2


def test_cert_unknown():
    rc = _run_check("cert", {"status": "ok", "redis_latency_ms": 5.0,
                              "active_connections": 10, "dial": 25,
                              "cert_days_remaining": None,
                              "block_rate_pct": 1.0, "active_bans": 100,
                              "redis_connected": True,
                              "connections_total": 1000})
    assert rc == 3


# ── Dial check ────────────────────────────────────────────────────────────────

def test_dial_ok():
    rc = _run_check("dial", {"status": "ok", "redis_latency_ms": 5.0,
                              "active_connections": 10, "dial": 25,
                              "cert_days_remaining": 90.0,
                              "block_rate_pct": 1.0, "active_bans": 100,
                              "redis_connected": True,
                              "connections_total": 1000},
                    extra_args=["--expected-dial", "25"])
    assert rc == 0


def test_dial_mismatch():
    rc = _run_check("dial", {"status": "ok", "redis_latency_ms": 5.0,
                              "active_connections": 10, "dial": 50,
                              "cert_days_remaining": 90.0,
                              "block_rate_pct": 1.0, "active_bans": 100,
                              "redis_connected": True,
                              "connections_total": 1000},
                    extra_args=["--expected-dial", "25"])
    assert rc == 1


# ── Perfdata format ───────────────────────────────────────────────────────────

def test_perfdata_format():
    """Nagios perfdata must follow: 'label'=value;warn;crit;min;max"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_ja4proxy", CHECK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    data = {
        "status": "ok", "redis_latency_ms": 5.0,
        "active_connections": 10, "dial": 25,
        "cert_days_remaining": 90.0,
        "block_rate_pct": 1.0, "active_bans": 100,
        "redis_connected": True, "connections_total": 1000,
    }
    pd = mod._perfdata(data)
    assert "redis_latency=5.0" in pd
    assert "active_connections=10" in pd
    assert "dial_setting=25" in pd
    assert "cert_days_remaining=90.0" in pd
    assert "block_rate=1.0" in pd


def test_perfdata_has_thresholds():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_ja4proxy", CHECK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    data = {
        "status": "ok", "redis_latency_ms": 25.0,
        "active_connections": 10, "dial": 25,
        "cert_days_remaining": 20.0,
        "block_rate_pct": 1.0, "active_bans": 100,
        "redis_connected": True, "connections_total": 1000,
    }
    pd = mod._perfdata(data)
    # redis_latency should have warn;crit (20;50)
    assert "redis_latency=25.0;20.0;50.0;0;1000" in pd
