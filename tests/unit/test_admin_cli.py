"""Tests for scripts/ja4proxy_admin.py.

All tests use a mock Redis client — no real Redis required.
Tests verify correct key operations, output format, and --confirm guard.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest
from click.testing import CliRunner

# Add scripts/ to path so we can import ja4proxy_admin
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from ja4proxy_admin import cli  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_redis() -> MagicMock:
    r = MagicMock()
    r.ping.return_value = True
    r.get.return_value = None
    r.set.return_value = True
    r.delete.return_value = 1
    r.sadd.return_value = 1
    r.srem.return_value = 1
    r.smembers.return_value = set()
    r.scard.return_value = 0
    r.sismember.return_value = False
    r.hgetall.return_value = {}
    r.keys.return_value = []
    r.zrevrange.return_value = []
    r.zcard.return_value = 0
    r.zscore.return_value = None
    r.xlen.return_value = 0
    r.exists.return_value = False
    r.xinfo_groups.return_value = []
    r.ttl.return_value = 3600
    r.info.return_value = {
        "used_memory": 10 * 1024 * 1024,
        "maxmemory": 512 * 1024 * 1024,
    }
    return r


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def invoke(runner: CliRunner, mock_redis: MagicMock):
    """Helper: invoke CLI with mocked Redis and REDIS_URL set."""

    def _invoke(*args: str, **kwargs: Any):
        with patch("ja4proxy_admin._get_redis", return_value=mock_redis), patch.dict(
            os.environ, {"REDIS_URL": "redis://localhost:6379/0"}
        ):
            return runner.invoke(cli, list(args), catch_exceptions=False, **kwargs)

    return _invoke


# ---------------------------------------------------------------------------
# --confirm guard
# ---------------------------------------------------------------------------


class TestConfirmGuard:
    def test_ban_requires_confirm(self, invoke: Any) -> None:
        result = invoke("ban", "1.2.3.4")
        assert result.exit_code == 1
        assert "--confirm" in result.output

    def test_unban_requires_confirm(self, invoke: Any) -> None:
        result = invoke("unban", "1.2.3.4")
        assert result.exit_code == 1
        assert "--confirm" in result.output

    def test_blacklist_add_requires_confirm(self, invoke: Any) -> None:
        result = invoke("blacklist", "add", "t13d..._aabb_ccdd")
        assert result.exit_code == 1
        assert "--confirm" in result.output

    def test_whitelist_add_requires_confirm(self, invoke: Any) -> None:
        result = invoke("whitelist", "add", "t13d..._aabb_ccdd")
        assert result.exit_code == 1
        assert "--confirm" in result.output

    def test_flush_abuseipdb_requires_confirm(self, invoke: Any) -> None:
        result = invoke("flush", "abuseipdb", "1.2.3.4")
        assert result.exit_code == 1
        assert "--confirm" in result.output

    def test_flush_beaconing_requires_confirm(self, invoke: Any) -> None:
        result = invoke("flush", "beaconing", "1.2.3.4")
        assert result.exit_code == 1
        assert "--confirm" in result.output

    def test_dial_set_nonzero_requires_acknowledge(self, invoke: Any) -> None:
        result = invoke("dial", "set", "50", "--confirm")
        assert result.exit_code == 1
        assert "--acknowledge-blocking" in result.output

    def test_dial_set_zero_needs_only_confirm(
        self, invoke: Any, mock_redis: MagicMock
    ) -> None:
        result = invoke("dial", "set", "0", "--confirm")
        assert result.exit_code == 0
        mock_redis.set.assert_called_once_with("config:dial", "0")


# ---------------------------------------------------------------------------
# ban
# ---------------------------------------------------------------------------


class TestBan:
    def test_ban_sets_key_with_ttl(self, invoke: Any, mock_redis: MagicMock) -> None:
        result = invoke("ban", "1.2.3.4", "--ttl", "7200", "--confirm")
        assert result.exit_code == 0
        mock_redis.set.assert_called_once_with(
            "ban:1.2.3.4", "manual-admin-ban", ex=7200
        )

    def test_ban_permanent_no_ex(self, invoke: Any, mock_redis: MagicMock) -> None:
        result = invoke("ban", "1.2.3.4", "--ttl", "0", "--confirm")
        assert result.exit_code == 0
        mock_redis.set.assert_called_once_with("ban:1.2.3.4", "manual-admin-ban")

    def test_ban_custom_reason(self, invoke: Any, mock_redis: MagicMock) -> None:
        result = invoke("ban", "1.2.3.4", "--reason", "spam", "--confirm")
        assert result.exit_code == 0
        mock_redis.set.assert_called_with("ban:1.2.3.4", "spam", ex=3600)

    def test_ban_json_output(self, invoke: Any) -> None:
        result = invoke("--format", "json", "ban", "1.2.3.4", "--confirm")
        assert result.exit_code == 0
        # Output has a status line then JSON — find the JSON block
        json_start = result.output.index("{")
        data = json.loads(result.output[json_start:])
        assert data["ip"] == "1.2.3.4"


class TestUnban:
    def test_unban_deletes_key(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.delete.return_value = 1
        result = invoke("unban", "1.2.3.4", "--confirm")
        assert result.exit_code == 0
        mock_redis.delete.assert_called_once_with("ban:1.2.3.4")
        assert "Unbanned" in result.output

    def test_unban_not_found(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.delete.return_value = 0
        result = invoke("unban", "1.2.3.4", "--confirm")
        assert result.exit_code == 0
        assert "not banned" in result.output


# ---------------------------------------------------------------------------
# dial
# ---------------------------------------------------------------------------


class TestDial:
    def test_dial_get_default_zero(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.get.return_value = None
        result = invoke("dial", "get")
        assert result.exit_code == 0
        assert "0" in result.output

    def test_dial_get_shows_stored_value(
        self, invoke: Any, mock_redis: MagicMock
    ) -> None:
        mock_redis.get.return_value = "75"
        result = invoke("dial", "get")
        assert result.exit_code == 0
        assert "75" in result.output

    def test_dial_set_stores_value(self, invoke: Any, mock_redis: MagicMock) -> None:
        result = invoke("dial", "set", "50", "--acknowledge-blocking", "--confirm")
        assert result.exit_code == 0
        mock_redis.set.assert_called_with("config:dial", "50")

    def test_dial_set_rejects_out_of_range(self, invoke: Any) -> None:
        result = invoke("dial", "set", "101", "--acknowledge-blocking", "--confirm")
        assert result.exit_code != 0

    def test_dial_get_json(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.get.return_value = "30"
        result = invoke("--format", "json", "dial", "get")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["dial"] == 30


# ---------------------------------------------------------------------------
# whitelist / blacklist
# ---------------------------------------------------------------------------


class TestLists:
    def test_whitelist_add(self, invoke: Any, mock_redis: MagicMock) -> None:
        result = invoke("whitelist", "add", "t13d..._aa_bb", "--confirm")
        assert result.exit_code == 0
        mock_redis.sadd.assert_called_once_with("ja4:whitelist", "t13d..._aa_bb")

    def test_blacklist_add(self, invoke: Any, mock_redis: MagicMock) -> None:
        result = invoke("blacklist", "add", "t13d..._aa_bb", "--confirm")
        assert result.exit_code == 0
        mock_redis.sadd.assert_called_once_with("ja4:blacklist", "t13d..._aa_bb")

    def test_whitelist_remove(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.srem.return_value = 1
        result = invoke("whitelist", "remove", "t13d..._aa_bb", "--confirm")
        assert result.exit_code == 0
        mock_redis.srem.assert_called_once_with("ja4:whitelist", "t13d..._aa_bb")

    def test_blacklist_remove_not_found(
        self, invoke: Any, mock_redis: MagicMock
    ) -> None:
        mock_redis.srem.return_value = 0
        result = invoke("blacklist", "remove", "t13d..._aa_bb", "--confirm")
        assert result.exit_code == 0
        assert "Not found" in result.output

    def test_whitelist_list_empty(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.smembers.return_value = set()
        result = invoke("whitelist", "list")
        assert result.exit_code == 0

    def test_blacklist_list_entries(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.smembers.return_value = {"t13d_aa_bb", "t13d_cc_dd"}
        result = invoke("blacklist", "list")
        assert result.exit_code == 0
        assert "t13d_aa_bb" in result.output or "t13d_cc_dd" in result.output


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


class TestInspect:
    def test_inspect_ip_banned(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.get.side_effect = lambda key: (
            "manual-admin-ban" if "ban:" in key else None
        )
        mock_redis.ttl.return_value = 1800
        result = invoke("inspect", "ip", "1.2.3.4")
        assert result.exit_code == 0
        assert "1.2.3.4" in result.output

    def test_inspect_ip_clean(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.get.return_value = None
        result = invoke("inspect", "ip", "1.2.3.4")
        assert result.exit_code == 0

    def test_inspect_ip_json(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.get.return_value = None
        result = invoke("--format", "json", "inspect", "ip", "1.2.3.4")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ip"] == "1.2.3.4"

    def test_inspect_ja4_in_blacklist(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.sismember.side_effect = lambda key, _: key == "ja4:blacklist"
        result = invoke("inspect", "ja4", "t13d_aa_bb")
        assert result.exit_code == 0

    def test_inspect_ja4_json(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.sismember.return_value = False
        result = invoke("--format", "json", "inspect", "ja4", "t13d_aa_bb")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ja4"] == "t13d_aa_bb"
        assert "whitelist" in data
        assert "blacklist" in data


# ---------------------------------------------------------------------------
# suspect
# ---------------------------------------------------------------------------


class TestSuspect:
    def test_suspect_list_empty(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.zrevrange.return_value = []
        result = invoke("suspect", "list")
        assert result.exit_code == 0
        assert "No beaconing suspects" in result.output

    def test_suspect_list_with_entries(
        self, invoke: Any, mock_redis: MagicMock
    ) -> None:
        mock_redis.zrevrange.return_value = [
            ("1.2.3.4:t13d_aa_bb", 0.85),
            ("5.6.7.8:t13d_cc_dd", 0.72),
        ]
        result = invoke("suspect", "list", "--top", "2")
        assert result.exit_code == 0
        assert "1.2.3.4" in result.output

    def test_suspect_list_json(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.zrevrange.return_value = [("1.2.3.4:t13d_aa_bb", 0.85)]
        result = invoke("--format", "json", "suspect", "list")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["confidence"] == 0.85


# ---------------------------------------------------------------------------
# flush
# ---------------------------------------------------------------------------


class TestFlush:
    def test_flush_abuseipdb_deletes_key(
        self, invoke: Any, mock_redis: MagicMock
    ) -> None:
        mock_redis.delete.return_value = 1
        result = invoke("flush", "abuseipdb", "1.2.3.4", "--confirm")
        assert result.exit_code == 0
        mock_redis.delete.assert_called_once_with("abuseipdb:score:1.2.3.4")

    def test_flush_beaconing_deletes_windows(
        self, invoke: Any, mock_redis: MagicMock
    ) -> None:
        mock_redis.keys.return_value = [
            "beacon:1.2.3.4:t13d_aa",
            "beacon:1.2.3.4:t13d_bb",
        ]
        result = invoke("flush", "beaconing", "1.2.3.4", "--confirm")
        assert result.exit_code == 0
        assert "2" in result.output

    def test_flush_beaconing_no_keys(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.keys.return_value = []
        result = invoke("flush", "beaconing", "1.2.3.4", "--confirm")
        assert result.exit_code == 0
        assert "0" in result.output


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_output(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.get.return_value = "25"
        mock_redis.keys.return_value = []
        result = invoke("status")
        assert result.exit_code == 0
        assert "dial" in result.output.lower() or "25" in result.output

    def test_status_json(self, invoke: Any, mock_redis: MagicMock) -> None:
        mock_redis.get.return_value = "0"
        mock_redis.keys.return_value = []
        result = invoke("--format", "json", "status")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "dial" in data
        assert "redis_memory_mb" in data
        assert "active_bans" in data
        assert "event_stream_length" in data

    def test_status_no_redis_url(self, runner: CliRunner) -> None:
        env = {k: v for k, v in os.environ.items() if k != "REDIS_URL"}
        result = runner.invoke(cli, ["status"], env=env, catch_exceptions=False)
        assert result.exit_code == 1
        assert "REDIS_URL" in result.output
