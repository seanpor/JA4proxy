#!/usr/bin/env python3
"""
Additional pipeline tests to cover previously uncovered branches.

Covers:
- StaticAllowlist.reload: empty raw_ip entry (line 172)
- StaticAllowlist.match: invalid IP string (lines 197-198)
- StaticAllowlist.add_from_redis: valid and invalid entries (lines 207-217)
- Pipeline.update_sets (lines 269-270)
- Pipeline.on_config_reload (lines 274-276)
- _check_block_bypasses: country blacklist hit (lines 396-400)
- _format_signals: dict signal path and unknown-type fallback (514-516, 521-523, 528-530)
- Pipeline.process: unexpected exception → fail-open allow
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from src.cache.local_cache import LocalCache
from src.security.pipeline import (
    ConnectionContext,
    Pipeline,
    StaticAllowlist,
    _format_signals,
)

# ---------------------------------------------------------------------------
# Helpers (mirrors test_pipeline.py helpers to keep tests self-contained)
# ---------------------------------------------------------------------------


def _make_cache(dial: int = 0) -> LocalCache:
    cache = LocalCache({})
    cache.dial = dial
    return cache


def _make_pipeline(policy_overrides=None, config_overrides=None, dial=0):
    policy = {
        "alpn_browser_bypass": {"enabled": True},
        "ja4_whitelist_bypass": {"enabled": True},
        "mtls_bypass": {"enabled": True},
        "static_ip_allowlist": {"enabled": True},
        "ja4_blacklist_bypass": {"enabled": True},
        "country_blacklist_bypass": {"enabled": True},
    }
    if policy_overrides:
        policy.update(policy_overrides)
    config = {
        "security_policy": policy,
        "geoip": {"country_blacklist": []},
    }
    if config_overrides:
        config.update(config_overrides)
    cache = _make_cache(dial=dial)
    mock_redis = MagicMock()
    return Pipeline(config=config, local_cache=cache, redis_client=mock_redis)


def _ctx(**kwargs):
    defaults = {"client_ip": "1.2.3.4", "ja4": "t13d1516h2_aabbccddee11_112233445566"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# StaticAllowlist — empty raw_ip skipped (line 172)
# ---------------------------------------------------------------------------


class TestStaticAllowlistReloadEmptyIp:
    def test_empty_ip_entry_skipped(self):
        """Line 172: entry with empty ip field is skipped silently."""
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [
                    {"ip": "", "comment": "empty — should be ignored"},
                    {"ip": "10.0.0.1", "comment": "valid"},
                ],
            }
        }
        al = StaticAllowlist(config)
        # Only the valid entry is kept
        assert len(al._entries) == 1
        assert al.match("10.0.0.1") is not None

    def test_entry_missing_ip_key_skipped(self):
        """Entry with no 'ip' key → raw_ip = '' → continue."""
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"comment": "no ip key at all"}],
            }
        }
        al = StaticAllowlist(config)
        assert al._entries == []


# ---------------------------------------------------------------------------
# StaticAllowlist.match — invalid IP (lines 197-198)
# ---------------------------------------------------------------------------


class TestStaticAllowlistMatchInvalidIp:
    def test_invalid_ip_string_returns_none(self):
        """Lines 197-198: ValueError from ip_address() → return None."""
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "192.168.1.0/24", "comment": "valid CIDR"}],
            }
        }
        al = StaticAllowlist(config)
        # Malformed IP string
        result = al.match("not-an-ip")
        assert result is None

    def test_empty_string_returns_none(self):
        """Empty IP string → ValueError in ip_address()."""
        config = {"static_allowlist": {"enabled": True, "ips": []}}
        al = StaticAllowlist(config)
        assert al.match("") is None

    def test_valid_ip_not_in_list_returns_none(self):
        """Valid IP that is not in the allowlist → None (not ValueError)."""
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "10.0.0.1"}],
            }
        }
        al = StaticAllowlist(config)
        assert al.match("9.9.9.9") is None


# ---------------------------------------------------------------------------
# StaticAllowlist.add_from_redis (lines 207-217)
# ---------------------------------------------------------------------------


class TestStaticAllowlistAddFromRedis:
    def test_valid_ip_added(self):
        """Lines 207-214: valid IP from Redis is appended with warning."""
        config = {"static_allowlist": {"enabled": True, "ips": []}}
        al = StaticAllowlist(config)
        al.add_from_redis("203.0.113.10")
        # Entry is appended
        assert al.match("203.0.113.10") is not None

    def test_valid_cidr_added(self):
        """CIDR from Redis is parsed and appended."""
        config = {"static_allowlist": {"enabled": True, "ips": []}}
        al = StaticAllowlist(config)
        al.add_from_redis("203.0.113.0/24")
        assert al.match("203.0.113.55") is not None

    def test_invalid_ip_from_redis_skipped(self):
        """Lines 216-219: invalid IP from Redis → ValueError caught, warning logged."""
        config = {"static_allowlist": {"enabled": True, "ips": []}}
        al = StaticAllowlist(config)
        al.add_from_redis("not-valid-ip")
        # Invalid IP must not be added
        assert al._entries == []

    def test_redis_entry_comment_set(self):
        """Entry added from Redis gets 'Redis-sourced (UI-added)' comment."""
        config = {"static_allowlist": {"enabled": True, "ips": []}}
        al = StaticAllowlist(config)
        al.add_from_redis("10.0.0.1")
        _, entry = al._entries[0]
        assert "Redis-sourced" in entry["comment"]


# ---------------------------------------------------------------------------
# Pipeline.update_sets (lines 269-270)
# ---------------------------------------------------------------------------


class TestPipelineUpdateSets:
    def test_update_sets_replaces_whitelist_and_blacklist(self):
        """Lines 269-270: update_sets() atomically replaces in-process sets."""
        p = _make_pipeline()
        new_whitelist = {"fp1", "fp2"}
        new_blacklist = {"bad1"}
        p.update_sets(new_whitelist, new_blacklist)
        assert p._whitelist == new_whitelist
        assert p._blacklist == new_blacklist

    def test_update_sets_empty_sets(self):
        """update_sets() with empty sets clears previous values."""
        p = _make_pipeline()
        p.update_sets({"old_fp"}, {"old_bad"})
        p.update_sets(set(), set())
        assert p._whitelist == set()
        assert p._blacklist == set()


# ---------------------------------------------------------------------------
# Pipeline.on_config_reload (lines 274-276)
# ---------------------------------------------------------------------------


class TestPipelineOnConfigReload:
    def test_reload_updates_policy(self):
        """Lines 274-276: on_config_reload() applies new security_policy."""
        p = _make_pipeline()
        new_config = {
            "security_policy": {
                "alpn_browser_bypass": {"enabled": False},
                "ja4_whitelist_bypass": {"enabled": True},
                "mtls_bypass": {"enabled": True},
                "static_ip_allowlist": {"enabled": True},
                "ja4_blacklist_bypass": {"enabled": True},
                "country_blacklist_bypass": {"enabled": True},
            },
            "geoip": {"country_blacklist": []},
        }
        p.on_config_reload(new_config)
        assert p._policy["alpn_browser_bypass"]["enabled"] is False

    def test_reload_rebuilds_allowlist(self):
        """Line 276: allowlist is rebuilt with new config entries."""
        p = _make_pipeline()
        new_config = {
            "security_policy": {"static_ip_allowlist": {"enabled": True}},
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "192.0.2.1", "comment": "new entry"}],
            },
            "geoip": {"country_blacklist": []},
        }
        p.on_config_reload(new_config)
        # The allowlist should now match the new IP
        assert p._allowlist.match("192.0.2.1") is not None

    def test_reload_updates_config_reference(self):
        """After reload, p._config references the new dict."""
        p = _make_pipeline()
        new_config = {"security_policy": {}, "geoip": {"country_blacklist": []}}
        p.on_config_reload(new_config)
        assert p._config is new_config


# ---------------------------------------------------------------------------
# Country blacklist bypass — match path (lines 396-400)
# ---------------------------------------------------------------------------


class TestCountryBlacklistBypassHit:
    def test_blocked_country_returns_block(self):
        """Lines 396-400: country in geoip.country_blacklist → BLOCK bypass."""
        p = _make_pipeline(
            config_overrides={"geoip": {"country_blacklist": ["CN", "RU"]}}
        )
        ctx = _ctx(client_ip="1.2.3.4", country="CN")
        result = _run(p.process(ctx))
        assert result.action == "block"
        assert result.bypassed is True
        assert result.bypass_reason == "country_blacklist"

    def test_non_blocked_country_falls_through(self):
        """Country not in blacklist → falls through to scorer."""
        p = _make_pipeline(config_overrides={"geoip": {"country_blacklist": ["CN"]}})
        ctx = _ctx(client_ip="1.2.3.4", country="US")
        result = _run(p.process(ctx))
        # Scorer is a stub → score=0, action=allow
        assert result.action == "allow"
        assert result.bypassed is False

    def test_country_none_does_not_trigger_bypass(self):
        """country=None never triggers the country blacklist check."""
        p = _make_pipeline(config_overrides={"geoip": {"country_blacklist": ["CN"]}})
        ctx = _ctx(client_ip="1.2.3.4", country=None)
        result = _run(p.process(ctx))
        assert result.action == "allow"


# ---------------------------------------------------------------------------
# _format_signals — dict signal path and unknown-type fallback
# (lines 514-516, 521-523, 528-530)
# ---------------------------------------------------------------------------


class TestFormatSignalsDictAndFallback:
    def test_dict_signal_score_of(self):
        """Lines 514-515: dict signal → score_of uses dict.get("score")."""
        sig = {"name": "test_signal", "score": 25}
        result = _format_signals([sig])
        assert "test_signal(+25)" in result

    def test_dict_signal_name_of(self):
        """Lines 521-522: dict signal → name_of uses dict.get("name")."""
        sig = {"name": "my_signal", "score": 10}
        result = _format_signals([sig])
        assert "my_signal" in result

    def test_dict_signal_raw_score_of(self):
        """Lines 528-529: dict signal → raw_score_of uses dict.get("score")."""
        sig = {"name": "raw_check", "score": -5}
        result = _format_signals([sig])
        assert "raw_check(-5)" in result

    def test_dict_signal_missing_score_defaults_to_zero(self):
        """Dict without 'score' key → score defaults to 0."""
        sig = {"name": "no_score_sig"}
        result = _format_signals([sig])
        assert "no_score_sig(+0)" in result

    def test_unknown_type_score_of_fallback(self):
        """Line 516: object with neither score nor weight → score_of returns 0.0."""

        class _Bare:
            pass

        # _Bare has no .score, .weight, not a dict → score_of returns 0.0
        # Should still be formatted (name_of returns "?" for unknown types)
        sig = _Bare()
        result = _format_signals([sig])
        # Must produce a valid string without crashing
        assert isinstance(result, str)

    def test_unknown_type_name_fallback(self):
        """Line 523: object with no .name and not a dict → name_of returns '?'."""

        class _NoName:
            score = 10
            weight = 1.0

        sig = _NoName()
        result = _format_signals([sig])
        # Object has score+weight (weighted path), but no name → name_of returns "?"
        assert "?(+" in result or "?(-" in result or "?(+10)" in result

    def test_unknown_type_raw_score_fallback(self):
        """Line 530: object with no .score, not a dict → raw_score_of returns 0."""

        class _NoScore:
            name = "no_score_obj"

        sig = _NoScore()
        result = _format_signals([sig])
        # Has .name but no .score or .weight → score_of=0.0, raw_score_of=0
        assert "no_score_obj(+0)" in result

    def test_mixed_dict_and_dataclass_signals(self):
        """Mixing dict and MagicMock signals in one list."""
        mock_sig = MagicMock()
        mock_sig.name = "from_scorer"
        mock_sig.score = 30
        mock_sig.weight = 1.0
        dict_sig = {"name": "from_dict", "score": 15}
        result = _format_signals([mock_sig, dict_sig])
        assert "from_scorer(+30)" in result
        assert "from_dict(+15)" in result


# ---------------------------------------------------------------------------
# Pipeline.process — unexpected exception → fail-open
# ---------------------------------------------------------------------------


class TestPipelineFailOpen:
    def test_unexpected_exception_in_inner_allows(self):
        """process() catches any exception and returns allow (fail open)."""
        p = _make_pipeline()
        with patch.object(p, "_process_inner", side_effect=RuntimeError("boom")):
            result = _run(p.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 0


# ---------------------------------------------------------------------------
# _emit_stream_event — exception swallowed, never propagates
# ---------------------------------------------------------------------------


class TestEmitStreamEventException:
    def test_xadd_exception_is_swallowed(self):
        """_emit_stream_event must never raise even when Redis.xadd fails."""
        p = _make_pipeline()
        # Give the redis mock an xadd attribute that raises
        p._redis.xadd = MagicMock(side_effect=ConnectionError("Redis down"))

        from src.security.pipeline import PipelineResult

        result = PipelineResult(action="allow", score=0, dial=0, counterfactuals={})
        ctx = _ctx()

        # Must not raise
        _run(p._emit_stream_event(ctx, result))
        p._redis.xadd.assert_called_once()
