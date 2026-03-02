"""Unit tests for src/security/pipeline.py — bypass conditions and pipeline flow."""

import asyncio
from unittest.mock import MagicMock

import pytest

from src.cache.local_cache import LocalCache
from src.security.pipeline import (
    ConnectionContext,
    Pipeline,
    PipelineResult,
    StaticAllowlist,
    _format_signals,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_cache(dial: int = 0) -> LocalCache:
    cache = LocalCache({})
    cache.dial = dial
    return cache


def _make_pipeline(policy_overrides: dict | None = None, dial: int = 0) -> Pipeline:
    """Create a pipeline with all bypasses enabled by default."""
    policy = {
        "alpn_browser_bypass": {"enabled": True},
        "ja4_whitelist_bypass": {"enabled": True},
        "mtls_bypass": {"enabled": True},
        "static_ip_allowlist": {"enabled": True},
        "ja4_blacklist_bypass": {"enabled": True},
        "country_blacklist_bypass": {"enabled": True},
    }
    if policy_overrides:
        for key, val in policy_overrides.items():
            policy[key] = val

    config = {
        "security_policy": policy,
        "geoip": {"country_blacklist": []},
        "mtls": {"enabled": True, "ca_cert_path": None},
    }
    cache = _make_cache(dial=dial)
    mock_redis = MagicMock()
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=mock_redis)
    return pipeline


def _ctx(**kwargs) -> ConnectionContext:
    defaults = {"client_ip": "1.2.3.4", "ja4": "t13d1516h2_aabbccddee11_112233445566"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


def _run(coro):
    try:
        loop = asyncio.get_running_loop()
        raise RuntimeError("_run() should not be called from within an async context")
    except RuntimeError:
        return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# ALPN browser bypass
# ---------------------------------------------------------------------------


class TestAlpnBrowserBypass:
    def test_h2_alpn_bypasses_when_enabled(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(alpn="h2")))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "alpn_browser"
        assert result.score is None

    def test_h1_alpn_bypasses_when_enabled(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(alpn="h1")))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "alpn_browser"

    def test_h2_alpn_no_bypass_when_disabled(self):
        pipeline = _make_pipeline(
            policy_overrides={"alpn_browser_bypass": {"enabled": False}}
        )
        result = _run(pipeline.process(_ctx(alpn="h2")))
        # Falls through to scorer — Phase 0 stub returns score=0, action=allow
        assert result.bypassed is False
        assert result.score == 0

    def test_no_alpn_does_not_bypass(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(alpn=None)))
        assert result.bypassed is False

    def test_unknown_alpn_does_not_bypass(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(alpn="h3")))
        assert result.bypassed is False


# ---------------------------------------------------------------------------
# JA4 whitelist bypass
# ---------------------------------------------------------------------------


class TestJA4WhitelistBypass:
    def test_whitelisted_ja4_bypasses(self):
        pipeline = _make_pipeline()
        pipeline._whitelist = {"t13d1516h2_aabbccddee11_112233445566"}
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4_whitelist"

    def test_non_whitelisted_ja4_falls_through(self):
        pipeline = _make_pipeline()
        pipeline._whitelist = {"other_ja4"}
        result = _run(pipeline.process(_ctx()))
        assert result.bypassed is False

    def test_whitelist_bypass_disabled_falls_through(self):
        pipeline = _make_pipeline(
            policy_overrides={"ja4_whitelist_bypass": {"enabled": False}}
        )
        pipeline._whitelist = {"t13d1516h2_aabbccddee11_112233445566"}
        result = _run(pipeline.process(_ctx()))
        assert result.bypassed is False


# ---------------------------------------------------------------------------
# mTLS bypass
# ---------------------------------------------------------------------------


class TestMTLSBypass:
    def test_valid_cert_bypasses(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(has_valid_client_cert=True)))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "mtls"

    def test_no_cert_does_not_bypass(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(has_valid_client_cert=False)))
        assert result.bypassed is False

    def test_mtls_bypass_disabled_falls_through(self):
        pipeline = _make_pipeline(policy_overrides={"mtls_bypass": {"enabled": False}})
        result = _run(pipeline.process(_ctx(has_valid_client_cert=True)))
        assert result.bypassed is False


# ---------------------------------------------------------------------------
# Static IP allowlist bypass
# ---------------------------------------------------------------------------


class TestStaticAllowlistBypass:
    def test_exact_ip_match(self):
        config = {
            "security_policy": {"static_ip_allowlist": {"enabled": True}},
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "1.2.3.4", "comment": "test"}],
            },
        }
        cache = _make_cache()
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        result = _run(pipeline.process(_ctx(client_ip="1.2.3.4")))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "static_allowlist"

    def test_cidr_match(self):
        config = {
            "security_policy": {"static_ip_allowlist": {"enabled": True}},
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "10.0.0.0/8", "comment": "internal"}],
            },
        }
        cache = _make_cache()
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        result = _run(pipeline.process(_ctx(client_ip="10.20.30.40")))
        assert result.action == "allow"
        assert result.bypassed is True

    def test_ip_not_in_allowlist_falls_through(self):
        config = {
            "security_policy": {"static_ip_allowlist": {"enabled": True}},
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "10.0.0.0/8", "comment": "internal"}],
            },
        }
        cache = _make_cache()
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        result = _run(pipeline.process(_ctx(client_ip="1.2.3.4")))
        assert result.bypassed is False

    def test_ipv6_allowlist_entry(self):
        config = {
            "security_policy": {"static_ip_allowlist": {"enabled": True}},
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "2001:db8::/32", "comment": "docs range"}],
            },
        }
        cache = _make_cache()
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        result = _run(pipeline.process(_ctx(client_ip="2001:db8::1")))
        assert result.action == "allow"
        assert result.bypassed is True


# ---------------------------------------------------------------------------
# JA4 blacklist bypass
# ---------------------------------------------------------------------------


class TestJA4BlacklistBypass:
    def test_blacklisted_ja4_blocks(self):
        pipeline = _make_pipeline()
        pipeline._blacklist = {"t13d1516h2_aabbccddee11_112233445566"}
        result = _run(pipeline.process(_ctx()))
        assert result.action == "block"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4_blacklist"

    def test_non_blacklisted_ja4_falls_through(self):
        pipeline = _make_pipeline()
        pipeline._blacklist = set()
        result = _run(pipeline.process(_ctx()))
        assert result.bypassed is False
        assert result.action == "allow"

    def test_blacklist_bypass_disabled_falls_through(self):
        pipeline = _make_pipeline(
            policy_overrides={"ja4_blacklist_bypass": {"enabled": False}}
        )
        pipeline._blacklist = {"t13d1516h2_aabbccddee11_112233445566"}
        result = _run(pipeline.process(_ctx()))
        # Blacklist bypass disabled → goes through scorer
        assert result.bypassed is False


# ---------------------------------------------------------------------------
# All bypasses disabled + empty signals → fail open
# ---------------------------------------------------------------------------


class TestAllBypassesDisabled:
    def test_all_bypasses_disabled_empty_signals_allows(self):
        """With all bypasses off and no signals, score=0 → action=allow."""
        pipeline = _make_pipeline(
            policy_overrides={
                "alpn_browser_bypass": {"enabled": False},
                "ja4_whitelist_bypass": {"enabled": False},
                "mtls_bypass": {"enabled": False},
                "static_ip_allowlist": {"enabled": False},
                "ja4_blacklist_bypass": {"enabled": False},
                "country_blacklist_bypass": {"enabled": False},
            }
        )
        # h2 ALPN, valid cert — none of these trigger bypasses
        result = _run(pipeline.process(_ctx(alpn="h2", has_valid_client_cert=True)))
        assert result.bypassed is False
        assert result.action == "allow"
        assert result.score == 0

    def test_does_not_crash_with_no_scorer(self):
        """Phase 0: no scorer wired in → returns score=0, action=allow safely."""
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 0


# ---------------------------------------------------------------------------
# Monitor mode (dial=0)
# ---------------------------------------------------------------------------


class TestMonitorMode:
    def test_dial_zero_always_allows(self):
        """dial=0 → monitor mode; action=allow even if scorer says block."""
        pipeline = _make_pipeline(dial=0)
        # Inject a mock scorer that returns score=90 (would be ban)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=90,
            signals=[],
            recommended_action="ban",
            explanation="",
        )
        mock_decider = MagicMock()
        mock_decider.decide.return_value = "ban"
        pipeline.update_scorer(mock_scorer, mock_decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"  # Monitor mode overrides to allow
        assert result.score == 90


# ---------------------------------------------------------------------------
# StaticAllowlist
# ---------------------------------------------------------------------------


class TestStaticAllowlist:
    def test_empty_config_no_match(self):
        allowlist = StaticAllowlist({})
        assert allowlist.match("1.2.3.4") is None

    def test_exact_ipv4_match(self):
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "1.2.3.4", "comment": "test"}],
            }
        }
        allowlist = StaticAllowlist(config)
        assert allowlist.match("1.2.3.4") is not None

    def test_exact_ipv4_no_match(self):
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "1.2.3.4", "comment": "test"}],
            }
        }
        allowlist = StaticAllowlist(config)
        assert allowlist.match("1.2.3.5") is None

    def test_cidr_match(self):
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "192.168.0.0/16", "comment": "lan"}],
            }
        }
        allowlist = StaticAllowlist(config)
        assert allowlist.match("192.168.1.1") is not None

    def test_cidr_no_match_outside(self):
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "192.168.0.0/16", "comment": "lan"}],
            }
        }
        allowlist = StaticAllowlist(config)
        assert allowlist.match("10.0.0.1") is None

    def test_ipv6_match(self):
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "2001:db8::/32", "comment": "docs"}],
            }
        }
        allowlist = StaticAllowlist(config)
        assert allowlist.match("2001:db8::1") is not None

    def test_disabled_returns_none(self):
        config = {
            "static_allowlist": {
                "enabled": False,
                "ips": [{"ip": "1.2.3.4", "comment": "test"}],
            }
        }
        allowlist = StaticAllowlist(config)
        assert allowlist.match("1.2.3.4") is None

    def test_invalid_entry_skipped(self):
        config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [
                    {"ip": "not-an-ip", "comment": "invalid"},
                    {"ip": "1.2.3.4", "comment": "valid"},
                ],
            }
        }
        allowlist = StaticAllowlist(config)
        assert allowlist.match("1.2.3.4") is not None  # Valid entry still works

    def test_reload_updates_entries(self):
        allowlist = StaticAllowlist({})
        assert allowlist.match("1.2.3.4") is None
        new_config = {
            "static_allowlist": {
                "enabled": True,
                "ips": [{"ip": "1.2.3.4", "comment": "added"}],
            }
        }
        allowlist.reload(new_config)
        assert allowlist.match("1.2.3.4") is not None


# ---------------------------------------------------------------------------
# _format_signals helper
# ---------------------------------------------------------------------------


class TestFormatSignals:
    def test_empty_signals(self):
        assert _format_signals([]) == "[]"

    def test_single_positive_signal(self):
        sig = MagicMock()
        sig.name = "missing_sni"
        sig.score = 30
        sig.weight = 1.0
        result = _format_signals([sig])
        assert "missing_sni(+30)" in result

    def test_negative_signal(self):
        sig = MagicMock()
        sig.name = "return_visitor"
        sig.score = -20
        sig.weight = 1.0
        result = _format_signals([sig])
        assert "return_visitor(-20)" in result

    def test_top_5_shown_max(self):
        sigs = []
        for i in range(8):
            s = MagicMock()
            s.name = f"sig{i}"
            s.score = i
            s.weight = 1.0
            sigs.append(s)
        result = _format_signals(sigs)
        assert "..." in result

    def test_sorted_descending(self):
        low = MagicMock()
        low.name = "low"
        low.score = 5
        low.weight = 1.0
        high = MagicMock()
        high.name = "high"
        high.score = 40
        high.weight = 1.0
        result = _format_signals([low, high])
        # high should appear first
        assert result.index("high") < result.index("low")
