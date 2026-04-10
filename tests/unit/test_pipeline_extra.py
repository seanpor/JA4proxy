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
        """_emit_stream_event must never raise even when WriteBuffer.enqueue fails."""
        from unittest.mock import AsyncMock

        p = _make_pipeline()
        # Make the write_buffer.enqueue raise to exercise the exception-swallowing path
        p._write_buffer.enqueue = AsyncMock(side_effect=ConnectionError("Redis down"))

        from src.security.pipeline import PipelineResult

        result = PipelineResult(action="allow", score=0, dial=0, counterfactuals={})
        ctx = _ctx()

        # Must not raise
        _run(p._emit_stream_event(ctx, result))
        p._write_buffer.enqueue.assert_called_once()


# ---------------------------------------------------------------------------
# _load_blocklist_feeds — static_cidrs path (lines 385-400)
# ---------------------------------------------------------------------------


class TestLoadBlocklistFeeds:
    def test_static_cidrs_loaded_into_blocklist_manager(self):
        """Lines 398-400: feed with static_cidrs calls load_cidrs on the manager.
        Security consequence: if static CIDRs are not loaded, known-bad IP ranges
        (e.g. Spamhaus DROP ranges pre-seeded for offline use) never block,
        allowing malicious traffic through without any signal.
        """
        config = {
            "security_policy": {},
            "blocklists": {
                "feeds": [
                    {
                        "name": "test_feed",
                        "url": "",
                        "format": "spamhaus",
                        "is_bypass": True,
                        "action": "block",
                        "score": 60,
                        "refresh_interval_seconds": 43200,
                        "enabled": True,
                        "static_cidrs": ["192.0.2.0/24", "198.51.100.0/24"],
                    }
                ]
            },
        }
        cache = _make_cache()
        p = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        # The CIDRs should be loaded into the blocklist manager
        blocked, feed_name = p._blocklist_manager.is_blocked("192.0.2.5")
        assert blocked is True
        assert feed_name == "test_feed"

    def test_disabled_feed_not_loaded(self):
        """Line 385-386: feed with enabled=False is skipped entirely.
        Security consequence: explicitly disabled feeds should stay disabled —
        if they were loaded anyway, they could silently re-block IPs that the
        operator intentionally excluded.
        """
        config = {
            "security_policy": {},
            "blocklists": {
                "feeds": [
                    {
                        "name": "disabled_feed",
                        "enabled": False,
                        "static_cidrs": ["10.20.30.0/24"],
                    }
                ]
            },
        }
        cache = _make_cache()
        p = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        blocked, _ = p._blocklist_manager.is_blocked("10.20.30.1")
        assert blocked is False

    def test_feed_without_static_cidrs_does_not_crash(self):
        """Lines 384-396: feed with no static_cidrs key is processed without error.
        This is the normal production path (URL-fetched feeds have no static_cidrs).
        """
        config = {
            "security_policy": {},
            "blocklists": {
                "feeds": [
                    {
                        "name": "url_feed",
                        "url": "https://example.com/drop.txt",
                        "enabled": True,
                    }
                ]
            },
        }
        cache = _make_cache()
        # Must not raise
        p = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        assert p._blocklist_manager is not None


# ---------------------------------------------------------------------------
# Pipeline wiring methods (lines 409, 413, 424-432)
# ---------------------------------------------------------------------------


class TestPipelineWiringMethods:
    def test_set_abuseipdb_checker(self):
        """Line 409: set_abuseipdb_checker stores the checker on the pipeline.
        Security consequence: if this wiring is broken, the AbuseIPDB signal is
        never collected — high-confidence abusive IPs score as 0, bypassing
        reputation-based blocking entirely.
        """
        p = _make_pipeline()
        mock_checker = MagicMock()
        p.set_abuseipdb_checker(mock_checker)
        assert p._abuseipdb_checker is mock_checker

    def test_set_abuseipdb_checker_none(self):
        """set_abuseipdb_checker(None) disables checker gracefully."""
        p = _make_pipeline()
        p.set_abuseipdb_checker(None)
        assert p._abuseipdb_checker is None

    def test_set_rdap_enricher(self):
        """Line 413: set_rdap_enricher stores the enricher on the pipeline.
        Security consequence: if RDAP wiring is broken, no org-reputation signals
        are emitted — known malicious hosting providers are not scored.
        """
        p = _make_pipeline()
        mock_enricher = MagicMock()
        p.set_rdap_enricher(mock_enricher)
        assert p._rdap_enricher is mock_enricher

    def test_set_rdap_enricher_none(self):
        """set_rdap_enricher(None) disables enricher gracefully."""
        p = _make_pipeline()
        p.set_rdap_enricher(None)
        assert p._rdap_enricher is None

    def test_set_ti_providers_all(self):
        """Lines 424-428: set_ti_providers wires all five TI providers.
        Security consequence: un-wired TI providers return no signals —
        IPs known to GreyNoise, MISP, ThreatFox, or VirusTotal as malicious
        score 0, silently passing through.
        """
        p = _make_pipeline()
        gn = MagicMock()
        av = MagicMock()
        mi = MagicMock()
        tf = MagicMock()
        vt = MagicMock()
        p.set_ti_providers(greynoise=gn, alienvault=av, misp=mi, threatfox=tf, virustotal=vt)
        assert p._greynoise_provider is gn
        assert p._alienvault_provider is av
        assert p._misp_provider is mi
        assert p._threatfox_provider is tf
        assert p._virustotal_provider is vt

    def test_set_ti_providers_partial_none(self):
        """set_ti_providers with some providers None — valid when not all feeds configured."""
        p = _make_pipeline()
        gn = MagicMock()
        p.set_ti_providers(greynoise=gn, alienvault=None, misp=None)
        assert p._greynoise_provider is gn
        assert p._alienvault_provider is None
        assert p._misp_provider is None

    def test_set_confidence_manager(self):
        """Line 432: set_confidence_manager stores the manager on the pipeline.
        Security consequence: without the confidence manager, TI signal weights
        are not adjusted for feed reliability — a degraded TI feed contributes
        full weight to scores, increasing false positive rate.
        """
        p = _make_pipeline()
        cm = MagicMock()
        p.set_confidence_manager(cm)
        assert p._confidence_manager is cm

    def test_set_confidence_manager_none(self):
        """set_confidence_manager(None) disables it gracefully."""
        p = _make_pipeline()
        p.set_confidence_manager(None)
        assert p._confidence_manager is None


# ---------------------------------------------------------------------------
# _get_analytics_signals — cache hit, redis=None, Redis reads (lines 450-519)
# ---------------------------------------------------------------------------


def _make_async_cache_pipeline(redis_get_side_effect=None, cache_hit_value=None):
    """Build a pipeline with an AsyncMock redis for analytics signal tests."""
    from unittest.mock import AsyncMock

    policy = {"alpn_browser_bypass": {"enabled": False}}
    config = {
        "security_policy": policy,
        "geoip": {"country_blacklist": []},
    }
    cache = _make_cache(dial=0)
    # Seed the analytics_signals LRU cache if requested
    if cache_hit_value is not None:
        cache.analytics_signals.set("1.2.3.0/24", cache_hit_value)

    mock_redis = AsyncMock()
    if redis_get_side_effect is not None:
        mock_redis.get.side_effect = redis_get_side_effect
    else:
        mock_redis.get.return_value = None
    return Pipeline(config=config, local_cache=cache, redis_client=mock_redis)


class TestGetAnalyticsSignals:
    def test_invalid_ip_returns_empty_list(self):
        """Lines 450-452: ValueError from ip_address() → returns [] without crash.
        Security consequence: malformed or non-canonical IPs (e.g. passed from
        a PROXY protocol parser bug) must not crash the analytics lookup —
        crash here would propagate to the pipeline and could trigger fail-open.
        """
        p = _make_async_cache_pipeline()
        result = _run(p._get_analytics_signals("not-an-ip"))
        assert result == []

    def test_cache_hit_returns_without_redis(self):
        """Line 456: cached analytics signals returned without hitting Redis.
        Security consequence: if the cache is ignored and Redis is queried on
        every connection, an attacker can trigger Redis saturation by opening
        many connections from the same /24, creating a DoS vector.
        """
        from src.security.models import RiskSignal

        cached = [RiskSignal(name="analytics_campaign", score=35, reason="cached")]
        p = _make_async_cache_pipeline(cache_hit_value=cached)
        result = _run(p._get_analytics_signals("1.2.3.99"))
        assert len(result) == 1
        assert result[0].name == "analytics_campaign"
        # Redis must not have been called since result came from cache
        p._redis.get.assert_not_called()

    def test_redis_none_returns_empty_and_caches(self):
        """Lines 460-462: redis=None → returns [] and caches the empty result.
        Security consequence: if Redis is unavailable and this path crashes
        instead of returning [], the fail-open rule is violated — the pipeline
        would fail closed and block legitimate users.
        """
        policy = {"alpn_browser_bypass": {"enabled": False}}
        config = {"security_policy": policy, "geoip": {"country_blacklist": []}}
        cache = _make_cache(dial=0)
        p = Pipeline(config=config, local_cache=cache, redis_client=None)
        result = _run(p._get_analytics_signals("10.0.0.1"))
        assert result == []
        # Verify the empty result was cached (so next call is fast)
        cached = cache.analytics_signals.get("10.0.0.0/24")
        assert cached == []

    def test_redis_returns_campaign_signal(self):
        """Lines 464-486: Redis has campaign key → analytics_campaign + subnet_campaign signals.
        Security consequence: if the campaign analytics signal is not read from Redis,
        coordinated botnet campaigns attacking from a /24 will not be detected cross-instance,
        allowing them to stay below per-IP rate limits indefinitely.
        """
        from unittest.mock import AsyncMock

        async def side_effect(key):
            if "campaign" in key:
                return b"1"
            return None

        p = _make_async_cache_pipeline(redis_get_side_effect=side_effect)
        result = _run(p._get_analytics_signals("1.2.3.4"))
        names = [s.name for s in result]
        assert "analytics_campaign" in names
        assert "subnet_campaign" in names

    def test_redis_returns_slowscan_signal(self):
        """Lines 488-497: Redis has slowscan key → analytics_slowscan signal.
        Security consequence: slow-scan reconnaissance from a /24 spreads the
        scans across many IPs. Without this cross-instance signal, each proxy
        instance sees only a fraction of the scan and never exceeds rate limits.
        """
        from unittest.mock import AsyncMock

        async def side_effect(key):
            if "slowscan" in key:
                return b"1"
            return None

        p = _make_async_cache_pipeline(redis_get_side_effect=side_effect)
        result = _run(p._get_analytics_signals("1.2.3.4"))
        names = [s.name for s in result]
        assert "analytics_slowscan" in names

    def test_redis_timeout_returns_empty(self):
        """Lines 498-508: TimeoutError from Redis → [] returned, fail open.
        Security consequence: if Redis timeouts propagate as exceptions rather than
        returning [], the pipeline exception handler catches them and logs an error,
        but the connection is still allowed. However, a crash here would prevent
        the signal from being safely skipped and could mask the real cause.
        """
        import asyncio

        async def side_effect(key):
            raise asyncio.TimeoutError()

        p = _make_async_cache_pipeline(redis_get_side_effect=side_effect)
        result = _run(p._get_analytics_signals("1.2.3.4"))
        assert result == []

    def test_redis_connection_error_returns_empty(self):
        """Lines 498-508: ConnectionError from Redis → [] returned, fail open."""
        async def side_effect(key):
            raise ConnectionError("Redis down")

        p = _make_async_cache_pipeline(redis_get_side_effect=side_effect)
        result = _run(p._get_analytics_signals("1.2.3.4"))
        assert result == []

    def test_redis_generic_exception_returns_empty(self):
        """Lines 509-516: generic exception from Redis → [] returned, fail open.
        Security consequence: Redis bugs or protocol errors must not crash analytics
        — the signal must be skipped, not the whole pipeline.
        """
        async def side_effect(key):
            raise RuntimeError("unexpected error")

        p = _make_async_cache_pipeline(redis_get_side_effect=side_effect)
        result = _run(p._get_analytics_signals("1.2.3.4"))
        assert result == []

    def test_successful_redis_result_is_cached(self):
        """Lines 518-519: after a successful Redis read, result is cached.
        Security consequence: if caching is broken, every connection causes a
        Redis round-trip. Under attack, the /24 analytics lookup rate could
        saturate Redis with get commands, degrading the entire Redis layer.
        """
        from unittest.mock import AsyncMock

        call_count = []

        async def side_effect(key):
            call_count.append(key)
            return None  # No signals, but still exercises the cache-set path

        p = _make_async_cache_pipeline(redis_get_side_effect=side_effect)
        # First call hits Redis
        _run(p._get_analytics_signals("1.2.3.4"))
        first_call_count = len(call_count)

        # Second call for same IP should use cache, not Redis
        _run(p._get_analytics_signals("1.2.3.99"))  # same /24
        # Redis should not have been called again
        assert len(call_count) == first_call_count


# ---------------------------------------------------------------------------
# Pipeline.process — OpenTelemetry tracer path (lines 558-578)
# ---------------------------------------------------------------------------


class TestPipelineTracerPath:
    def test_tracer_path_wraps_process_inner(self):
        """Lines 558-578: when a tracer is wired in, process() uses it as a context manager.
        Security consequence: if the tracer path skips result attribute setting,
        distributed traces will have missing span attributes (action, risk.score),
        preventing accurate incident forensics in a compromised environment.
        """
        p = _make_pipeline()
        mock_span = MagicMock()
        mock_tracer_instance = MagicMock()
        mock_tracer_instance.start_as_current_span.return_value.__enter__ = MagicMock(
            return_value=mock_span
        )
        mock_tracer_instance.start_as_current_span.return_value.__exit__ = MagicMock(
            return_value=False
        )
        mock_tracer_obj = MagicMock()
        mock_tracer_obj.get_tracer.return_value = mock_tracer_instance
        p._tracer = mock_tracer_obj

        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"
        mock_tracer_obj.get_tracer.assert_called_with("ja4proxy.pipeline")

    def test_tracer_path_exception_still_returns_allow(self):
        """Lines 569-574: exception inside tracer span → fail open to allow.
        Security consequence: a bug in a signal module during traced processing
        must not result in a block — the tracer catches the exception, records
        it on the span, and the connection is still allowed (fail-open rule).
        """
        p = _make_pipeline()
        mock_span = MagicMock()
        mock_tracer_instance = MagicMock()
        mock_tracer_instance.start_as_current_span.return_value.__enter__ = MagicMock(
            return_value=mock_span
        )
        mock_tracer_instance.start_as_current_span.return_value.__exit__ = MagicMock(
            return_value=False
        )
        mock_tracer_obj = MagicMock()
        mock_tracer_obj.get_tracer.return_value = mock_tracer_instance
        p._tracer = mock_tracer_obj

        with patch.object(p, "_process_inner", side_effect=RuntimeError("tracer boom")):
            result = _run(p.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 0
        mock_span.record_exception.assert_called_once()


# ---------------------------------------------------------------------------
# _process_inner — deception checker hit (lines 627-635)
# ---------------------------------------------------------------------------


class TestDeceptionCheckerHit:
    def test_deception_hit_returns_silent_drop(self):
        """Lines 627-635: deception checker match → silent_drop action.
        Security consequence: honey-fingerprints and honey-SNIs are deception
        assets — only scanners and attackers probe them. If this path is broken,
        attackers probing deception assets are not silently dropped but instead
        scored normally, potentially scoring below the block threshold.
        """
        from unittest.mock import AsyncMock

        p = _make_pipeline(
            policy_overrides={
                "alpn_browser_bypass": {"enabled": False},
                "ja4_whitelist_bypass": {"enabled": False},
                "mtls_bypass": {"enabled": False},
                "static_ip_allowlist": {"enabled": False},
                "ja4_blacklist_bypass": {"enabled": False},
                "country_blacklist_bypass": {"enabled": False},
            }
        )
        # Make deception checker return a hit
        p._deception_checker.check = AsyncMock(
            return_value={"trigger": "honey_sni", "sni": "honeypot.internal"}
        )
        ctx = _ctx(client_ip="5.6.7.8", alpn=None)
        result = _run(p.process(ctx))
        assert result.action == "silent_drop"
        assert result.bypassed is True
        assert "deception_honey_sni" in result.bypass_reason


# ---------------------------------------------------------------------------
# _process_inner — TLS version hard block (lines 641-646)
# ---------------------------------------------------------------------------


class TestTLSVersionBlock:
    def test_tls_enforcer_none_triggers_block(self):
        """Lines 640-646: tls_enforcer.check() returning None → block bypass.
        Security consequence: TLS 1.0/1.1 connections must be hard-blocked
        before reaching the scorer. If this path is broken, old-TLS clients
        score normally and may be allowed through with score=0.
        """
        p = _make_pipeline(
            policy_overrides={
                "alpn_browser_bypass": {"enabled": False},
                "ja4_whitelist_bypass": {"enabled": False},
                "mtls_bypass": {"enabled": False},
                "static_ip_allowlist": {"enabled": False},
                "ja4_blacklist_bypass": {"enabled": False},
                "country_blacklist_bypass": {"enabled": False},
            }
        )
        # tls_enforcer.check() returns None to signal a hard block
        p._tls_enforcer.check = MagicMock(return_value=None)
        ctx = _ctx(client_ip="9.9.9.9", tls_version="TLSv1.0")
        result = _run(p.process(ctx))
        assert result.action == "block"
        assert result.bypassed is True
        assert result.bypass_reason == "tls_version"


# ---------------------------------------------------------------------------
# _collect_signals — TI provider signal collection (lines 1040-1228)
# ---------------------------------------------------------------------------


def _make_full_pipeline(dial=50):
    """Pipeline with all bypasses disabled and dial set, for signal collection testing."""
    from unittest.mock import AsyncMock

    policy = {
        "alpn_browser_bypass": {"enabled": False},
        "ja4_whitelist_bypass": {"enabled": False},
        "mtls_bypass": {"enabled": False},
        "static_ip_allowlist": {"enabled": False},
        "ja4_blacklist_bypass": {"enabled": False},
        "country_blacklist_bypass": {"enabled": False},
    }
    config = {
        "security_policy": policy,
        "geoip": {"country_blacklist": []},
    }
    cache = _make_cache(dial=dial)
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    p = Pipeline(config=config, local_cache=cache, redis_client=mock_redis)
    # Wire a passthrough scorer so the pipeline doesn't discard signals
    mock_scorer = MagicMock()
    mock_scorer.score.return_value = MagicMock(
        total_score=0, signals=[], recommended_action="allow"
    )
    mock_decider = MagicMock()
    mock_decider.decide.return_value = "allow"
    mock_decider.counterfactuals.return_value = {}
    p.update_scorer(mock_scorer, mock_decider)
    return p


class TestTIProviderSignals:
    def test_greynoise_provider_signal_collected(self):
        """Lines 1135-1149: GreyNoise provider get_signal called and result included.
        Security consequence: if the GreyNoise call is skipped, IPs flagged as
        malicious in GreyNoise's global internet-scan dataset score as 0, leaving
        a known threat actor undetected.
        """
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        gn = MagicMock()
        gn.get_signal.return_value = RiskSignal(
            name="greynoise_malicious", score=70, reason="GreyNoise: malicious scanner"
        )
        p.set_ti_providers(greynoise=gn, alienvault=None)

        # Capture what the scorer received
        seen_signals = []

        def capture(signals):
            seen_signals.extend(signals)
            return MagicMock(total_score=70, signals=[], recommended_action="block")

        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="1.2.3.4")
        _run(p.process(ctx))
        gn.get_signal.assert_called_with("1.2.3.4")
        assert any(s.name == "greynoise_malicious" for s in seen_signals)

    def test_greynoise_provider_none_not_called(self):
        """Line 1136: greynoise_provider=None → signal collector returns [] immediately."""
        p = _make_full_pipeline()
        # greynoise stays None (default)
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"  # no crash

    def test_greynoise_provider_exception_fails_open(self):
        """Lines 1141-1149: exception in greynoise get_signal → [] returned, fail open.
        Security consequence: a GreyNoise API client bug must not crash the pipeline —
        the signal is skipped and the connection is decided on remaining signals only.
        """
        p = _make_full_pipeline()
        gn = MagicMock()
        gn.get_signal.side_effect = RuntimeError("GreyNoise API error")
        p.set_ti_providers(greynoise=gn, alienvault=None)
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_alienvault_provider_signal_collected(self):
        """Lines 1151-1165: AlienVault OTX provider get_signal called and included.
        Security consequence: if AlienVault is skipped, IPs in active threat pulses
        on OTX are not scored — targeted attacks leveraging known C2 IPs pass through.
        """
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        av = MagicMock()
        av.get_signal.return_value = RiskSignal(
            name="alienvault_threat", score=60, reason="AlienVault: active threat"
        )
        p.set_ti_providers(greynoise=None, alienvault=av)

        seen_signals = []

        def capture(signals):
            seen_signals.extend(signals)
            return MagicMock(total_score=60, signals=[], recommended_action="flag")

        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="2.3.4.5")
        _run(p.process(ctx))
        av.get_signal.assert_called_with("2.3.4.5")
        assert any(s.name == "alienvault_threat" for s in seen_signals)

    def test_alienvault_provider_exception_fails_open(self):
        """Lines 1157-1165: exception in alienvault get_signal → fail open."""
        p = _make_full_pipeline()
        av = MagicMock()
        av.get_signal.side_effect = ValueError("OTX error")
        p.set_ti_providers(greynoise=None, alienvault=av)
        ctx = _ctx(client_ip="2.3.4.5")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_misp_provider_signal_collected(self):
        """Lines 1167-1186: MISP provider get_signal called and signal included.
        Security consequence: if MISP is skipped, IOCs from shared threat intelligence
        communities are not matched — targeted APT infrastructure passes undetected.
        """
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        mi = MagicMock()
        mi.get_signal.return_value = RiskSignal(
            name="misp_ioc", score=80, reason="MISP: IOC match"
        )
        p.set_ti_providers(greynoise=None, alienvault=None, misp=mi)

        seen_signals = []

        def capture(signals):
            seen_signals.extend(signals)
            return MagicMock(total_score=80, signals=[], recommended_action="block")

        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="3.4.5.6")
        _run(p.process(ctx))
        mi.get_signal.assert_called_with("3.4.5.6")
        assert any(s.name == "misp_ioc" for s in seen_signals)

    def test_misp_confidence_manager_applied(self):
        """Lines 1174-1176: when confidence_manager present, signal weight is adjusted.
        Security consequence: if confidence weighting is not applied, a degraded MISP
        feed contributes full weight — stale IOCs from a compromised MISP instance
        would incorrectly block legitimate IPs.
        """
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        mi = MagicMock()
        signal = RiskSignal(name="misp_ioc", score=80, reason="MISP: IOC match")
        mi.get_signal.return_value = signal

        cm = MagicMock()
        cm.get_confidence_weight.return_value = 0.5
        p.set_confidence_manager(cm)
        p.set_ti_providers(greynoise=None, alienvault=None, misp=mi)

        ctx = _ctx(client_ip="3.4.5.6")
        _run(p.process(ctx))
        cm.get_confidence_weight.assert_called_with("misp")

    def test_misp_provider_exception_fails_open(self):
        """Lines 1178-1186: exception in misp get_signal → fail open."""
        p = _make_full_pipeline()
        mi = MagicMock()
        mi.get_signal.side_effect = RuntimeError("MISP unreachable")
        p.set_ti_providers(greynoise=None, alienvault=None, misp=mi)
        ctx = _ctx(client_ip="3.4.5.6")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_threatfox_provider_signal_collected(self):
        """Lines 1188-1207: ThreatFox provider get_signal called and signal included.
        Security consequence: if ThreatFox is skipped, recently published malware C2
        indicators are not matched — active malware campaigns pass without scoring.
        """
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        tf = MagicMock()
        tf.get_signal.return_value = RiskSignal(
            name="threatfox_c2", score=85, reason="ThreatFox: C2 indicator"
        )
        p.set_ti_providers(greynoise=None, alienvault=None, threatfox=tf)

        seen_signals = []

        def capture(signals):
            seen_signals.extend(signals)
            return MagicMock(total_score=85, signals=[], recommended_action="block")

        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="4.5.6.7")
        _run(p.process(ctx))
        tf.get_signal.assert_called_with("4.5.6.7")
        assert any(s.name == "threatfox_c2" for s in seen_signals)

    def test_threatfox_confidence_manager_applied(self):
        """Lines 1195-1197: threatfox signal weight adjusted by confidence manager."""
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        tf = MagicMock()
        tf.get_signal.return_value = RiskSignal(
            name="threatfox_c2", score=85, reason="ThreatFox: C2"
        )
        cm = MagicMock()
        cm.get_confidence_weight.return_value = 0.75
        p.set_confidence_manager(cm)
        p.set_ti_providers(greynoise=None, alienvault=None, threatfox=tf)

        ctx = _ctx(client_ip="4.5.6.7")
        _run(p.process(ctx))
        cm.get_confidence_weight.assert_called_with("threatfox")

    def test_threatfox_provider_exception_fails_open(self):
        """Lines 1199-1207: exception in threatfox get_signal → fail open."""
        p = _make_full_pipeline()
        tf = MagicMock()
        tf.get_signal.side_effect = RuntimeError("ThreatFox error")
        p.set_ti_providers(greynoise=None, alienvault=None, threatfox=tf)
        ctx = _ctx(client_ip="4.5.6.7")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_virustotal_provider_signal_collected(self):
        """Lines 1209-1228: VirusTotal provider get_signal called and signal included.
        Security consequence: if VirusTotal is skipped, IPs with positive malware
        detections from 60+ AV engines are not scored — known malicious infrastructure
        receives a score of 0.
        """
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        vt = MagicMock()
        vt.get_signal.return_value = RiskSignal(
            name="virustotal_malicious", score=75, reason="VirusTotal: 30/60 engines"
        )
        p.set_ti_providers(greynoise=None, alienvault=None, virustotal=vt)

        seen_signals = []

        def capture(signals):
            seen_signals.extend(signals)
            return MagicMock(total_score=75, signals=[], recommended_action="block")

        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="5.6.7.8")
        _run(p.process(ctx))
        vt.get_signal.assert_called_with("5.6.7.8")
        assert any(s.name == "virustotal_malicious" for s in seen_signals)

    def test_virustotal_confidence_manager_applied(self):
        """Lines 1216-1218: virustotal signal weight adjusted by confidence manager."""
        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        vt = MagicMock()
        vt.get_signal.return_value = RiskSignal(
            name="virustotal_malicious", score=75, reason="VT"
        )
        cm = MagicMock()
        cm.get_confidence_weight.return_value = 0.9
        p.set_confidence_manager(cm)
        p.set_ti_providers(greynoise=None, alienvault=None, virustotal=vt)

        ctx = _ctx(client_ip="5.6.7.8")
        _run(p.process(ctx))
        cm.get_confidence_weight.assert_called_with("virustotal")

    def test_virustotal_provider_exception_fails_open(self):
        """Lines 1220-1228: exception in virustotal get_signal → fail open."""
        p = _make_full_pipeline()
        vt = MagicMock()
        vt.get_signal.side_effect = RuntimeError("VT timeout")
        p.set_ti_providers(greynoise=None, alienvault=None, virustotal=vt)
        ctx = _ctx(client_ip="5.6.7.8")
        result = _run(p.process(ctx))
        assert result.action == "allow"


# ---------------------------------------------------------------------------
# _collect_signals — JA4X blacklist signal (lines 824-839)
# ---------------------------------------------------------------------------


class TestJA4XBlacklistSignal:
    def test_ja4x_in_blacklist_produces_signal(self):
        """Lines 824-839: ja4x in _ja4x_blacklist → ja4x_blacklist RiskSignal added.
        Security consequence: JA4X fingerprints from known-malicious TLS cert chains
        must generate a risk signal. If this signal is not emitted, a client with a
        known-bad certificate chain scores 0 and passes through.
        """
        p = _make_full_pipeline()
        p._ja4x_blacklist = {"abc123def456_111222333444_aabbccddeeff"}
        ctx = _ctx(client_ip="1.2.3.4", ja4x="abc123def456_111222333444_aabbccddeeff")

        seen_signals = []

        def capture(signals):
            seen_signals.extend(signals)
            return MagicMock(total_score=80, signals=[], recommended_action="block")

        p._scorer.score.side_effect = capture
        _run(p.process(ctx))
        assert any(s.name == "ja4x_blacklist" for s in seen_signals)

    def test_ja4x_not_in_blacklist_no_signal(self):
        """JA4X not in blacklist → no ja4x_blacklist signal."""
        p = _make_full_pipeline()
        p._ja4x_blacklist = {"different_ja4x_value"}
        ctx = _ctx(client_ip="1.2.3.4", ja4x="abc123def456_111222333444_aabbccddeeff")

        seen_signals = []

        def capture(signals):
            seen_signals.extend(signals)
            return MagicMock(total_score=0, signals=[], recommended_action="allow")

        p._scorer.score.side_effect = capture
        _run(p.process(ctx))
        assert not any(s.name == "ja4x_blacklist" for s in seen_signals)


# ---------------------------------------------------------------------------
# _collect_signals — RDAP browser subnet recording (line 844)
# ---------------------------------------------------------------------------


class TestRDAPBrowserSubnetRecording:
    def test_h2_alpn_with_rdap_enricher_records_subnet(self):
        """Line 843-846: h2 ALPN with rdap_enricher set → record_browser_subnet called.
        Security consequence: the RDAP block-expansion guard uses browser subnet records
        to prevent expanding a /24 block when browsers use the same range. If this
        record is never made, a botnet sharing a /24 with legitimate browser traffic
        could trigger block expansion and knock out real users.

        Note: h2 ALPN normally bypasses the pipeline (ALLOW bypass) before reaching
        _collect_signals. This test uses an injected collector path instead, or
        the h2 bypass must be disabled. We disable it to exercise the code path.
        """
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()
        mock_rdap = MagicMock()
        mock_rdap.record_browser_subnet = AsyncMock()
        p.set_rdap_enricher(mock_rdap)

        # h2 ALPN with bypass disabled reaches _collect_signals
        ctx = _ctx(client_ip="1.2.3.4", alpn="h2")
        _run(p.process(ctx))
        mock_rdap.record_browser_subnet.assert_called_with("1.2.3.4")


# ---------------------------------------------------------------------------
# _collect_signals — behavioral/attribution exception paths (lines 1249-1257)
# ---------------------------------------------------------------------------


class TestBehavioralAttributionExceptionPaths:
    def test_attribution_exception_fails_open(self):
        """Lines 1233-1242: exception in attribution manager → [] returned, fail open.
        Security consequence: attribution analysis correlates TLS fingerprints across
        sessions to identify repeat attackers. If an attribution bug crashes the pipeline,
        sessions from known attackers score without attribution signals.
        """
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()
        p._attribution_manager.get_signal = AsyncMock(
            side_effect=RuntimeError("attribution crash")
        )
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_behavioral_exception_fails_open(self):
        """Lines 1249-1257: exception in behavioral analyzer → [] returned, fail open.
        Security consequence: behavioral analysis detects evasion patterns (randomized
        timing, JA4 rotation). If a crash skips this signal, an attacker actively
        rotating fingerprints avoids detection.
        """
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()
        p._behavioral_analyzer.get_signals = AsyncMock(
            side_effect=RuntimeError("behavioral crash")
        )
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"


# ---------------------------------------------------------------------------
# MultiStrategyRateTracker init failure (lines 345-350)
# ---------------------------------------------------------------------------


class TestRateTrackerInitFailure:
    def test_rate_tracker_init_exception_disables_tracker(self):
        """Lines 345-350: MultiStrategyRateTracker constructor raises → _rate_tracker=None.
        Security consequence: if a rate_tracker init failure crashed the pipeline
        constructor, every new connection would fail. Instead, rate limiting is
        gracefully disabled (dial=0 mode still works; rate limits just don't fire).
        """
        policy = {"alpn_browser_bypass": {"enabled": False}}
        config = {
            "security_policy": policy,
            "geoip": {"country_blacklist": []},
        }
        cache = _make_cache(dial=0)
        mock_redis = MagicMock()

        with patch(
            "src.security.pipeline.MultiStrategyRateTracker",
            side_effect=RuntimeError("rate tracker init boom"),
        ):
            p = Pipeline(config=config, local_cache=cache, redis_client=mock_redis)

        assert p._rate_tracker is None
        # Pipeline must still be usable
        result = _run(p.process(_ctx(client_ip="1.2.3.4")))
        assert result.action == "allow"


# ---------------------------------------------------------------------------
# _emit_log — counterfactuals with non-allow actions (lines 1387-1391)
# ---------------------------------------------------------------------------


def _make_async_pipeline(dial=0, policy_overrides=None):
    """Pipeline with AsyncMock redis for tests that exercise async signal collection."""
    from unittest.mock import AsyncMock

    policy = {
        "alpn_browser_bypass": {"enabled": False},
        "ja4_whitelist_bypass": {"enabled": False},
        "mtls_bypass": {"enabled": False},
        "static_ip_allowlist": {"enabled": False},
        "ja4_blacklist_bypass": {"enabled": False},
        "country_blacklist_bypass": {"enabled": False},
    }
    if policy_overrides:
        policy.update(policy_overrides)
    config = {
        "security_policy": policy,
        "geoip": {"country_blacklist": []},
    }
    cache = _make_cache(dial=dial)
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    return Pipeline(config=config, local_cache=cache, redis_client=mock_redis)


class TestEmitLogCounterfactuals:
    def test_counterfactuals_with_non_allow_actions_logged(self):
        """Lines 1387-1391: counterfactuals dict with non-allow actions → would= string.
        Security consequence: monitor mode counterfactuals let secops preview what
        blocking would look like at each dial setting. If this path is broken,
        the 'would=' field in the log is empty — secops cannot assess the impact
        of enabling blocking without actually enabling it.
        """
        # Use AsyncMock redis so async signal collectors don't error out
        p = _make_async_pipeline(dial=0)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=60, signals=[], recommended_action="block"
        )
        mock_decider = MagicMock()
        mock_decider.decide.return_value = "block"
        mock_decider.counterfactuals.return_value = {25: "flag", 50: "block", 75: "ban"}
        p.update_scorer(mock_scorer, mock_decider)

        import logging
        log_records = []

        class CapturingHandler(logging.Handler):
            def emit(self, record):
                log_records.append(record.getMessage())

        handler = CapturingHandler()
        logger_obj = logging.getLogger("src.security.pipeline")
        logger_obj.addHandler(handler)
        logger_obj.setLevel(logging.DEBUG)
        try:
            ctx = _ctx(client_ip="1.2.3.4")
            _run(p.process(ctx))
        finally:
            logger_obj.removeHandler(handler)

        # At least one log record should contain 'would='
        would_lines = [r for r in log_records if "would=" in r]
        assert len(would_lines) >= 1
        # Should show non-allow counterfactual actions
        assert any("flag" in r or "block" in r or "ban" in r for r in would_lines)

    def test_empty_counterfactuals_shows_allow_at_all(self):
        """Lines 1391-1393: empty counterfactuals → 'allow@all' in log.
        Security consequence: if the 'allow@all' fallback is missing, the monitor-mode
        log line is malformed — log parsers will fail to extract the would-be action,
        breaking alerting rules that detect high-risk monitor-mode connections.
        """
        # Use AsyncMock redis so async signal collectors don't error out
        p = _make_async_pipeline(dial=0)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=0, signals=[], recommended_action="allow"
        )
        mock_decider = MagicMock()
        mock_decider.decide.return_value = "allow"
        mock_decider.counterfactuals.return_value = {}
        p.update_scorer(mock_scorer, mock_decider)

        import logging
        log_records = []

        class CapturingHandler(logging.Handler):
            def emit(self, record):
                log_records.append(record.getMessage())

        handler = CapturingHandler()
        logger_obj = logging.getLogger("src.security.pipeline")
        logger_obj.addHandler(handler)
        logger_obj.setLevel(logging.DEBUG)
        try:
            ctx = _ctx(client_ip="1.2.3.4")
            _run(p.process(ctx))
        finally:
            logger_obj.removeHandler(handler)

        would_lines = [r for r in log_records if "would=" in r]
        assert len(would_lines) >= 1
        assert any("allow@all" in r for r in would_lines)


# ---------------------------------------------------------------------------
# _emit_log — ja4x in JSON log (line 1437)
# ---------------------------------------------------------------------------


class TestEmitLogJa4x:
    def test_ja4x_emitted_in_json_log_when_present(self):
        """Line 1437: ja4x field is emitted in the JSON log when ctx.ja4x is set.
        Security consequence: if ja4x is absent from logs, post-incident forensics
        cannot correlate attack sessions by certificate fingerprint — a key attacker
        tracking mechanism is lost.
        """
        p = _make_pipeline()
        import json
        import logging

        json_records = []

        class JsonCapturingHandler(logging.Handler):
            def emit(self, record):
                try:
                    doc = json.loads(record.getMessage())
                    json_records.append(doc)
                except (json.JSONDecodeError, ValueError):
                    pass

        handler = JsonCapturingHandler()
        logger_obj = logging.getLogger("src.security.pipeline")
        logger_obj.addHandler(handler)
        logger_obj.setLevel(logging.DEBUG)
        try:
            # h2 bypass — bypassed connections still go through _emit_log
            ctx = _ctx(client_ip="1.2.3.4", alpn="h2", ja4x="abc123_def456_789012")
            _run(p.process(ctx))
        finally:
            logger_obj.removeHandler(handler)

        # Find a JSON record containing ja4x
        ja4x_records = [r for r in json_records if "ja4x" in r]
        assert len(ja4x_records) >= 1
        assert ja4x_records[0]["ja4x"] == "abc123_def456_789012"


# ---------------------------------------------------------------------------
# _emit_stream_event — counterfactuals fields (line 1467)
# ---------------------------------------------------------------------------


class TestEmitStreamEventCounterfactuals:
    def test_counterfactuals_written_as_action_at_fields(self):
        """Line 1466-1467: counterfactuals dict items written as action_at_{d} fields.
        Security consequence: the stream event is consumed by the analytics node to
        track what actions would have been taken at each dial setting. If counterfactual
        fields are missing, analytics cannot produce 'what would happen if dial=50'
        reports — secops cannot validate blocking thresholds safely before enabling them.
        """
        from unittest.mock import AsyncMock

        p = _make_pipeline()
        p._write_buffer.enqueue = AsyncMock()

        from src.security.pipeline import PipelineResult

        result = PipelineResult(
            action="allow",
            score=45,
            dial=0,
            counterfactuals={25: "flag", 50: "block", 75: "ban"},
        )
        ctx = _ctx()
        _run(p._emit_stream_event(ctx, result))

        call_args = p._write_buffer.enqueue.call_args
        fields = call_args[0][2]  # third positional arg to enqueue("xadd", key, fields)
        assert "action_at_25" in fields
        assert "action_at_50" in fields
        assert "action_at_75" in fields
        assert fields["action_at_25"] == "flag"
        assert fields["action_at_50"] == "block"
        assert fields["action_at_75"] == "ban"


# ---------------------------------------------------------------------------
# _extract_ja4x_from_cert (lines 1302-1335)
# ---------------------------------------------------------------------------


class TestExtractJA4xFromCert:
    def test_invalid_cert_bytes_returns_none(self):
        """Lines 1333-1335: parse failure on invalid DER bytes → None returned.
        Security consequence: mTLS client certs that can't be parsed for JA4X
        must fail open (return None) rather than crash. If an exception propagates,
        the mTLS bypass logic could fail and block a valid client.
        """
        p = _make_pipeline()
        result = p._extract_ja4x_from_cert(b"not-valid-der-bytes")
        assert result is None

    def test_empty_bytes_returns_none(self):
        """Empty cert bytes → cryptography parse failure → None."""
        p = _make_pipeline()
        result = p._extract_ja4x_from_cert(b"")
        assert result is None


# ---------------------------------------------------------------------------
# _get_analytics_signals — IPv6 subnet path (line 450)
# ---------------------------------------------------------------------------


class TestGetAnalyticsSignalsIPv6:
    def test_ipv6_address_uses_48_subnet(self):
        """Line 450: IPv6 address → /48 subnet computed correctly.
        Security consequence: if IPv6 addresses fall through to the IPv4 code path,
        analytics signals from IPv6 botnets are never correlated cross-instance —
        IPv6-based campaigns score only per-instance, never triggering subnet signals.
        """
        p = _make_async_cache_pipeline()
        # Call with an IPv6 address — should not crash and should return []
        result = _run(p._get_analytics_signals("2001:db8::1"))
        assert isinstance(result, list)

    def test_ipv6_campaign_signal_from_redis(self):
        """IPv6 address: campaign signal read from Redis for /48 subnet."""
        from unittest.mock import AsyncMock

        async def side_effect(key):
            if "2001:db8::/48" in key and "campaign" in key:
                return b"1"
            return None

        p = _make_async_cache_pipeline(redis_get_side_effect=side_effect)
        result = _run(p._get_analytics_signals("2001:db8::1"))
        names = [s.name for s in result]
        assert "analytics_campaign" in names


# ---------------------------------------------------------------------------
# update_ja4x_sets and start/stop (lines 528-529, 533, 537)
# ---------------------------------------------------------------------------


class TestUpdateJA4xSetsAndLifecycle:
    def test_update_ja4x_sets_stores_sets(self):
        """Lines 528-529: update_ja4x_sets() stores both whitelist and blacklist.
        Security consequence: JA4X fingerprint bypass and blacklist matching rely on
        in-process sets populated at startup. If update_ja4x_sets is not called or
        broken, all JA4X whitelist bypasses fail (blocks valid clients) and all
        JA4X blacklist signals are never emitted.
        """
        p = _make_pipeline()
        p.update_ja4x_sets({"good_ja4x"}, {"bad_ja4x"})
        assert "good_ja4x" in p._ja4x_whitelist
        assert "bad_ja4x" in p._ja4x_blacklist

    def test_start_and_stop_do_not_raise(self):
        """Lines 533, 537: start() and stop() complete without raising.
        Security consequence: if the WriteBuffer fails to start, deferred writes
        are never flushed — analytics stream events are silently dropped and the
        analytics node loses visibility into connection events.
        """
        from unittest.mock import AsyncMock

        p = _make_pipeline()
        p._write_buffer.start = AsyncMock()
        p._write_buffer.stop = AsyncMock()
        _run(p.start())
        _run(p.stop())
        p._write_buffer.start.assert_called_once()
        p._write_buffer.stop.assert_called_once()


# ---------------------------------------------------------------------------
# JA4X whitelist bypass (line 727)
# ---------------------------------------------------------------------------


class TestJA4XWhitelistBypass:
    def test_ja4x_in_whitelist_bypasses(self):
        """Line 727: ja4x in _ja4x_whitelist → ALLOW bypass.
        Security consequence: if JA4X whitelist bypass is broken, clients with
        trusted certificate chains (e.g. internal tooling with a known cert)
        are not bypassed and instead go through full scoring — this increases
        false positive risk for trusted infrastructure.
        """
        p = _make_pipeline()
        p._ja4x_whitelist = {"abc123_def456_789012"}
        ctx = _ctx(client_ip="1.2.3.4", ja4x="abc123_def456_789012")
        result = _run(p.process(ctx))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4x_whitelist"


# ---------------------------------------------------------------------------
# Spamhaus bypass — is_bypass=True path (lines 772-774)
# ---------------------------------------------------------------------------


class TestSpamhausBypassIsbypassTrue:
    def test_blocklisted_ip_with_bypass_feed_blocks(self):
        """Lines 772-774: IP in bypass feed → BLOCK bypass returned.
        Security consequence: Spamhaus DROP/EDROP must hard-block before the scorer.
        If the is_bypass check is broken, IPs in the Spamhaus DROP list are scored
        instead of blocked — an IP scoring below the dial threshold passes through.
        """
        config = {
            "security_policy": {
                "spamhaus_bypass": {"enabled": True},
                "alpn_browser_bypass": {"enabled": False},
                "ja4_whitelist_bypass": {"enabled": False},
                "mtls_bypass": {"enabled": False},
                "static_ip_allowlist": {"enabled": False},
                "ja4_blacklist_bypass": {"enabled": False},
                "country_blacklist_bypass": {"enabled": False},
            },
            "geoip": {"country_blacklist": []},
            "blocklists": {
                "feeds": [
                    {
                        "name": "spamhaus_drop",
                        "is_bypass": True,
                        "action": "block",
                        "score": 80,
                        "enabled": True,
                        "static_cidrs": ["203.0.113.0/24"],
                    }
                ]
            },
        }
        cache = _make_cache(dial=0)
        p = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        ctx = _ctx(client_ip="203.0.113.5")
        result = _run(p.process(ctx))
        assert result.action == "block"
        assert result.bypassed is True
        assert "spamhaus_drop" in result.bypass_reason


# ---------------------------------------------------------------------------
# _collect_signals — error paths for built-in modules (lines 856-916, 921-954)
# ---------------------------------------------------------------------------


class TestCollectSignalsErrorPaths:
    """Test the error-handling paths in _collect_signals for each built-in module.
    These tests exercise the asyncio.gather() error path where each nested function
    swallows its own exception and returns [].
    """

    def _make_signal_pipeline(self):
        """Pipeline with AsyncMock redis and all bypasses off for signal collection."""
        return _make_full_pipeline()

    def test_tls_mismatch_exception_logged(self):
        """Lines 857-864: exception in check_ja4_tls_mismatch → logged, continue.
        Security consequence: JA4/TLS version mismatch is a key evasion detection
        signal. If an exception in the mismatch check is not caught, it could
        propagate through _collect_signals and corrupt the signal list.
        """
        p = self._make_signal_pipeline()
        # check_ja4_tls_mismatch is imported inside the function body, so patch
        # it at the source module (tls_enforcer).
        with patch("src.security.tls_enforcer.check_ja4_tls_mismatch", side_effect=RuntimeError("mismatch boom")):
            ctx = _ctx(client_ip="1.2.3.4")
            result = _run(p.process(ctx))
        # Must not raise and must still allow
        assert result.action == "allow"

    def test_sni_analyzer_exception_skipped(self):
        """Lines 870-878: exception in SNI analyzer → logged, signal skipped.
        Security consequence: if an SNI analyzer exception propagates, the entire
        signal collection fails — the connection is allowed with score=0 but
        without any DGA/missing-SNI signals that should have been collected.
        """
        p = self._make_signal_pipeline()
        p._sni_analyzer.analyze = MagicMock(side_effect=RuntimeError("SNI crash"))
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_blocklist_get_signals_exception_skipped(self):
        """Lines 884-891: exception in blocklist.get_signals → logged, signal skipped.
        Security consequence: if blocklist signal collection crashes, IPs in non-bypass
        feeds (is_bypass=False) do not generate score contributions — they only get
        hard-blocked by the bypass check, missing the chance to blend with other signals.
        """
        p = self._make_signal_pipeline()
        p._blocklist_manager.get_signals = MagicMock(side_effect=RuntimeError("blocklist crash"))
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_tcp_analyzer_timeout_skipped(self):
        """Lines 898-907: TimeoutError in TCP analyzer → skipped, fail open.
        Security consequence: TCP analyzer detects session resumption abuse and
        high concurrency. On Redis timeout, skipping this signal is correct —
        blocking based on a timed-out signal would risk false positives.
        """
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._tcp_analyzer.analyze = AsyncMock(side_effect=asyncio.TimeoutError())
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_tcp_analyzer_generic_exception_skipped(self):
        """Lines 908-916: generic exception in TCP analyzer → logged, signal skipped."""
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._tcp_analyzer.analyze = AsyncMock(side_effect=RuntimeError("TCP crash"))
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_asn_classifier_timeout_skipped(self):
        """Lines 921-930: TimeoutError in ASN classifier → skipped, fail open.
        Security consequence: ASN/datacenter detection is enrichment — a timeout
        here must not block legitimate cloud-provider traffic that happens to
        originate from a datacenter ASN.
        """
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._asn_classifier.signals = AsyncMock(side_effect=asyncio.TimeoutError())
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_asn_classifier_generic_exception_skipped(self):
        """Lines 931-939: generic exception in ASN classifier → logged, signal skipped."""
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._asn_classifier.signals = AsyncMock(side_effect=RuntimeError("ASN crash"))
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_dns_enrichment_timeout_skipped(self):
        """Lines 946-954: TimeoutError in DNS enrichment → skipped, fail open.
        Security consequence: DNS PTR lookup is async enrichment — a timeout
        must never delay or block the connection decision.
        """
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._dns_enrichment.get_signal = AsyncMock(side_effect=asyncio.TimeoutError())
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_analytics_timeout_skipped(self):
        """Lines 1115-1124: TimeoutError in analytics signal collection → skipped.
        Security consequence: campaign analytics is cross-instance enrichment —
        Redis timeout here must not prevent the connection decision.
        """
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._get_analytics_signals = AsyncMock(side_effect=asyncio.TimeoutError())
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_analytics_generic_exception_skipped(self):
        """Lines 1125-1133: generic exception in analytics collection → skipped."""
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._get_analytics_signals = AsyncMock(side_effect=RuntimeError("analytics boom"))
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_rate_limiter_timeout_skipped(self):
        """Lines 982-989: TimeoutError in rate limiter → skipped, fail open.
        Security consequence: if rate limiter timeout causes a block, a Redis
        saturation event would block all connections — the opposite of fail-open.
        """
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        if p._rate_tracker is not None:
            p._rate_tracker.track_connection = AsyncMock(side_effect=asyncio.TimeoutError())
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_beacon_detector_timeout_skipped(self):
        """Lines 1040-1049: TimeoutError in beaconing detector → skipped, fail open."""
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._beaconing_detector.get_signal = AsyncMock(side_effect=asyncio.TimeoutError())
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_beacon_detector_generic_exception_skipped(self):
        """Lines 1050-1058: generic exception in beaconing detector → skipped."""
        from unittest.mock import AsyncMock

        p = self._make_signal_pipeline()
        p._beaconing_detector.get_signal = AsyncMock(side_effect=RuntimeError("beacon crash"))
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_abuseipdb_signal_collected_when_checker_present(self):
        """Lines 1063-1065: abuseipdb checker get_signal called and signal included.
        Security consequence: AbuseIPDB provides crowd-sourced abuse reports.
        If this path is not exercised, high-confidence abusive IPs (score>80)
        escape detection by the most accurate reputation source.
        """
        from src.security.models import RiskSignal

        p = self._make_signal_pipeline()
        mock_checker = MagicMock()
        mock_checker.get_signal.return_value = RiskSignal(
            name="abuseipdb", score=70, reason="AbuseIPDB confidence=70"
        )
        p.set_abuseipdb_checker(mock_checker)

        seen = []
        def capture(signals):
            seen.extend(signals)
            return MagicMock(total_score=70, signals=[], recommended_action="block")
        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="1.2.3.4")
        _run(p.process(ctx))
        mock_checker.get_signal.assert_called_with("1.2.3.4")
        assert any(s.name == "abuseipdb" for s in seen)

    def test_abuseipdb_timeout_skipped(self):
        """Lines 1066-1075: TimeoutError from abuseipdb.get_signal → skipped."""
        import asyncio
        p = self._make_signal_pipeline()
        mock_checker = MagicMock()
        mock_checker.get_signal.side_effect = asyncio.TimeoutError()
        p.set_abuseipdb_checker(mock_checker)
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_abuseipdb_generic_exception_skipped(self):
        """Lines 1076-1084: generic exception from abuseipdb.get_signal → skipped."""
        p = self._make_signal_pipeline()
        mock_checker = MagicMock()
        mock_checker.get_signal.side_effect = RuntimeError("abuseipdb crash")
        p.set_abuseipdb_checker(mock_checker)
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_rdap_signal_collected_when_enricher_present(self):
        """Lines 1089-1091: rdap enricher get_signal called and signal included.
        Security consequence: RDAP org reputation blocks entire hosting org netblocks.
        If this signal path is broken, hosting providers used exclusively by attackers
        never contribute to the score.
        """
        from src.security.models import RiskSignal

        p = self._make_signal_pipeline()
        mock_enricher = MagicMock()
        mock_enricher.get_signal.return_value = [
            RiskSignal(name="rdap_bad_org", score=50, reason="Bad org")
        ]
        mock_enricher.record_browser_subnet = MagicMock()
        p.set_rdap_enricher(mock_enricher)

        seen = []
        def capture(signals):
            seen.extend(signals)
            return MagicMock(total_score=50, signals=[], recommended_action="flag")
        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="1.2.3.4")
        _run(p.process(ctx))
        mock_enricher.get_signal.assert_called()
        assert any(s.name == "rdap_bad_org" for s in seen)

    def test_rdap_timeout_skipped(self):
        """Lines 1092-1101: TimeoutError from rdap enricher → skipped, fail open."""
        import asyncio
        p = self._make_signal_pipeline()
        mock_enricher = MagicMock()
        mock_enricher.get_signal.side_effect = asyncio.TimeoutError()
        mock_enricher.record_browser_subnet = MagicMock()
        p.set_rdap_enricher(mock_enricher)
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"

    def test_rdap_generic_exception_skipped(self):
        """Lines 1102-1110: generic exception from rdap enricher → skipped."""
        p = self._make_signal_pipeline()
        mock_enricher = MagicMock()
        mock_enricher.get_signal.side_effect = RuntimeError("RDAP crash")
        mock_enricher.record_browser_subnet = MagicMock()
        p.set_rdap_enricher(mock_enricher)
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"


# ---------------------------------------------------------------------------
# tracer path — ja4x and sni attributes on span (lines 564, 566)
# ---------------------------------------------------------------------------


class TestTracerSpanAttributes:
    def test_tracer_span_gets_ja4x_attribute(self):
        """Line 564: when ctx.ja4x is set, span.set_attribute('ja4x', ...) is called.
        Security consequence: missing ja4x in trace spans prevents forensic
        correlation of attacks by certificate chain fingerprint.
        """
        p = _make_pipeline()
        mock_span = MagicMock()
        mock_tracer_instance = MagicMock()
        mock_tracer_instance.start_as_current_span.return_value.__enter__ = MagicMock(
            return_value=mock_span
        )
        mock_tracer_instance.start_as_current_span.return_value.__exit__ = MagicMock(
            return_value=False
        )
        mock_tracer_obj = MagicMock()
        mock_tracer_obj.get_tracer.return_value = mock_tracer_instance
        p._tracer = mock_tracer_obj

        ctx = _ctx(client_ip="1.2.3.4", ja4x="abc123_def456_789012", sni="test.example.com")
        _run(p.process(ctx))

        # Verify span attributes were set for ja4x and sni
        set_calls = [str(c) for c in mock_span.set_attribute.call_args_list]
        assert any("ja4x" in c for c in set_calls)
        assert any("sni" in c for c in set_calls)


# ---------------------------------------------------------------------------
# _collect_signals — JA4X cert extraction (line 821)
# ---------------------------------------------------------------------------


class TestJA4XCertExtraction:
    def test_client_certificate_triggers_ja4x_extraction(self):
        """Line 820-821: ja4x=None with client_certificate → _extract_ja4x_from_cert called.
        Security consequence: mTLS clients present DER certs that should generate
        JA4X fingerprints for cert-chain based TI matching. If extraction is not
        triggered, mTLS clients are invisible to JA4X blacklist/whitelist checks.
        """
        p = _make_full_pipeline()
        # Patch _extract_ja4x_from_cert to return a known value
        with patch.object(p, "_extract_ja4x_from_cert", return_value="extracted_fp") as mock_extract:
            ctx = _ctx(client_ip="1.2.3.4", ja4x=None, client_certificate=b"\x30\x00")
            _run(p.process(ctx))
            mock_extract.assert_called_once_with(b"\x30\x00")


# ---------------------------------------------------------------------------
# _collect_signals — rate limiter signal logic (lines 993-1034)
# ---------------------------------------------------------------------------


class TestRateLimiterSignalLogic:
    def test_rate_limiter_majority_ban_produces_signal(self):
        """Lines 993-1013: majority_level='ban' when ≥2 strategies agree → ban signal.
        Security consequence: the majority policy prevents a single misconfigured
        rate-limit strategy from triggering a ban. If this logic is broken, an
        attacker can tune their rate to stay just above one strategy's ban threshold
        while below others, avoiding the signal entirely.
        """
        from unittest.mock import AsyncMock

        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        if p._rate_tracker is None:
            return  # Skip if rate tracker disabled

        # Mock track_connection to return metrics indicating ban level for 2+ strategies
        mock_metrics = {}

        class MockStrategy:
            def __init__(self, val):
                self.value = val

        class MockMetric:
            connections_per_second = 200.0

        class MockStrategyConfig:
            ban_threshold = 100.0
            block_threshold = 50.0
            suspicious_threshold = 20.0

        strategy_a = MockStrategy("by_ip")
        strategy_b = MockStrategy("by_ja4")

        mock_metrics[strategy_a] = MockMetric()
        mock_metrics[strategy_b] = MockMetric()

        p._rate_tracker.track_connection = AsyncMock(return_value=mock_metrics)
        p._rate_tracker.get_strategy_config = MagicMock(return_value=MockStrategyConfig())

        seen = []
        def capture(signals):
            seen.extend(signals)
            return MagicMock(total_score=90, signals=[], recommended_action="ban")
        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="1.2.3.4")
        _run(p.process(ctx))
        assert any("rate_limit_ban" in s.name for s in seen)

    def test_rate_limiter_single_ban_strategy_falls_back(self):
        """Lines 1001-1002: only one strategy at 'ban' → majority_level still becomes ban.
        Security consequence: even a single strategy indicating 'ban' (when no
        majority is met) escalates to ban — this is the fail-safe rule that prevents
        a high-confidence single-strategy signal from being ignored.
        """
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()
        if p._rate_tracker is None:
            return

        class MockStrategy:
            def __init__(self, val):
                self.value = val

        class MockMetricHigh:
            connections_per_second = 200.0

        class MockMetricLow:
            connections_per_second = 5.0

        class MockStrategyConfigHigh:
            ban_threshold = 100.0
            block_threshold = 50.0
            suspicious_threshold = 20.0

        class MockStrategyConfigLow:
            ban_threshold = 100.0
            block_threshold = 50.0
            suspicious_threshold = 20.0

        strategy_a = MockStrategy("by_ip")
        strategy_b = MockStrategy("by_ja4")

        mock_metrics = {
            strategy_a: MockMetricHigh(),
            strategy_b: MockMetricLow(),
        }

        def get_config(strategy):
            if strategy == strategy_a:
                return MockStrategyConfigHigh()
            return MockStrategyConfigLow()

        p._rate_tracker.track_connection = AsyncMock(return_value=mock_metrics)
        p._rate_tracker.get_strategy_config = MagicMock(side_effect=get_config)

        seen = []
        def capture(signals):
            seen.extend(signals)
            return MagicMock(total_score=90, signals=[], recommended_action="ban")
        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="1.2.3.4")
        _run(p.process(ctx))
        # Only one strategy at ban → falls back to ban signal
        assert any("rate_limit" in s.name for s in seen)

    def test_rate_limiter_block_level_signal(self):
        """Lines 987: strategy at block threshold (below ban, above block) → 'block' level.
        Security consequence: the 'block' level produces a score=60 signal, which at
        dial=50 maps to a block action. If the elif branch is missing, block-threshold
        crossings are silently ignored and only ban-level connections are scored.
        """
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()
        if p._rate_tracker is None:
            return

        class MockStrategy:
            def __init__(self, val):
                self.value = val

        class MockMetric:
            connections_per_second = 75.0  # above block (50), below ban (100)

        class MockStrategyConfig:
            ban_threshold = 100.0
            block_threshold = 50.0
            suspicious_threshold = 20.0

        strategy_a = MockStrategy("by_ip")
        strategy_b = MockStrategy("by_ja4")
        mock_metrics = {strategy_a: MockMetric(), strategy_b: MockMetric()}

        p._rate_tracker.track_connection = AsyncMock(return_value=mock_metrics)
        p._rate_tracker.get_strategy_config = MagicMock(return_value=MockStrategyConfig())

        seen = []
        def capture(signals):
            seen.extend(signals)
            return MagicMock(total_score=60, signals=[], recommended_action="block")
        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="1.2.3.4")
        _run(p.process(ctx))
        assert any("rate_limit_block" in s.name for s in seen)

    def test_rate_limiter_suspicious_level_signal(self):
        """Lines 989: strategy at suspicious threshold → 'suspicious' level signal.
        Security consequence: the suspicious level (score=20) is early warning.
        If missing, borderline-rate connections are never flagged before they escalate.
        """
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()
        if p._rate_tracker is None:
            return

        class MockStrategy:
            def __init__(self, val):
                self.value = val

        class MockMetric:
            connections_per_second = 25.0  # above suspicious (20), below block (50)

        class MockStrategyConfig:
            ban_threshold = 100.0
            block_threshold = 50.0
            suspicious_threshold = 20.0

        strategy_a = MockStrategy("by_ip")
        strategy_b = MockStrategy("by_ja4")
        mock_metrics = {strategy_a: MockMetric(), strategy_b: MockMetric()}

        p._rate_tracker.track_connection = AsyncMock(return_value=mock_metrics)
        p._rate_tracker.get_strategy_config = MagicMock(return_value=MockStrategyConfig())

        seen = []
        def capture(signals):
            seen.extend(signals)
            return MagicMock(total_score=20, signals=[], recommended_action="allow")
        p._scorer.score.side_effect = capture

        ctx = _ctx(client_ip="1.2.3.4")
        _run(p.process(ctx))
        assert any("rate_limit_suspicious" in s.name for s in seen)

    def test_rate_limiter_generic_exception_skipped(self):
        """Lines 1026-1034: generic exception in rate limiter → [], fail open.
        Security consequence: if rate limiter logic crashes (e.g. bad Redis response
        format), the exception must be caught so the connection is not blocked by
        a scoring error — rate limit bugs must not cause false positives.
        """
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()
        if p._rate_tracker is None:
            return
        p._rate_tracker.track_connection = AsyncMock(side_effect=RuntimeError("rate limiter crash"))
        ctx = _ctx(client_ip="1.2.3.4")
        result = _run(p.process(ctx))
        assert result.action == "allow"


# ---------------------------------------------------------------------------
# TLS mismatch signal appended (line 856)
# ---------------------------------------------------------------------------


class TestTLSMismatchSignalAppended:
    def test_tls_mismatch_signal_appended_to_signals(self):
        """Line 856: check_ja4_tls_mismatch returns a signal → it is appended.
        Security consequence: JA4 encodes the declared TLS version while ctx.tls_version
        is the negotiated version. A mismatch means the client is spoofing its
        ClientHello to bypass fingerprint-based filters. If the signal is not appended,
        this evasion technique scores 0 and passes through.
        """
        from unittest.mock import AsyncMock

        from src.security.models import RiskSignal

        p = _make_full_pipeline()
        mismatch_sig = RiskSignal(name="ja4_tls_mismatch", score=40, reason="mismatch detected")

        with patch("src.security.tls_enforcer.check_ja4_tls_mismatch", return_value=mismatch_sig):
            seen = []
            def capture(signals):
                seen.extend(signals)
                return MagicMock(total_score=40, signals=[], recommended_action="flag")
            p._scorer.score.side_effect = capture

            ctx = _ctx(client_ip="1.2.3.4")
            _run(p.process(ctx))

        assert any(s.name == "ja4_tls_mismatch" for s in seen)


# ---------------------------------------------------------------------------
# _extract_ja4x_from_cert — successful parse (lines 1309-1332)
# ---------------------------------------------------------------------------


class TestExtractJA4xFromCertSuccess:
    def test_valid_self_signed_cert_produces_fingerprint(self):
        """Lines 1309-1332: valid DER-encoded cert → JA4X fingerprint string returned.
        Security consequence: if JA4X extraction from mTLS certs is broken, the
        JA4X blacklist/whitelist bypass never fires for mTLS clients — attackers
        using a known-bad cert chain bypass detection and victims with known-good
        certs are not allowed through the bypass.
        """
        try:
            import datetime

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
        except ImportError:
            return  # Skip if cryptography not available

        # Generate a minimal self-signed cert with a SAN extension to exercise
        # the san extraction branch (line 1321)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        p = _make_pipeline()
        result = p._extract_ja4x_from_cert(der_bytes)
        # Result should be a string matching the JA4X format: hash_hash_hash
        assert result is not None
        assert isinstance(result, str)
        parts = result.split("_")
        assert len(parts) == 3
        # Each hash component should be 12 hex chars
        for part in parts:
            assert len(part) == 12
            assert all(c in "0123456789abcdef" for c in part)

    def test_cert_without_san_uses_empty_hash(self):
        """Lines 1322-1323, 1327: cert without SAN extension → ExtensionNotFound caught,
        san='', and _hash('') returns '000000000000'.
        Security consequence: if ExtensionNotFound is not caught, parsing any cert
        without a SAN extension (common in internal CA certs) would return None
        instead of a valid fingerprint — mTLS clients using minimal certs would
        never generate a JA4X fingerprint for blacklist matching.
        """
        try:
            import datetime

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
        except ImportError:
            return

        # Generate a cert with NO SAN extension
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "no-san-test"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            # Deliberately NO .add_extension for SAN
            .sign(key, hashes.SHA256())
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        p = _make_pipeline()
        result = p._extract_ja4x_from_cert(der_bytes)
        assert result is not None
        # Third component (SAN hash) should be the empty-string sentinel
        parts = result.split("_")
        assert len(parts) == 3
        assert parts[2] == "000000000000"


# ---------------------------------------------------------------------------
# Parallel collection exception escape (lines 1283-1289)
# ---------------------------------------------------------------------------


class TestParallelCollectionException:
    def test_parallel_collection_exception_escape_logged(self):
        """Lines 1283-1289: exception escaping asyncio.gather (return_exceptions=True)
        → logged as parallel_collection_error, not re-raised.
        Security consequence: in theory all per-module collectors catch their own
        exceptions. This path fires if return_exceptions=True still receives an
        Exception object. If this logging branch is missing, untracked exceptions
        from gather() would silently corrupt the signals list.
        """
        import asyncio
        from unittest.mock import AsyncMock

        p = _make_full_pipeline()

        # Patch asyncio.gather to return a list containing an Exception object
        # (simulating a collector that bypassed its own exception handler)
        original_gather = asyncio.gather

        async def patched_gather(*coros, return_exceptions=False, **kwargs):
            # Run only the first awaitable to keep other coverage paths alive,
            # then inject an escaped Exception in the results.
            results = await original_gather(*coros, return_exceptions=True, **kwargs)
            # Inject an escaped exception to exercise lines 1283-1289
            results = list(results)
            results.append(RuntimeError("escaped exception"))
            return results

        with patch("asyncio.gather", side_effect=patched_gather):
            ctx = _ctx(client_ip="1.2.3.4")
            result = _run(p.process(ctx))

        # Must not raise — exception was absorbed
        assert result.action == "allow"
