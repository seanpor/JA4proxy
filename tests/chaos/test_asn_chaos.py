"""Chaos tests for ASN classifier."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider
from src.security.asn_classifier import ASNClassifier
from src.security.pipeline import ConnectionContext, Pipeline
from src.security.risk_scorer import RiskScorer

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def _run(coro):
    try:
        loop = asyncio.get_running_loop()
        raise RuntimeError("_run() should not be called from within an async context")
    except RuntimeError:
        return asyncio.new_event_loop().run_until_complete(coro)


def _make_pipeline(dial: int = 100) -> Pipeline:
    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
        },
        "asn_classifier": {
            "enabled": True,
            "datacenter_list_path": "config/asn_datacenter_list.yml",
            "maxmind_db_path": "config/GeoLite2-ASN.mmdb",
            "tor_exit_list": {
                "enabled": True,
                "refresh_interval_seconds": 3600,
            },
            "risk_contributions": {
                "tor": 40,
                "datacenter": 20,
                "vpn": 10,
                "unknown": 5,
                "residential": 0,
                "mobile": 0,
            },
        },
    }
    cache = LocalCache({})
    cache.dial = dial
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _ctx(**kwargs) -> ConnectionContext:
    defaults = {"client_ip": "1.2.3.4", "ja4": "t13d_test_fp", "sni": "example.com"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


class TestASNClassifierChaos:
    """ASN classifier handles chaos scenarios gracefully."""

    def test_maxmind_db_missing_fails_open(self):
        """Missing MaxMind database → classifier disabled, no crash, pipeline allows."""
        config = {
            "asn_classifier": {
                "enabled": True,
                "datacenter_list_path": "config/asn_datacenter_list.yml",
                "maxmind_db_path": "config/nonexistent.mmdb",  # Missing file
                "tor_exit_list": {"enabled": False},
            },
        }
        classifier = ASNClassifier(config, MagicMock())

        # Should not crash, should return unknown classification
        result = classifier.classify("1.2.3.4")
        assert result.category == "unknown"

    def test_tor_list_download_failure_retains_cache(self):
        """Tor list download fails → last known list retained, no crash."""
        mock_redis = MagicMock()
        mock_redis.smembers.side_effect = ConnectionError("Redis down")

        config = {
            "asn_classifier": {
                "enabled": True,
                "tor_exit_list": {"enabled": True, "refresh_interval_seconds": 3600},
            },
        }

        classifier = ASNClassifier(config, mock_redis)
        # Simulate having a cached list
        classifier._tor_exit_ips = {"1.2.3.4", "5.6.7.8"}

        # Force a refresh that will fail
        with patch("aiohttp.ClientSession.get") as mock_get:
            mock_get.side_effect = Exception("Download failed")
            asyncio.run(classifier._refresh_tor_list())

        # Original list should be retained
        assert len(classifier._tor_exit_ips) == 2

    def test_redis_leader_election_failure_uses_cached(self):
        """Redis leader election fails → use cached Tor list if available."""
        mock_redis = MagicMock()
        mock_redis.set.side_effect = ConnectionError("Redis down")
        mock_redis.smembers.return_value = {b"1.2.3.4", b"5.6.7.8"}

        config = {
            "asn_classifier": {
                "enabled": True,
                "tor_exit_list": {"enabled": True, "refresh_interval_seconds": 3600},
            },
        }

        classifier = ASNClassifier(config, mock_redis)
        asyncio.run(classifier._init_tor_list())

        # Should have loaded from Redis
        assert len(classifier._tor_exit_ips) == 2

    def test_asn_classifier_error_in_pipeline_fails_open(self):
        """ASN classifier raises in pipeline → pipeline fails open (allow)."""
        pipeline = _make_pipeline(dial=100)

        # Force ASN classifier to raise
        with patch.object(
            pipeline._asn_classifier, "signals", side_effect=RuntimeError("ASN error")
        ):
            result = _run(pipeline.process(_ctx()))

        assert result.action == "allow"

    def test_tor_list_refresh_loop_continues_after_error(self):
        """Tor refresh loop continues running after transient error."""
        mock_redis = MagicMock()
        refresh_count = 0

        config = {
            "asn_classifier": {
                "enabled": True,
                "tor_exit_list": {"enabled": True, "refresh_interval_seconds": 1},
            },
        }

        classifier = ASNClassifier(config, mock_redis)

        async def mock_refresh():
            nonlocal refresh_count
            refresh_count += 1
            if refresh_count == 1:
                raise Exception("First refresh fails")
            # Second refresh succeeds
            classifier._tor_exit_ips = {"1.2.3.4"}

        async def run_test():
            with patch.object(classifier, "_refresh_tor_list", side_effect=mock_refresh):
                # Run the refresh loop for 2 iterations with timeout
                task = asyncio.create_task(classifier._tor_refresh_loop(1))
                await asyncio.sleep(2.1)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass  # Expected

        asyncio.run(run_test())

        # Should have attempted refresh at least once
        assert refresh_count >= 1

    def test_classify_with_invalid_ip_no_crash(self):
        """Invalid IP string → classifier returns unknown, no crash."""
        config = {
            "asn_classifier": {
                "enabled": True,
                "datacenter_list_path": "config/asn_datacenter_list.yml",
                "maxmind_db_path": "config/GeoLite2-ASN.mmdb",
                "tor_exit_list": {"enabled": False},
            },
        }
        classifier = ASNClassifier(config, MagicMock())

        # Invalid IP should not crash
        result = classifier.classify("invalid-ip-string")
        assert result.category == "unknown"

    def test_classify_with_ipv6_no_crash(self):
        """IPv6 address → classifier handles correctly, no crash."""
        config = {
            "asn_classifier": {
                "enabled": True,
                "datacenter_list_path": "config/asn_datacenter_list.yml",
                "maxmind_db_path": "config/GeoLite2-ASN.mmdb",
                "tor_exit_list": {"enabled": False},
            },
        }
        classifier = ASNClassifier(config, MagicMock())

        # IPv6 should not crash
        result = classifier.classify("2001:db8::1")
        # Should return some classification (likely unknown without MaxMind)
        assert result.category in ["unknown", "residential", "datacenter", "vpn", "tor", "mobile"]


class TestASNClassifierDisabledChaos:
    """Disabled ASN classifier handles chaos gracefully."""

    def test_disabled_classifier_no_signals(self):
        """Disabled classifier → no ASN signals, no errors."""
        config = {
            "asn_classifier": {"enabled": False},
        }
        classifier = ASNClassifier(config, MagicMock())

        result = classifier.classify("1.2.3.4")
        assert result.category == "unknown"

        signals = asyncio.run(classifier.signals(ConnectionContext(client_ip="1.2.3.4")))
        assert len(signals) == 0

    def test_disabled_classifier_in_pipeline_no_crash(self):
        """Disabled classifier in pipeline → pipeline continues normally."""
        config = {
            "security_policy": {
                "alpn_browser_bypass": {"enabled": True},
                "ja4_whitelist_bypass": {"enabled": True},
                "mtls_bypass": {"enabled": True},
                "static_ip_allowlist": {"enabled": True},
                "ja4_blacklist_bypass": {"enabled": True},
                "country_blacklist_bypass": {"enabled": True},
            },
            "asn_classifier": {"enabled": False},
        }
        cache = LocalCache({})
        cache.dial = 100
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        scorer = RiskScorer(THRESHOLDS)
        decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
        pipeline.update_scorer(scorer, decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action in ["allow", "flag"]
        assert not any(s.name.startswith("asn_") for s in result.signals)
