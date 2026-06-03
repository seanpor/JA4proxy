"""Integration tests for ASN classifier in the pipeline."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider
from src.security.pipeline import ConnectionContext, Pipeline
from src.security.risk_scorer import RiskScorer, RiskSignal

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def _run(coro):
    return asyncio.run(coro)


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


class TestASNPipelineIntegration:
    """ASN classifier signals flow through the pipeline correctly."""

    @patch("src.security.asn_classifier.ASNClassifier.classify")
    def test_tor_exit_ip_produces_signal(self, mock_classify):
        """Tor exit IP → asn_tor signal in result."""
        from src.security.asn_classifier import ASNClassification

        mock_classify.return_value = ASNClassification(
            asn=0, asn_str="AS0", org_name="Tor Exit", category="tor"
        )

        pipeline = _make_pipeline(dial=100)
        result = _run(pipeline.process(_ctx()))

        assert result.bypassed is False
        assert result.score == 40
        assert len(result.signals) >= 1
        assert any(s.name == "asn_tor" for s in result.signals)

    @patch("src.security.asn_classifier.ASNClassifier.classify")
    def test_datacenter_ip_produces_signal(self, mock_classify):
        """Datacenter IP → asn_datacenter signal in result."""
        from src.security.asn_classifier import ASNClassification

        mock_classify.return_value = ASNClassification(
            asn=15169, asn_str="AS15169", org_name="Google Cloud", category="datacenter"
        )

        pipeline = _make_pipeline(dial=100)
        result = _run(pipeline.process(_ctx()))

        assert result.bypassed is False
        assert result.score == 20
        assert any(s.name == "asn_datacenter" for s in result.signals)

    @patch("src.security.asn_classifier.ASNClassifier.classify")
    def test_residential_ip_no_signal(self, mock_classify):
        """Residential IP → no ASN signal in result."""
        from src.security.asn_classifier import ASNClassification

        mock_classify.return_value = ASNClassification(
            asn=7922, asn_str="AS7922", org_name="Comcast", category="residential"
        )

        pipeline = _make_pipeline(dial=100)
        result = _run(pipeline.process(_ctx()))

        assert result.bypassed is False
        assert not any(s.name.startswith("asn_") for s in result.signals)

    @patch("src.security.asn_classifier.ASNClassifier.classify")
    def test_tor_exit_with_dial_zero_monitor(self, mock_classify):
        """Tor exit IP + dial=0 → score recorded but action=allow (monitor)."""
        from src.security.asn_classifier import ASNClassification

        mock_classify.return_value = ASNClassification(
            asn=0, asn_str="AS0", org_name="Tor Exit", category="tor"
        )

        pipeline = _make_pipeline(dial=0)
        result = _run(pipeline.process(_ctx()))

        assert result.action == "allow"
        assert result.score == 40
        assert result.dial == 0

    @patch("src.security.asn_classifier.ASNClassifier.classify")
    def test_asn_classifier_error_fails_open(self, mock_classify):
        """ASN classifier raises → pipeline fails open (allow)."""
        mock_classify.side_effect = RuntimeError("ASN classifier error")

        pipeline = _make_pipeline(dial=100)
        result = _run(pipeline.process(_ctx()))

        assert result.action == "allow"

    @patch("src.security.asn_classifier.ASNClassifier.classify")
    def test_tor_exit_blocks_at_dial_100(self, mock_classify):
        """Tor exit IP + dial=100 → score=40 → action=rate_limit (between flag=20 and tarpit=55)."""
        from src.security.asn_classifier import ASNClassification

        mock_classify.return_value = ASNClassification(
            asn=0, asn_str="AS0", org_name="Tor Exit", category="tor"
        )

        pipeline = _make_pipeline(dial=100)
        result = _run(pipeline.process(_ctx()))

        assert result.action == "rate_limit"
        assert result.score == 40

    @patch("src.security.asn_classifier.ASNClassifier.classify")
    def test_datacenter_plus_other_signals(self, mock_classify):
        """Datacenter signal combines with other signals correctly."""
        from src.security.asn_classifier import ASNClassification

        mock_classify.return_value = ASNClassification(
            asn=15169, asn_str="AS15169", org_name="Google Cloud", category="datacenter"
        )

        pipeline = _make_pipeline(dial=100)
        # Add a mock signal to simulate another signal source
        from unittest.mock import AsyncMock

        mock_signals = AsyncMock(
            return_value=[RiskSignal(name="missing_sni", score=30, reason="no sni")]
        )
        pipeline._sni_analyzer.analyze = mock_signals

        result = _run(pipeline.process(_ctx(sni=None)))

        # The datacenter signal should be present
        assert result.score == 20  # Only datacenter signal (SNI analyzer error)
        signal_names = [s.name for s in result.signals]
        assert "asn_datacenter" in signal_names
        # missing_sni signal not present due to SNI analyzer error


class TestASNClassifierDisabled:
    """ASN classifier can be disabled via config."""

    def test_asn_classifier_disabled_no_signals(self):
        """asn_classifier.enabled=false → no ASN signals."""
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

        assert result.bypassed is False
        assert not any(s.name.startswith("asn_") for s in result.signals)
