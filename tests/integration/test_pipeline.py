"""Integration tests for the full pipeline (Phases 1–3).

Tests that the pipeline wires scorer, decider, and TLS enforcer correctly
and that bypass, scoring, monitor-mode, and TLS enforcement paths all
produce correct results.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider
from src.security.pipeline import ConnectionContext, Pipeline
from src.security.risk_scorer import RiskScorer, RiskSignal
from src.security.tls_enforcer import TLS11, TLS12, TLS13

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


def _make_pipeline(dial: int = 75) -> Pipeline:
    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
        }
    }
    cache = LocalCache({})
    cache.dial = dial
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _ctx(**kwargs) -> ConnectionContext:
    defaults = {"client_ip": "185.220.101.5", "ja4": "t13d_bad_fingerprint_aa"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


class TestPipelineBypasses:
    """Bypass paths produce correct PipelineResult."""

    def test_h2_alpn_bypass_logged_correctly(self):
        pipeline = _make_pipeline()
        result = _run(pipeline.process(_ctx(alpn="h2")))
        assert result.action == "allow"
        assert result.bypassed is True
        assert result.bypass_reason == "alpn_browser"
        assert result.score is None
        assert result.signals == []

    def test_known_bad_ja4_blocked(self):
        pipeline = _make_pipeline()
        pipeline._blacklist = {"t13d_bad_fingerprint_aa"}
        result = _run(pipeline.process(_ctx()))
        assert result.action == "block"
        assert result.bypassed is True
        assert result.bypass_reason == "ja4_blacklist"


class TestPipelineScoring:
    """End-to-end scoring with real RiskScorer + ActionDecider."""

    def test_zero_signals_allows(self):
        pipeline = _make_pipeline(dial=100)
        # Provide SNI to avoid missing_sni signal
        result = _run(pipeline.process(_ctx(sni="example.com")))
        assert result.action in ["allow", "flag"]
        assert result.score == 0

    def test_dial_zero_allows_even_high_score(self):
        """dial=0 → MONITOR; action=allow regardless of score."""
        pipeline = _make_pipeline(dial=0)
        # Inject high-scoring signals manually via a mock scorer
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=90,
            signals=[RiskSignal("asn_tor", 90, "tor")],
            recommended_action="ban",
            explanation="asn_tor(+90)",
        )
        mock_decider = MagicMock()
        mock_decider.decide.return_value = "ban"
        pipeline.update_scorer(mock_scorer, mock_decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action in ["allow", "flag"]

        assert result.score == 90  # Score is recorded

    def test_dial_100_high_score_blocks(self):
        """dial=100 + score above block threshold → block action."""
        pipeline = _make_pipeline(dial=100)
        # Inject a scorer that returns score=78 (between block=70 and ban=85)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=78,
            signals=[
                RiskSignal("rdap_known_bad_org", 45, "bad org"),
                RiskSignal("missing_sni", 30, "no sni"),
            ],
            recommended_action="block",
            explanation="rdap_known_bad_org(+45), missing_sni(+30)",
        )
        decider = ActionDecider(THRESHOLDS)
        pipeline.update_scorer(mock_scorer, decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action == "block"
        assert result.score == 78

    def test_signals_list_populated(self):
        """Signals from scorer appear in PipelineResult."""
        pipeline = _make_pipeline(dial=100)
        signals = [RiskSignal("missing_sni", 30, "no sni")]
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=30,
            signals=signals,
            recommended_action="flag",
            explanation="missing_sni(+30)",
        )
        decider = ActionDecider(THRESHOLDS)
        pipeline.update_scorer(mock_scorer, decider)

        result = _run(pipeline.process(_ctx()))
        assert len(result.signals) == 1
        assert result.signals[0].name == "missing_sni"


class TestPipelineMonitorMode:
    """dial=0 produces monitor log lines, not blocking actions."""

    def test_monitor_result_has_score_but_allow_action(self):
        pipeline = _make_pipeline(dial=0)
        mock_scorer = MagicMock()
        mock_scorer.score.return_value = MagicMock(
            total_score=61,
            signals=[],
            recommended_action="tarpit",
            explanation="",
        )
        mock_decider = MagicMock()
        mock_decider.decide.return_value = "tarpit"
        pipeline.update_scorer(mock_scorer, mock_decider)

        result = _run(pipeline.process(_ctx()))
        assert result.action == "allow"
        assert result.score == 61
        assert result.dial == 0


# ---------------------------------------------------------------------------
# Phase 3: TLS enforcement integration
# ---------------------------------------------------------------------------


def _make_tls_pipeline(
    dial: int = 100, tls_enforcer_cfg: dict | None = None
) -> Pipeline:
    """Pipeline with TLS enforcer config and real scorer/decider."""
    te_cfg = {
        "enabled": True,
        "block_ssl3": True,
        "block_tls_10": True,
        "block_tls_11": True,
        "flag_tls_12": False,
        "score": 10,
        "block_weak_ciphers": False,
        "weak_cipher_score": 20,
        "weak_ciphers": [],
    }
    if tls_enforcer_cfg:
        te_cfg.update(tls_enforcer_cfg)

    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
            "tls_version_bypass": {"enabled": True},
        },
        "tls_enforcer": te_cfg,
    }
    cache = LocalCache({})
    cache.dial = dial
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _tls_ctx(**kwargs) -> ConnectionContext:
    defaults = {"client_ip": "1.2.3.4", "ja4": "t13d_test_fp_aabbccddee11"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


class TestTLSEnforcerIntegration:
    """TLS enforcement wired into the pipeline."""

    def test_tls11_bypass_enabled_hard_block(self):
        """TLS 1.1 + tls_version_bypass enabled → block at pipeline entry, scorer not called."""
        pipeline = _make_tls_pipeline()
        mock_scorer = MagicMock()
        pipeline._scorer = mock_scorer

        ctx = _tls_ctx(tls_version=TLS11)
        result = _run(pipeline.process(ctx))

        assert result.action == "block"
        assert result.bypassed is True
        assert result.bypass_reason == "tls_version"
        mock_scorer.score.assert_not_called()  # scorer never reached

    def test_tls11_bypass_disabled_scored(self):
        """TLS 1.1 + bypass disabled → tls_version signal reaches scorer."""
        config = {
            "security_policy": {
                "alpn_browser_bypass": {"enabled": True},
                "ja4_whitelist_bypass": {"enabled": True},
                "mtls_bypass": {"enabled": True},
                "static_ip_allowlist": {"enabled": True},
                "ja4_blacklist_bypass": {"enabled": True},
                "country_blacklist_bypass": {"enabled": True},
                "tls_version_bypass": {"enabled": False},  # bypass disabled
            },
            "tls_enforcer": {
                "enabled": True,
                "block_tls_11": True,
                "block_ssl3": True,
            },
        }
        cache = LocalCache({})
        cache.dial = 100
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        pipeline.update_scorer(RiskScorer(THRESHOLDS), ActionDecider(THRESHOLDS))

        ctx = _tls_ctx(tls_version=TLS11)
        result = _run(pipeline.process(ctx))

        # Signal emitted — connection scored; not bypassed
        assert result.bypassed is False
        assert result.score is not None
        assert result.score > 0  # tls_version signal (score=40) was included
        assert any(getattr(s, "name", None) == "tls_version" for s in result.signals)

    def test_weak_cipher_scored_when_not_blocking(self):
        """Weak cipher + block_weak_ciphers=false → scored signal in result."""
        pipeline = _make_tls_pipeline(
            tls_enforcer_cfg={"block_weak_ciphers": False, "weak_cipher_score": 20}
        )
        ctx = _tls_ctx(tls_version=TLS13, cipher_list=[0x0004])  # RC4
        result = _run(pipeline.process(ctx))

        assert result.bypassed is False
        assert result.score >= 20
        assert any(getattr(s, "name", None) == "weak_cipher" for s in result.signals)

    def test_tls13_strong_ciphers_allow(self):
        """TLS 1.3 with strong ciphers → allow, no TLS signals."""
        pipeline = _make_tls_pipeline()
        ctx = _tls_ctx(tls_version=TLS13, cipher_list=[0xC02B, 0x1301])
        result = _run(pipeline.process(ctx))

        assert result.action in ["allow", "flag"]
        assert not any(
            getattr(s, "name", "") in ("tls_version", "weak_cipher")
            for s in result.signals
        )

    def test_hot_reload_flag_tls12_true_emits_signal(self):
        """Hot reload changes flag_tls_12=true → next connection gets signal."""
        pipeline = _make_tls_pipeline(tls_enforcer_cfg={"flag_tls_12": False})

        ctx = _tls_ctx(tls_version=TLS12)
        result_before = _run(pipeline.process(ctx))
        assert not any(
            getattr(s, "name", "") == "tls_version" for s in result_before.signals
        )

        # Hot reload with flag_tls_12=True
        new_config = {
            "security_policy": {
                "alpn_browser_bypass": {"enabled": True},
                "ja4_whitelist_bypass": {"enabled": True},
                "mtls_bypass": {"enabled": True},
                "static_ip_allowlist": {"enabled": True},
                "ja4_blacklist_bypass": {"enabled": True},
                "country_blacklist_bypass": {"enabled": True},
                "tls_version_bypass": {"enabled": True},
            },
            "tls_enforcer": {
                "enabled": True,
                "flag_tls_12": True,
                "score": 10,
                "block_ssl3": True,
                "block_tls_10": True,
                "block_tls_11": True,
            },
        }
        pipeline.on_config_reload(new_config)

        result_after = _run(pipeline.process(ctx))
        assert any(
            getattr(s, "name", "") == "tls_version" for s in result_after.signals
        )

    def test_no_tls_version_in_context_no_crash(self):
        """ctx.tls_version=None → no crash; TLS enforcer skips version check."""
        pipeline = _make_tls_pipeline()
        ctx = _tls_ctx(tls_version=None, cipher_list=[])
        result = _run(pipeline.process(ctx))
        assert result.action in ["allow", "flag"]


# ---------------------------------------------------------------------------
# Phase 7: DNS enrichment integration
# ---------------------------------------------------------------------------


class TestDNSEnrichmentIntegration:
    """DNS enrichment wired into the pipeline signal collection."""

    def test_cached_no_ptr_signal_reaches_scorer(self):
        """A cached no_ptr result produces a RiskSignal in the pipeline output."""
        from unittest.mock import AsyncMock, patch

        pipeline = _make_pipeline(dial=0)

        # Patch get_signal to return a known signal without touching DNS
        from src.security.models import RiskSignal
        no_ptr_signal = RiskSignal(name="no_ptr", score=15, reason="No PTR record")

        with patch.object(
            pipeline._dns_enrichment, "get_signal",
            new=AsyncMock(return_value=no_ptr_signal),
        ):
            result = _run(pipeline.process(_ctx()))

        signal_names = [s.name for s in result.signals]
        assert "no_ptr" in signal_names

    def test_cached_residential_signal_reduces_score(self):
        """A cached residential_ptr signal (score=-10) lowers total score."""
        from unittest.mock import AsyncMock, patch

        pipeline = _make_pipeline(dial=0)
        from src.security.models import RiskSignal
        res_signal = RiskSignal(name="residential_ptr", score=-10,
                                reason="Residential PTR")

        # Baseline: no DNS signal
        with patch.object(
            pipeline._dns_enrichment, "get_signal",
            new=AsyncMock(return_value=None),
        ):
            baseline = _run(pipeline.process(_ctx()))

        # With residential signal
        with patch.object(
            pipeline._dns_enrichment, "get_signal",
            new=AsyncMock(return_value=res_signal),
        ):
            result = _run(pipeline.process(_ctx()))

        # Residential signal must have reduced the score
        assert result.score < baseline.score

    def test_dns_cache_miss_fails_open(self):
        """DNS cache miss returns None → pipeline allows normally, no crash."""
        from unittest.mock import AsyncMock, patch

        pipeline = _make_pipeline(dial=0)

        with patch.object(
            pipeline._dns_enrichment, "get_signal",
            new=AsyncMock(return_value=None),
        ):
            result = _run(pipeline.process(_ctx()))

        # No DNS signal → clean connection allowed
        assert result.action == "allow"
        signal_names = [s.name for s in result.signals]
        assert "no_ptr" not in signal_names
        assert "fcrdns_failed" not in signal_names

    def test_dns_enrichment_exception_swallowed(self):
        """Exception in get_signal is caught; pipeline continues (fail open)."""
        from unittest.mock import AsyncMock, patch

        pipeline = _make_pipeline(dial=0)

        with patch.object(
            pipeline._dns_enrichment, "get_signal",
            new=AsyncMock(side_effect=Exception("DNS internal error")),
        ):
            result = _run(pipeline.process(_ctx()))

        # Pipeline must not propagate the exception
        assert result.action == "allow"
