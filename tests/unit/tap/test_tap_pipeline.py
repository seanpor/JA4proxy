"""
Unit tests for src/tap/tap_pipeline.py — Group 6 (Phase 20).

Tests cover:
- TapPipeline.process(): signal generation, scoring, Redis writes
- TapPipeline._fingerprints_to_signals(): per-signal conditions
- TapPipeline._score_to_tap_action(): score → action mapping
"""
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from src.tap.fingerprints.correlation import ConnectionFingerprints
from src.tap.fingerprints.tls_ext_values import JA4TLSExtValues
from src.tap.tap_pipeline import TapPipeline, _SCORE_ACTIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fp(**kwargs) -> ConnectionFingerprints:
    defaults = {
        "conn_id": str(uuid.uuid4()),
        "timestamp": datetime.now(tz=timezone.utc),
        "client_ip": "1.2.3.4",
        "server_ip": "5.6.7.8",
        "server_port": 443,
    }
    defaults.update(kwargs)
    return ConnectionFingerprints(**defaults)


def _make_assessment(total_score: int):
    """Return a mock RiskAssessment with the given total_score."""
    m = MagicMock()
    m.total_score = total_score
    return m


def _make_pipeline(scorer_score: int = 0, redis: MagicMock = None) -> TapPipeline:
    config = {"tap": {}, "tap_enforcement": {"ban_ttl_s": 3600}}
    scorer = MagicMock()
    scorer.score.return_value = _make_assessment(scorer_score)
    decider = MagicMock()
    redis = redis or MagicMock()
    return TapPipeline(config=config, scorer=scorer, decider=decider, redis=redis)


def _grease_tls_ext() -> JA4TLSExtValues:
    """TLS ext values with GREASE — typical browser."""
    return JA4TLSExtValues(
        supported_groups=[0x1D, 0x17],
        key_share_groups=[0x1D],
        sig_algs=[0x0403, 0x0804],
        psk_modes=[1],
        grease_values=[0x0A0A],
        has_compress_cert=False,
        has_alps=False,
        padding_len=None,
        session_ticket_len=0,
    )


def _no_grease_tls_ext() -> JA4TLSExtValues:
    """TLS ext values without GREASE — typical bot/scanner."""
    return JA4TLSExtValues(
        supported_groups=[0x1D, 0x17],
        key_share_groups=[0x1D],
        sig_algs=[0x0403],
        psk_modes=[],
        grease_values=[],
        has_compress_cert=False,
        has_alps=False,
        padding_len=None,
        session_ticket_len=0,
    )


# ---------------------------------------------------------------------------
# _score_to_tap_action
# ---------------------------------------------------------------------------

class TestScoreToTapAction:
    def setup_method(self):
        self.pipeline = _make_pipeline()

    def test_score_0_to_19_maps_to_observe(self):
        assert self.pipeline._score_to_tap_action(0) == "observe"
        assert self.pipeline._score_to_tap_action(10) == "observe"
        assert self.pipeline._score_to_tap_action(19) == "observe"

    def test_score_20_to_34_maps_to_flag(self):
        assert self.pipeline._score_to_tap_action(20) == "flag"
        assert self.pipeline._score_to_tap_action(34) == "flag"

    def test_score_35_to_54_maps_to_flag(self):
        # Both 35+ thresholds map to "flag"
        assert self.pipeline._score_to_tap_action(35) == "flag"
        assert self.pipeline._score_to_tap_action(54) == "flag"

    def test_score_55_to_69_maps_to_signal_slow(self):
        assert self.pipeline._score_to_tap_action(55) == "signal_slow"
        assert self.pipeline._score_to_tap_action(69) == "signal_slow"

    def test_score_70_to_84_maps_to_signal_block(self):
        assert self.pipeline._score_to_tap_action(70) == "signal_block"
        assert self.pipeline._score_to_tap_action(84) == "signal_block"

    def test_score_85_to_100_maps_to_signal_ban(self):
        assert self.pipeline._score_to_tap_action(85) == "signal_ban"
        assert self.pipeline._score_to_tap_action(100) == "signal_ban"


# ---------------------------------------------------------------------------
# _fingerprints_to_signals — individual signal conditions
# ---------------------------------------------------------------------------

class TestFingerprintsToSignals:
    def setup_method(self):
        self.pipeline = _make_pipeline()

    def test_no_grease_adds_10_to_score(self):
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_112233445566",
            tls_ext_values=_no_grease_tls_ext(),
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "tls_no_grease" in names
        sig = next(s for s in signals if s.name == "tls_no_grease")
        assert sig.score == 10

    def test_grease_present_no_signal(self):
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_112233445566",
            tls_ext_values=_grease_tls_ext(),
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "tls_no_grease" for s in signals)

    def test_scanner_ja4_adds_20_to_score(self):
        # Old TLS version prefix → scanner
        fp = _make_fp(ja4="t10d0100h0_aabbccddeeff_112233445566")
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "scanner_ja4" in names
        sig = next(s for s in signals if s.name == "scanner_ja4")
        assert sig.score == 20

    def test_t11_prefix_also_flagged_as_scanner(self):
        fp = _make_fp(ja4="t11d0100h0_aabbccddeeff_112233445566")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert any(s.name == "scanner_ja4" for s in signals)

    def test_modern_ja4_not_flagged_as_scanner(self):
        fp = _make_fp(ja4="t13d1516h2_aabbccddeeff_112233445566")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "scanner_ja4" for s in signals)

    def test_ja4l_mismatch_adds_20_to_score(self):
        # client_km > 15000 = impossibly far
        fp = _make_fp(ja4l="ja4l_16000_64")
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "ja4l_distance_mismatch" in names
        sig = next(s for s in signals if s.name == "ja4l_distance_mismatch")
        assert sig.score == 20

    def test_ja4l_reasonable_distance_no_signal(self):
        fp = _make_fp(ja4l="ja4l_5000_64")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "ja4l_distance_mismatch" for s in signals)

    def test_expired_cert_adds_15_to_score(self):
        fp = _make_fp(cert_is_expired=True, ja4x="aabb_ccdd_eeff")
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "cert_expired" in names
        sig = next(s for s in signals if s.name == "cert_expired")
        assert sig.score == 15

    def test_non_expired_cert_no_signal(self):
        fp = _make_fp(cert_is_expired=False, ja4x="aabb_ccdd_eeff")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "cert_expired" for s in signals)

    def test_h2_settings_mismatch_adds_15_to_score(self):
        # H2 fingerprint present but no matched client → unrecognized H2 client
        fp = _make_fp(h2_fingerprint="abc123def456", h2_matched_client=None)
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "h2_settings_mismatch" in names
        sig = next(s for s in signals if s.name == "h2_settings_mismatch")
        assert sig.score == 15

    def test_h2_with_known_client_no_mismatch_signal(self):
        fp = _make_fp(h2_fingerprint="abc123def456", h2_matched_client="chrome_120")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "h2_settings_mismatch" for s in signals)

    def test_os_ua_mismatch_adds_15_to_score(self):
        # Safari on Linux OS = contradiction (Safari only runs on Apple hardware)
        fp = _make_fp(
            os_fingerprint="linux_5x_default",
            h2_matched_client="safari_17",
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "os_ua_mismatch" in names
        sig = next(s for s in signals if s.name == "os_ua_mismatch")
        assert sig.score == 15

    def test_os_ua_mismatch_safari_on_windows_also_flagged(self):
        fp = _make_fp(
            os_fingerprint="windows_10_default",
            h2_matched_client="safari_17",
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert any(s.name == "os_ua_mismatch" for s in signals)

    def test_chrome_on_linux_no_mismatch(self):
        fp = _make_fp(
            os_fingerprint="linux_5x_default",
            h2_matched_client="chrome_120",
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "os_ua_mismatch" for s in signals)

    def test_ssh_attack_tool_adds_25_to_score(self):
        fp = _make_fp(ja4ssh="ja4ssh_c0202_diffie-hellman-group1-sha1_aes_sha1")
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "ssh_attack_tool" in names
        sig = next(s for s in signals if s.name == "ssh_attack_tool")
        assert sig.score == 25

    def test_modern_ssh_kex_no_signal(self):
        fp = _make_fp(ja4ssh="ja4ssh_c0202_curve25519-sha256_aes256-gcm_none")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "ssh_attack_tool" for s in signals)

    def test_chrome_fingerprints_produce_low_score(self):
        """Browser-like fingerprint: GREASE present, modern TLS, no alerts."""
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_112233445566",
            tls_ext_values=_grease_tls_ext(),
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        total = sum(s.score for s in signals)
        assert total < 20, f"Chrome-like FP should score < 20, got {total}"

    def test_nmap_fingerprints_produce_high_score(self):
        """Scanner-like fingerprint: old TLS + no GREASE."""
        fp = _make_fp(
            ja4="t10d0100h0_aabbccddeeff_112233445566",
            tls_ext_values=_no_grease_tls_ext(),
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        total = sum(s.score for s in signals)
        assert total >= 20, f"Nmap-like FP should score ≥ 20, got {total}"


# ---------------------------------------------------------------------------
# TapPipeline.process() — Redis interaction
# ---------------------------------------------------------------------------

class TestTapPipelineProcess:
    def _make_redis_mock(self) -> MagicMock:
        """Mock Redis where all sync calls succeed."""
        m = MagicMock()
        m.hset.return_value = 1
        m.expire.return_value = True
        m.zadd.return_value = 1
        m.zremrangebyrank.return_value = 0
        m.pfadd.return_value = 1
        m.incr.return_value = 1
        m.set.return_value = True
        return m

    @pytest.mark.asyncio
    async def test_signal_ban_writes_ban_redis_key(self):
        redis = self._make_redis_mock()
        pipeline = _make_pipeline(scorer_score=90, redis=redis)
        fp = _make_fp(client_ip="10.0.0.1")
        await pipeline.process(fp)
        # ban:{ip} must have been set
        set_calls = [str(c) for c in redis.set.call_args_list]
        assert any("ban:10.0.0.1" in c for c in set_calls)

    @pytest.mark.asyncio
    async def test_signal_block_writes_block_decision_redis_key(self):
        redis = self._make_redis_mock()
        pipeline = _make_pipeline(scorer_score=75, redis=redis)
        fp = _make_fp(client_ip="10.0.0.2")
        await pipeline.process(fp)
        set_calls = [str(c) for c in redis.set.call_args_list]
        assert any("block_decisions:block:10.0.0.2" in c for c in set_calls)

    @pytest.mark.asyncio
    async def test_observe_action_writes_no_ban_key(self):
        redis = self._make_redis_mock()
        pipeline = _make_pipeline(scorer_score=5, redis=redis)
        fp = _make_fp(client_ip="10.0.0.3")
        await pipeline.process(fp)
        # No ban: or block_decisions: keys written
        set_calls = [str(c) for c in redis.set.call_args_list]
        assert not any("ban:" in c for c in set_calls)
        assert not any("block_decisions:" in c for c in set_calls)

    @pytest.mark.asyncio
    async def test_process_sets_risk_score_on_fp(self):
        pipeline = _make_pipeline(scorer_score=42)
        fp = _make_fp()
        await pipeline.process(fp)
        assert fp.risk_score == 42

    @pytest.mark.asyncio
    async def test_process_sets_action_on_fp(self):
        pipeline = _make_pipeline(scorer_score=85)
        fp = _make_fp()
        await pipeline.process(fp)
        assert fp.action == "signal_ban"

    @pytest.mark.asyncio
    async def test_process_populates_signals_list_on_fp(self):
        pipeline = _make_pipeline(scorer_score=10)
        fp = _make_fp(
            ja4="t10d0100h0_aabbccddeeff_112233445566",  # scanner → signal
        )
        await pipeline.process(fp)
        assert len(fp.signals) >= 1
        assert all("name" in s for s in fp.signals)
        assert all("score" in s for s in fp.signals)

    @pytest.mark.asyncio
    async def test_redis_error_does_not_propagate(self):
        """Redis failures must be swallowed; process() must return cleanly."""
        redis = MagicMock()
        redis.hset.side_effect = ConnectionError("Redis down")
        pipeline = _make_pipeline(scorer_score=0, redis=redis)
        fp = _make_fp()
        # Must not raise
        await pipeline.process(fp)

    @pytest.mark.asyncio
    async def test_fp_conn_key_written_to_redis(self):
        redis = self._make_redis_mock()
        pipeline = _make_pipeline(scorer_score=0, redis=redis)
        fp = _make_fp()
        await pipeline.process(fp)
        # hset called with fp:conn:{conn_id}
        hset_calls = [str(c) for c in redis.hset.call_args_list]
        assert any(f"fp:conn:{fp.conn_id}" in c for c in hset_calls)

    @pytest.mark.asyncio
    async def test_signal_slow_does_not_write_ban_or_block(self):
        redis = self._make_redis_mock()
        pipeline = _make_pipeline(scorer_score=60, redis=redis)  # → signal_slow
        fp = _make_fp(client_ip="10.0.0.5")
        await pipeline.process(fp)
        set_calls = [str(c) for c in redis.set.call_args_list]
        assert not any("ban:" in c for c in set_calls)
        assert not any("block_decisions:" in c for c in set_calls)
