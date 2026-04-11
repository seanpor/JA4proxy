"""
Unit tests for src/tap/tap_pipeline.py — Group 6 (Phase 20).

Tests cover:
- TapPipeline.process(): signal generation, scoring, Redis writes
- TapPipeline._fingerprints_to_signals(): per-signal conditions
- TapPipeline._score_to_tap_action(): score → action mapping
"""
import asyncio
import struct
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from src.tap.fingerprints.correlation import ConnectionFingerprints
from src.tap.fingerprints.tls_ext_values import JA4TLSExtValues
from src.tap.tap_pipeline import (
    _SCORE_ACTIONS,
    FingerprintExtractor,
    TapPipeline,
    _find_ssh_kexinit,
)

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

    def test_score_negative_falls_through_to_observe(self):
        """Line 398: score below 0 falls through all thresholds and hits the final
        'return observe' guard.
        So what: if this fallback is absent, any scorer that emits a negative
        score (e.g. after a bug in signal weighting) would raise UnboundLocalError
        inside _score_to_tap_action and drop the entire fingerprint from the tap
        pipeline, silently discarding connection metadata."""
        assert self.pipeline._score_to_tap_action(-1) == "observe"


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


# ---------------------------------------------------------------------------
# TapPipeline with no Redis (store=None path)
# ---------------------------------------------------------------------------


class TestTapPipelineNoRedis:
    @pytest.mark.asyncio
    async def test_process_works_without_redis(self):
        """process() must complete cleanly when redis=None."""
        config = {"tap": {}, "tap_enforcement": {"ban_ttl_s": 3600}}
        scorer = MagicMock()
        scorer.score.return_value = MagicMock(total_score=90)
        pipeline = TapPipeline(
            config=config,
            scorer=scorer,
            decider=MagicMock(),
            redis=None,
        )
        fp = _make_fp(client_ip="10.10.10.10")
        # Must not raise even with signal_ban action and no redis
        await pipeline.process(fp)
        assert fp.risk_score == 90
        assert fp.action == "signal_ban"

    @pytest.mark.asyncio
    async def test_write_ban_skips_when_redis_none(self):
        """_write_ban must be a no-op when redis is None."""
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=None
        )
        # Must not raise
        await pipeline._write_ban("1.2.3.4", 3600, "test")

    @pytest.mark.asyncio
    async def test_write_block_decision_skips_when_redis_none(self):
        """_write_block_decision must be a no-op when redis is None."""
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=None
        )
        # Must not raise
        await pipeline._write_block_decision("1.2.3.4", "test-conn")


# ---------------------------------------------------------------------------
# TapPipeline._write_to_redis — direct Redis write path
# ---------------------------------------------------------------------------


class TestWriteToRedis:
    def _make_redis_mock(self) -> MagicMock:
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
    async def test_write_to_redis_writes_conn_and_ip_keys(self):
        redis = self._make_redis_mock()
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        fp = _make_fp(conn_id="abc-123", client_ip="7.8.9.10")
        await pipeline._write_to_redis(fp)
        hset_calls = [str(c) for c in redis.hset.call_args_list]
        assert any("fp:conn:abc-123" in c for c in hset_calls)
        zadd_calls = [str(c) for c in redis.zadd.call_args_list]
        assert any("fp:ip:7.8.9.10" in c for c in zadd_calls)

    @pytest.mark.asyncio
    async def test_write_to_redis_writes_ja4_hll_when_ja4_present(self):
        redis = self._make_redis_mock()
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        fp = _make_fp(ja4="t13d1516h2_aabbccdd_eeff1122")
        await pipeline._write_to_redis(fp)
        pfadd_calls = [str(c) for c in redis.pfadd.call_args_list]
        assert any("fp:ja4:hll:" in c for c in pfadd_calls)
        incr_calls = [str(c) for c in redis.incr.call_args_list]
        assert any("fp:ja4:count:" in c for c in incr_calls)

    @pytest.mark.asyncio
    async def test_write_to_redis_skips_ja4_hll_when_no_ja4(self):
        redis = self._make_redis_mock()
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        fp = _make_fp()  # ja4=None by default
        await pipeline._write_to_redis(fp)
        assert not redis.pfadd.called

    @pytest.mark.asyncio
    async def test_write_to_redis_skips_when_redis_none(self):
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=None
        )
        fp = _make_fp()
        # Must not raise
        await pipeline._write_to_redis(fp)

    @pytest.mark.asyncio
    async def test_write_to_redis_exception_is_swallowed(self):
        redis = MagicMock()
        redis.hset.side_effect = RuntimeError("redis gone")
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        fp = _make_fp()
        # Must not raise
        await pipeline._write_to_redis(fp)

    @pytest.mark.asyncio
    async def test_write_ban_logs_and_writes_key(self):
        redis = MagicMock()
        redis.set.return_value = True
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        await pipeline._write_ban("192.168.1.100", 3600, "conn-abc")
        set_calls = [str(c) for c in redis.set.call_args_list]
        assert any("ban:192.168.1.100" in c for c in set_calls)

    @pytest.mark.asyncio
    async def test_write_ban_redis_error_is_swallowed(self):
        redis = MagicMock()
        redis.set.side_effect = ConnectionError("lost")
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        # Must not raise
        await pipeline._write_ban("1.1.1.1", 60, "x")

    @pytest.mark.asyncio
    async def test_write_block_decision_writes_key(self):
        redis = MagicMock()
        redis.set.return_value = True
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        await pipeline._write_block_decision("10.0.0.55", "conn-xyz")
        set_calls = [str(c) for c in redis.set.call_args_list]
        assert any("block_decisions:block:10.0.0.55" in c for c in set_calls)

    @pytest.mark.asyncio
    async def test_write_block_decision_redis_error_is_swallowed(self):
        redis = MagicMock()
        redis.set.side_effect = ConnectionError("lost")
        config = {"tap": {}, "tap_enforcement": {}}
        pipeline = TapPipeline(
            config=config, scorer=MagicMock(), decider=MagicMock(), redis=redis
        )
        # Must not raise
        await pipeline._write_block_decision("2.2.2.2", "y")


# ---------------------------------------------------------------------------
# TapPipeline.process() — exception path
# ---------------------------------------------------------------------------


class TestTapPipelineProcessException:
    @pytest.mark.asyncio
    async def test_scorer_exception_is_swallowed(self):
        """If scorer.score() raises, process() must swallow and return."""
        config = {"tap": {}, "tap_enforcement": {}}
        scorer = MagicMock()
        scorer.score.side_effect = RuntimeError("scorer broke")
        pipeline = TapPipeline(
            config=config,
            scorer=scorer,
            decider=MagicMock(),
            redis=MagicMock(),
        )
        fp = _make_fp()
        # Must not raise
        await pipeline.process(fp)


# ---------------------------------------------------------------------------
# FingerprintExtractor — initialization and on_stream_data
# ---------------------------------------------------------------------------


def _make_stream(
    fingerprints=None,
    client_data=b"",
    server_data=b"",
    server_port=443,
    syn_tcp_opts=None,
    syn_ts=None,
    synack_ts=None,
    ack_ts=None,
    conn_id="test-conn",
    client_ip="1.2.3.4",
    server_ip="5.6.7.8",
):
    """Build a minimal mock TCPStream."""
    stream = MagicMock()
    stream.fingerprints = fingerprints
    stream.client_data = client_data
    stream.server_data = server_data
    stream.server_port = server_port
    stream.syn_tcp_opts = syn_tcp_opts
    stream.syn_ts = syn_ts
    stream.synack_ts = synack_ts
    stream.ack_ts = ack_ts
    stream.conn_id = conn_id
    stream.client_ip = client_ip
    stream.server_ip = server_ip
    return stream


class TestFingerprintExtractorInit:
    def test_default_tls_ports_include_443(self):
        ext = FingerprintExtractor(config={})
        assert 443 in ext._tls_ports

    def test_custom_tls_ports_from_config(self):
        ext = FingerprintExtractor(config={"tap": {"tls_ports": [8443, 9443]}})
        assert 8443 in ext._tls_ports
        assert 9443 in ext._tls_ports
        assert 443 not in ext._tls_ports

    def test_default_ssh_ports_include_22(self):
        ext = FingerprintExtractor(config={})
        assert 22 in ext._ssh_ports

    def test_custom_ssh_ports_from_config(self):
        ext = FingerprintExtractor(config={"tap": {"ssh_ports": [2222, 2200]}})
        assert 2222 in ext._ssh_ports

    def test_os_database_defaults_to_empty(self):
        ext = FingerprintExtractor(config={})
        assert ext._os_db == []

    def test_os_database_passed_through(self):
        db = [MagicMock()]
        ext = FingerprintExtractor(config={}, os_database=db)
        assert ext._os_db is db

    def test_h2_database_defaults_to_empty(self):
        ext = FingerprintExtractor(config={})
        assert ext._h2_db == []


class TestFingerprintExtractorOnStreamData:
    def test_initialises_fingerprints_dict_when_none(self):
        ext = FingerprintExtractor(config={})
        stream = _make_stream(fingerprints=None)
        ext.on_stream_data(stream)
        assert stream.fingerprints == {}

    def test_preserves_existing_fingerprints_dict(self):
        ext = FingerprintExtractor(config={})
        existing = {"ja4": "already_set"}
        stream = _make_stream(fingerprints=existing)
        ext.on_stream_data(stream)
        assert stream.fingerprints["ja4"] == "already_set"

    def test_does_not_overwrite_existing_ja4(self):
        """If ja4 already in fp, extractor must not overwrite it."""
        ext = FingerprintExtractor(config={})
        stream = _make_stream(
            fingerprints={"ja4": "existing_ja4"},
            server_port=443,
            client_data=b"\x16\x03\x01" + b"\x00" * 100,
        )
        ext.on_stream_data(stream)
        assert stream.fingerprints["ja4"] == "existing_ja4"

    def test_non_tls_port_skips_ja4_extraction(self):
        """Port 9999 is not in default TLS ports — ja4 must not be set."""
        ext = FingerprintExtractor(config={})
        stream = _make_stream(
            fingerprints={},
            server_port=9999,
            client_data=b"\x16\x03\x01" + b"\x00" * 100,
        )
        with patch("src.tap.tap_pipeline.extract_ja4", return_value=None) as mock_ja4:
            ext.on_stream_data(stream)
            mock_ja4.assert_not_called()

    def test_ja4_extracted_when_result_available(self):
        ext = FingerprintExtractor(config={})
        mock_result = MagicMock()
        mock_result.fingerprint = "t13d1516h2_aabb_ccdd"
        stream = _make_stream(
            fingerprints={},
            server_port=443,
            client_data=b"\x16\x03\x03" + b"\x00" * 100,
        )
        with patch("src.tap.tap_pipeline.extract_ja4", return_value=mock_result):
            ext.on_stream_data(stream)
        assert stream.fingerprints.get("ja4") == "t13d1516h2_aabb_ccdd"
        assert stream.fingerprints.get("_ja4_result") is mock_result

    def test_ja4s_extracted_from_server_data(self):
        ext = FingerprintExtractor(config={})
        mock_result = MagicMock()
        mock_result.fingerprint = "s13d_aabb_ccdd"
        stream = _make_stream(
            fingerprints={},
            server_port=443,
            server_data=b"\x16\x03\x03" + b"\x00" * 100,
        )
        with patch("src.tap.tap_pipeline.extract_ja4s", return_value=mock_result):
            ext.on_stream_data(stream)
        assert stream.fingerprints.get("ja4s") == "s13d_aabb_ccdd"

    def test_ja4h_extracted_for_http_port(self):
        ext = FingerprintExtractor(config={})
        mock_result = MagicMock()
        mock_result.fingerprint = "ge11cn020000_aabb_ccdd"
        stream = _make_stream(
            fingerprints={},
            server_port=80,
            client_data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        with patch("src.tap.tap_pipeline.extract_ja4h", return_value=mock_result):
            ext.on_stream_data(stream)
        assert stream.fingerprints.get("ja4h") == "ge11cn020000_aabb_ccdd"

    def test_h2_fingerprint_extracted_when_available(self):
        ext = FingerprintExtractor(config={})
        mock_result = MagicMock()
        mock_result.fingerprint = "h2fp_aabbccdd"
        mock_result.matched_client = "chrome_120"
        stream = _make_stream(
            fingerprints={},
            client_data=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00" * 20,
        )
        with patch("src.tap.tap_pipeline.extract_h2_fingerprint", return_value=mock_result):
            ext.on_stream_data(stream)
        assert stream.fingerprints.get("h2_fingerprint") == "h2fp_aabbccdd"
        assert stream.fingerprints.get("_h2_matched_client") == "chrome_120"

    def test_h2_fingerprint_no_matched_client_not_stored(self):
        """If matched_client is None, _h2_matched_client key must not be set."""
        ext = FingerprintExtractor(config={})
        mock_result = MagicMock()
        mock_result.fingerprint = "h2fp_unknown"
        mock_result.matched_client = None
        stream = _make_stream(
            fingerprints={},
            client_data=b"PRI * HTTP/2.0" + b"\x00" * 20,
        )
        with patch("src.tap.tap_pipeline.extract_h2_fingerprint", return_value=mock_result):
            ext.on_stream_data(stream)
        assert "_h2_matched_client" not in stream.fingerprints

    def test_ja4ssh_extracted_when_kexinit_found(self):
        ext = FingerprintExtractor(config={})
        mock_result = MagicMock()
        mock_result.fingerprint = "ja4ssh_abc"
        # Craft SSH packet: banner + a valid kexinit packet
        # pkt_len=8, pad=1: wire=12 bytes, payload_len=6; [5]=0x14 (KEXINIT)
        kexinit_pkt = struct.pack("!IB", 8, 1) + b"\x14" + b"\x00" * 5 + b"\x00" * 1
        ssh_data = b"SSH-2.0-OpenSSH_8.9\n" + kexinit_pkt
        stream = _make_stream(
            fingerprints={},
            server_port=22,
            client_data=ssh_data,
        )
        with patch("src.tap.tap_pipeline.extract_ja4ssh", return_value=mock_result):
            ext.on_stream_data(stream)
        assert stream.fingerprints.get("ja4ssh") == "ja4ssh_abc"


class TestFingerprintExtractorOnStreamClose:
    def test_returns_connection_fingerprints_object(self):
        ext = FingerprintExtractor(config={})
        stream = _make_stream()
        result = ext.on_stream_close(stream)
        assert hasattr(result, "conn_id")
        assert result.conn_id == "test-conn"

    def test_ja4t_extracted_from_syn_tcp_opts(self):
        ext = FingerprintExtractor(config={})
        # syn_tcp_opts: MSS option (kind=2, len=4, val=1460)
        syn_opts = struct.pack("!BBH", 2, 4, 1460) + b"\x01\x03\x03\x08"
        stream = _make_stream(syn_tcp_opts=syn_opts)
        mock_result = MagicMock()
        mock_result.fingerprint = "ja4t_65535_1460_0_0"
        with patch("src.tap.tap_pipeline.extract_ja4t_from_syn", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert result.ja4t == "ja4t_65535_1460_0_0"

    def test_no_ja4t_when_syn_tcp_opts_is_none(self):
        ext = FingerprintExtractor(config={})
        stream = _make_stream(syn_tcp_opts=None)
        result = ext.on_stream_close(stream)
        assert result.ja4t is None

    def test_ja4l_extracted_from_timestamps(self):
        ext = FingerprintExtractor(config={})
        stream = _make_stream(
            syn_ts=1000.0,
            synack_ts=1000.1,
            ack_ts=1000.2,
        )
        mock_result = MagicMock()
        mock_result.fingerprint = "ja4l_1000_100"
        with patch("src.tap.tap_pipeline.extract_ja4l", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert result.ja4l == "ja4l_1000_100"

    def test_no_ja4l_when_timestamps_missing(self):
        ext = FingerprintExtractor(config={})
        # Only syn_ts set, synack_ts and ack_ts are None
        stream = _make_stream(syn_ts=1000.0, synack_ts=None, ack_ts=None)
        result = ext.on_stream_close(stream)
        assert result.ja4l is None

    def test_ja4x_extracted_from_server_tls_data(self):
        ext = FingerprintExtractor(config={})
        stream = _make_stream(
            server_port=443,
            server_data=b"\x16\x03\x01" + b"\x00" * 200,
        )
        mock_result = MagicMock()
        mock_result.fingerprint = "ja4x_abc123"
        mock_result.self_signed = False
        mock_result.not_after = None
        with patch("src.tap.tap_pipeline.extract_ja4x", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert result.ja4x == "ja4x_abc123"
        assert not result.cert_is_self_signed

    def test_cert_is_self_signed_flag_set(self):
        ext = FingerprintExtractor(config={})
        stream = _make_stream(
            server_port=443,
            server_data=b"\x16\x03\x01" + b"\x00" * 200,
        )
        mock_result = MagicMock()
        mock_result.fingerprint = "ja4x_self"
        mock_result.self_signed = True
        mock_result.not_after = None
        with patch("src.tap.tap_pipeline.extract_ja4x", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert result.cert_is_self_signed

    def test_cert_expired_flag_set_when_not_after_in_past(self):
        from datetime import datetime, timedelta, timezone

        ext = FingerprintExtractor(config={})
        stream = _make_stream(
            server_port=443,
            server_data=b"\x16\x03\x01" + b"\x00" * 200,
        )
        mock_result = MagicMock()
        mock_result.fingerprint = "ja4x_expired"
        mock_result.self_signed = False
        mock_result.not_after = datetime(2020, 1, 1, tzinfo=timezone.utc)
        with patch("src.tap.tap_pipeline.extract_ja4x", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert result.cert_is_expired

    def test_cert_not_expired_when_not_after_in_future(self):
        from datetime import datetime, timedelta, timezone

        ext = FingerprintExtractor(config={})
        stream = _make_stream(
            server_port=443,
            server_data=b"\x16\x03\x01" + b"\x00" * 200,
        )
        mock_result = MagicMock()
        mock_result.fingerprint = "ja4x_valid"
        mock_result.self_signed = False
        mock_result.not_after = datetime(2099, 1, 1, tzinfo=timezone.utc)
        with patch("src.tap.tap_pipeline.extract_ja4x", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert not result.cert_is_expired

    def test_os_fingerprint_extracted_when_db_and_syn_opts_available(self):
        from src.tap.fingerprints.os_fingerprint import OSFingerprintResult

        ext = FingerprintExtractor(config={}, os_database=[MagicMock()])
        syn_opts = struct.pack("!BBH", 2, 4, 1460) + b"\x01\x03\x03\x08"
        stream = _make_stream(syn_tcp_opts=syn_opts)
        mock_result = MagicMock()
        mock_result.confidence = 0.9
        mock_result.fingerprint_id = "linux_5x"
        with patch("src.tap.tap_pipeline.match_os", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert result.os_fingerprint == "linux_5x"

    def test_os_fingerprint_none_when_confidence_low(self):
        ext = FingerprintExtractor(config={}, os_database=[MagicMock()])
        syn_opts = b"\x00\x00"
        stream = _make_stream(syn_tcp_opts=syn_opts)
        mock_result = MagicMock()
        mock_result.confidence = 0.1  # below 0.3 threshold
        mock_result.fingerprint_id = "unknown"
        with patch("src.tap.tap_pipeline.match_os", return_value=mock_result):
            result = ext.on_stream_close(stream)
        assert result.os_fingerprint is None

    def test_tls_ext_values_populated_from_ja4_result(self):
        ext = FingerprintExtractor(config={})
        mock_ja4_result = MagicMock()
        mock_tls_ext = MagicMock()
        stream = _make_stream(
            fingerprints={"_ja4_result": mock_ja4_result},
        )
        with patch("src.tap.tap_pipeline.extract_tls_ext_values", return_value=mock_tls_ext):
            result = ext.on_stream_close(stream)
        assert result.tls_ext_values is mock_tls_ext

    def test_tls_ext_values_none_when_no_ja4_result(self):
        ext = FingerprintExtractor(config={})
        stream = _make_stream(fingerprints={})
        result = ext.on_stream_close(stream)
        assert result.tls_ext_values is None


# ---------------------------------------------------------------------------
# _fingerprints_to_signals — edge cases
# ---------------------------------------------------------------------------


class TestFingerprintsToSignalsEdgeCases:
    def setup_method(self):
        self.pipeline = _make_pipeline()

    def test_self_signed_cert_adds_5_to_score(self):
        fp = _make_fp(cert_is_self_signed=True)
        signals = self.pipeline._fingerprints_to_signals(fp)
        names = [s.name for s in signals]
        assert "cert_self_signed" in names
        sig = next(s for s in signals if s.name == "cert_self_signed")
        assert sig.score == 5

    def test_non_self_signed_cert_no_signal(self):
        fp = _make_fp(cert_is_self_signed=False)
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "cert_self_signed" for s in signals)

    def test_t00_prefix_flagged_as_scanner(self):
        fp = _make_fp(ja4="t00d0000h0_aabbccddeeff_112233445566")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert any(s.name == "scanner_ja4" for s in signals)

    def test_ja4l_missing_underscore_does_not_signal(self):
        """ja4l without underscore separator must not raise or emit signal."""
        fp = _make_fp(ja4l="nounderscore")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "ja4l_distance_mismatch" for s in signals)

    def test_ja4l_non_numeric_part_does_not_signal(self):
        """ja4l with non-numeric part after underscore must not raise."""
        fp = _make_fp(ja4l="ja4l_notanumber_extra")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "ja4l_distance_mismatch" for s in signals)

    def test_ja4l_exactly_at_threshold_15000_no_signal(self):
        fp = _make_fp(ja4l="ja4l_15000_64")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "ja4l_distance_mismatch" for s in signals)

    def test_ja4l_one_over_threshold_emits_signal(self):
        fp = _make_fp(ja4l="ja4l_15001_64")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert any(s.name == "ja4l_distance_mismatch" for s in signals)

    def test_tls_ext_values_none_does_not_emit_grease_signal(self):
        """When tls_ext_values is None, tls_no_grease must not be emitted."""
        fp = _make_fp(
            ja4="t13d1516h2_aabbccddeeff_112233445566",
            tls_ext_values=None,
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "tls_no_grease" for s in signals)

    def test_safari_on_apple_no_mismatch(self):
        fp = _make_fp(
            os_fingerprint="macos_13_default",
            h2_matched_client="safari_17",
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "os_ua_mismatch" for s in signals)

    def test_ios_safari_no_mismatch(self):
        fp = _make_fp(
            os_fingerprint="ios_17_default",
            h2_matched_client="safari_mobile",
        )
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert not any(s.name == "os_ua_mismatch" for s in signals)

    def test_ecdh_attack_kex_adds_ssh_signal(self):
        fp = _make_fp(ja4ssh="ssh_ecdh-sha2-1.3.132.0.10_someclient")
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert any(s.name == "ssh_attack_tool" for s in signals)

    def test_no_signals_for_clean_fp(self):
        """Fingerprint with nothing suspicious produces no signals."""
        fp = _make_fp()
        signals = self.pipeline._fingerprints_to_signals(fp)
        assert signals == []


# ---------------------------------------------------------------------------
# _find_ssh_kexinit
# ---------------------------------------------------------------------------


class TestFindSshKexinit:
    def test_returns_none_for_short_data(self):
        assert _find_ssh_kexinit(b"\x00" * 5) is None

    def test_returns_none_when_no_banner_newline(self):
        assert _find_ssh_kexinit(b"SSH-2.0-no-newline-here") is None

    def test_finds_kexinit_without_banner(self):
        # pkt_len=8, pad=1: wire=12 bytes, payload_len=6
        # [0:4]=pkt_len, [4]=padding_len, [5]=0x14(KEXINIT), [6:11]=payload, [11]=padding
        pkt = struct.pack("!IB", 8, 1) + b"\x14" + b"\x00" * 5 + b"\x00" * 1
        offset = _find_ssh_kexinit(pkt)
        assert offset is not None
        assert pkt[offset] == 0x14

    def test_finds_kexinit_after_banner(self):
        # Same packet structure after SSH banner
        pkt = struct.pack("!IB", 8, 1) + b"\x14" + b"\x00" * 5 + b"\x00" * 1
        data = b"SSH-2.0-OpenSSH_8.9\n" + pkt
        offset = _find_ssh_kexinit(data)
        assert offset is not None
        assert data[offset] == 0x14

    def test_returns_none_when_pkt_len_zero(self):
        # pkt_len=0 → invalid (< 2)
        pkt = struct.pack("!IB", 0, 0) + b"\x14" + b"\x00" * 5
        assert _find_ssh_kexinit(pkt) is None

    def test_returns_none_when_pkt_len_too_large(self):
        # pkt_len=40000 → exceeds 35000 limit
        pkt = struct.pack("!IB", 40000, 1) + b"\x14" + b"\x00" * 10
        assert _find_ssh_kexinit(pkt) is None

    def test_returns_none_when_truncated_payload(self):
        # payload_start + payload_len > len(data)
        pkt = struct.pack("!IB", 100, 1) + b"\x14" + b"\x00" * 5
        assert _find_ssh_kexinit(pkt) is None

    def test_returns_none_when_first_byte_not_kexinit(self):
        # Packet with valid length but msg type is 0x05, not 0x14
        pkt = struct.pack("!IB", 5, 1) + b"\x05" + b"\x00" * 3
        assert _find_ssh_kexinit(pkt) is None

    def test_advances_past_non_kexinit_packet_then_finds_next(self):
        """Two consecutive packets — first is not KEXINIT, second is.

        SSH wire format: [uint32 pkt_len][uint8 padding_len][payload...][padding...]
        Total wire length of each packet = 4 + pkt_len.
        With pkt_len=8, padding=1: wire length=12, payload_len=6 bytes.
        """
        # First packet: pkt_len=8, pad=1, msg=0x05 (not KEXINIT), 5 more bytes, 1 pad
        pkt1 = struct.pack("!IB", 8, 1) + b"\x05" + b"\x00" * 5 + b"\x00" * 1
        # Second packet: pkt_len=8, pad=1, msg=0x14 (KEXINIT), 5 more bytes, 1 pad
        pkt2 = struct.pack("!IB", 8, 1) + b"\x14" + b"\x00" * 5 + b"\x00" * 1
        data = pkt1 + pkt2
        # pkt1 wire length = 4 + 8 = 12 bytes; pkt2 starts at byte 12
        assert len(pkt1) == 12
        offset = _find_ssh_kexinit(data)
        assert offset is not None
        assert data[offset] == 0x14

    def test_returns_none_when_no_kexinit_found_after_loop(self):
        """Multiple non-KEXINIT packets — function returns None after exhausting data."""
        # pkt_len=8, pad=1: wire length=12, payload_len=6
        pkt = struct.pack("!IB", 8, 1) + b"\x05" + b"\x00" * 5 + b"\x00" * 1
        # Two such packets — neither is KEXINIT; loop exhausts and returns None
        data = pkt + pkt
        assert _find_ssh_kexinit(data) is None
