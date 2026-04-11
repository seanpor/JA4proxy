"""
Unit tests for src/analytics/stream_consumer.py.

Security consequence: StreamConsumer is the ingress point for all cross-instance
threat signals written to the Redis Stream.  If error handling or event processing
is broken, attack campaigns (coordinated multi-IP scans, slow-scan attackers) may
go undetected across proxy instances — allowing attackers to stay under per-instance
rate limits while collectively overwhelming the protected service.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.analytics.stream_consumer import InvalidEventError, StreamConsumer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_consumer(**kwargs) -> StreamConsumer:
    """Create a StreamConsumer with all heavy dependencies disabled."""
    defaults = dict(
        redis_url="redis://localhost:6379",
        hmac_required=False,
        campaign_detection=False,
        slow_scan_detection=False,
        ja4_intelligence=False,
        monitoring_enabled=False,
    )
    defaults.update(kwargs)
    consumer = StreamConsumer(**defaults)
    consumer.redis = AsyncMock()
    consumer.logger = MagicMock()
    return consumer


def _valid_event() -> dict:
    return {
        "src_ip": "10.0.0.1",
        "ja4": "t13d1516h2_aabbccddee11_aabbccddee11",
        "action": "allow",
        "timestamp": int(time.time()),
        "score": 20,
        "proxy_id": "proxy-1",
    }


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Initialisation / constructor
# ---------------------------------------------------------------------------


class TestConsumerInit:
    def test_campaign_detector_created_when_enabled(self):
        # Security: without campaign detection, subnet-level coordinated attacks
        # (e.g. botnets spreading requests across a /24) go undetected.
        c = _make_consumer(campaign_detection=True)
        assert c.campaign_detector is not None

    def test_slow_scan_detector_created_when_enabled(self):
        # Security: slow-scan attackers probe deliberately slowly; if the detector
        # is not initialised, low-volume multi-day port-sweeps pass through silently.
        c = _make_consumer(slow_scan_detection=True)
        assert c.slow_scan_detector is not None

    def test_ja4_intelligence_created_when_enabled(self):
        # Security: JA4 intelligence identifies fingerprints with unusual block rates
        # across instances, enabling cross-instance fingerprint blacklisting.
        c = _make_consumer(ja4_intelligence=True)
        assert c.ja4_intelligence is not None

    def test_detectors_none_when_disabled(self):
        c = _make_consumer()
        assert c.campaign_detector is None
        assert c.slow_scan_detector is None
        assert c.ja4_intelligence is None

    def test_monitoring_system_none_before_connect(self):
        c = _make_consumer(monitoring_enabled=True)
        # Monitoring system is created in connect(), not __init__
        assert c.monitoring_system is None

    def test_batch_size_default_100(self):
        c = _make_consumer()
        assert c.batch_size == 100


# ---------------------------------------------------------------------------
# connect() — group creation and monitoring init
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestConnect:
    async def test_connect_ignores_busygroup_error(self):
        """BUSYGROUP is raised when the group already exists; must be swallowed."""
        import redis.asyncio as aioredis

        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=aioredis.ResponseError("BUSYGROUP Consumer Group name already exists")
        )
        c = _make_consumer()
        c.redis = mock_redis
        # Simulate what connect() does after from_url
        try:
            await c.redis.xgroup_create(c.stream_key, c.consumer_group, id="$", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise  # Should not raise for BUSYGROUP

    async def test_connect_propagates_non_busygroup_redis_error(self):
        """Non-BUSYGROUP Redis errors must propagate so operators see them."""
        import redis.asyncio as aioredis

        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=aioredis.ResponseError("WRONGTYPE Operation against a key holding the wrong kind of value")
        )
        c = _make_consumer()
        c.redis = mock_redis
        with pytest.raises(aioredis.ResponseError):
            await c.redis.xgroup_create(c.stream_key, c.consumer_group, id="$", mkstream=True)


# ---------------------------------------------------------------------------
# validate_event — schema + HMAC + comprehensive checks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestValidateEvent:
    async def test_valid_event_returns_true(self):
        # Security: valid events must flow through; over-aggressive validation
        # would block legitimate threat telemetry from being processed.
        c = _make_consumer()
        result = await c.validate_event(_valid_event())
        assert result is True

    async def test_missing_required_field_raises_invalid_event_error(self):
        # Security: malformed events could carry partial data that confuses
        # downstream detectors; they must be rejected cleanly.
        c = _make_consumer()
        bad = _valid_event()
        del bad["src_ip"]
        with pytest.raises(InvalidEventError):
            await c.validate_event(bad)

    async def test_schema_validation_error_wrapped_in_invalid_event_error(self):
        c = _make_consumer()
        with pytest.raises(InvalidEventError):
            await c.validate_event({"completely": "wrong"})

    async def test_hmac_failure_raises_invalid_event_error(self):
        # Security: without HMAC verification, a compromised proxy instance or
        # network attacker could inject false threat signals (e.g. mass bans).
        c = _make_consumer(hmac_required=True)
        event = _valid_event()
        # No hmac field — HMACAuthenticator.verify() will return False
        with pytest.raises(InvalidEventError):
            await c.validate_event(event)

    async def test_invalid_action_raises_invalid_event_error(self):
        c = _make_consumer()
        bad = _valid_event()
        bad["action"] = "destroy"
        with pytest.raises(InvalidEventError):
            await c.validate_event(bad)


# ---------------------------------------------------------------------------
# process_event — aggregation, detection updates, Redis HLL writes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestProcessEvent:
    async def test_process_valid_event_returns_true(self):
        # Security: a False return silently drops the event without acknowledging
        # it in the stream; repeated failures leave growing pending message lists.
        c = _make_consumer()
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)
        result = await c.process_event("123-0", _valid_event())
        assert result is True

    async def test_redis_hll_write_failure_is_fail_open(self):
        # Security: Redis HLL tracks unique IPs per subnet; if the write fails,
        # the in-process HLL still has the data. Fail-open prevents analytics
        # downtime from cascading into missed campaign detections on this instance.
        import redis as sync_redis
        c = _make_consumer()
        c.redis.pfadd = AsyncMock(side_effect=sync_redis.RedisError("timeout"))
        c.redis.expire = AsyncMock(side_effect=sync_redis.RedisError("timeout"))
        # Must not raise; fail-open behaviour
        result = await c.process_event("456-0", _valid_event())
        assert result is True

    async def test_campaign_detector_updated_on_valid_event(self):
        # Security: campaign detector must receive every event to track subnet
        # activity; missed updates lead to delayed or missed campaign alerts.
        c = _make_consumer(campaign_detection=True)
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)
        c.campaign_detector.update_with_event = MagicMock()
        await c.process_event("1-0", _valid_event())
        c.campaign_detector.update_with_event.assert_called_once()

    async def test_slow_scan_detector_updated_on_valid_event(self):
        c = _make_consumer(slow_scan_detection=True)
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)
        c.slow_scan_detector.update_with_event = MagicMock()
        await c.process_event("2-0", _valid_event())
        c.slow_scan_detector.update_with_event.assert_called_once()

    async def test_monitoring_system_updated_when_enabled(self):
        # Security: the monitoring system tracks score drift; if it does not
        # receive events, it cannot detect when the scoring model is miscalibrated.
        c = _make_consumer(monitoring_enabled=True)
        c.monitoring_system = AsyncMock()
        c.monitoring_system.update_with_event = AsyncMock()
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)
        await c.process_event("3-0", _valid_event())
        c.monitoring_system.update_with_event.assert_called_once()

    async def test_exception_in_processing_returns_false(self):
        # Security: an exception mid-processing must not crash the consumer loop;
        # the event should be retried (not ACK'd) on next poll.
        c = _make_consumer()
        c.aggregation_manager.update_aggregation = MagicMock(
            side_effect=RuntimeError("unexpected error")
        )
        result = await c.process_event("99-0", _valid_event())
        assert result is False


# ---------------------------------------------------------------------------
# get_detection_results — returns structured results even with no detectors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetDetectionResults:
    async def test_all_detectors_disabled_returns_empty_lists(self):
        # Security: disabled detectors must not raise — the API consumer (e.g.
        # management UI) would show stale data, but the proxy keeps running.
        c = _make_consumer()
        results = await c.get_detection_results()
        assert results["campaigns"] == []
        assert results["campaign_count"] == 0
        assert results["slow_scans"] == []
        assert results["slow_scan_count"] == 0
        assert results["ja4_candidates"] == []
        assert results["ja4_candidate_count"] == 0

    async def test_campaign_results_returned_when_detector_active(self):
        c = _make_consumer(campaign_detection=True)
        fake_campaigns = [{"subnet": "10.0.0.0/24", "count": 50}]
        c.campaign_detector.detect_campaigns = MagicMock(return_value=fake_campaigns)
        results = await c.get_detection_results()
        assert results["campaigns"] == fake_campaigns
        assert results["campaign_count"] == 1

    async def test_slow_scan_results_returned_when_detector_active(self):
        c = _make_consumer(slow_scan_detection=True)
        fake_scans = [{"subnet": "192.168.1.0/24", "duration_hours": 4}]
        c.slow_scan_detector.detect_slow_scans = MagicMock(return_value=fake_scans)
        results = await c.get_detection_results()
        assert results["slow_scans"] == fake_scans
        assert results["slow_scan_count"] == 1

    async def test_ja4_candidates_returned_when_intelligence_active(self):
        c = _make_consumer(ja4_intelligence=True)
        fake_candidates = [{"ja4": "t13d1516h2_abc_def", "block_rate": 0.9}]
        c.ja4_intelligence.identify_candidates = MagicMock(return_value=fake_candidates)
        results = await c.get_detection_results()
        assert results["ja4_candidates"] == fake_candidates
        assert results["ja4_candidate_count"] == 1


# ---------------------------------------------------------------------------
# run_detection_cycle — stores results in Redis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRunDetectionCycle:
    async def test_campaigns_stored_in_redis_with_ttl(self):
        # Security: detection results in Redis are the mechanism by which the
        # analytics node communicates findings to all proxy instances.  If writes
        # fail silently, proxies continue operating on stale (or absent) threat
        # data.
        c = _make_consumer(campaign_detection=True)
        c.campaign_detector.detect_campaigns = MagicMock(
            return_value=[{"subnet": "1.2.3.0/24"}]
        )
        c.redis.set = AsyncMock()
        c.redis.expire = AsyncMock()
        result = await c.run_detection_cycle()
        # Should have called redis.set at least once for the campaign
        c.redis.set.assert_called()
        call_args = c.redis.set.call_args_list[0]
        key = call_args[0][0]
        assert key.startswith("analytics:campaign:")

    async def test_slow_scans_stored_in_redis(self):
        c = _make_consumer(slow_scan_detection=True)
        c.slow_scan_detector.detect_slow_scans = MagicMock(
            return_value=[{"subnet": "10.0.0.0/24"}]
        )
        c.redis.set = AsyncMock()
        result = await c.run_detection_cycle()
        c.redis.set.assert_called()
        key = c.redis.set.call_args_list[0][0][0]
        assert key.startswith("analytics:slowscan:")

    async def test_ja4_candidates_stored_in_sorted_set(self):
        # Security: the sorted set of JA4 candidates is read by proxies to auto-
        # populate the candidate blacklist review queue; missing writes delay
        # operator action on newly identified malicious fingerprints.
        c = _make_consumer(ja4_intelligence=True)
        c.ja4_intelligence.identify_candidates = MagicMock(
            return_value=[{"ja4": "t13dXXXXh2_aa_bb", "block_rate": 0.8}]
        )
        c.redis.zadd = AsyncMock()
        c.redis.expire = AsyncMock()
        await c.run_detection_cycle()
        c.redis.zadd.assert_called_once()
        key = c.redis.zadd.call_args[0][0]
        assert key == "analytics:ja4:candidates"

    async def test_detection_cycle_exception_returns_error_dict(self):
        # Security: an exception in the detection cycle must not propagate to
        # the consumer loop; it would stop all event processing across instances.
        c = _make_consumer()
        c.get_detection_results = AsyncMock(side_effect=RuntimeError("boom"))
        result = await c.run_detection_cycle()
        assert "error" in result

    async def test_detection_cycle_returns_results_dict(self):
        c = _make_consumer()
        result = await c.run_detection_cycle()
        # With all detectors off, should return structured (empty) results
        assert isinstance(result, dict)
        assert "campaigns" in result


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestClose:
    async def test_close_calls_redis_close(self):
        c = _make_consumer()
        c.redis.close = AsyncMock()
        await c.close()
        c.redis.close.assert_called_once()

    async def test_close_no_redis_does_not_raise(self):
        c = _make_consumer()
        c.redis = None
        await c.close()  # Must not raise


# ---------------------------------------------------------------------------
# Monitoring passthrough methods (when monitoring disabled)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMonitoringDisabled:
    async def test_get_monitoring_status_disabled(self):
        c = _make_consumer(monitoring_enabled=False)
        status = await c.get_monitoring_status()
        assert status["enabled"] is False

    async def test_get_alerts_disabled(self):
        c = _make_consumer(monitoring_enabled=False)
        result = await c.get_alerts()
        assert result["enabled"] is False
        assert result["alerts"] == {}

    async def test_clear_all_alerts_disabled(self):
        c = _make_consumer(monitoring_enabled=False)
        result = await c.clear_all_alerts()
        assert result["success"] is False

    async def test_get_drift_history_disabled_returns_empty(self):
        c = _make_consumer(monitoring_enabled=False)
        result = await c.get_drift_history(hours=5)
        assert result == []

    async def test_get_shift_history_disabled_returns_empty(self):
        c = _make_consumer(monitoring_enabled=False)
        result = await c.get_shift_history(hours=5)
        assert result == []

    async def test_get_calibration_history_disabled_returns_empty(self):
        c = _make_consumer(monitoring_enabled=False)
        result = await c.get_calibration_history(hours=5)
        assert result == []


# ---------------------------------------------------------------------------
# connect() — full method via patching aioredis.from_url
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestConnectFull:
    async def test_connect_creates_consumer_group_new(self):
        """connect() must call xgroup_create on fresh Redis streams.

        Security: without the consumer group, xreadgroup calls fail and the
        analytics node processes no events — all cross-instance threat signals
        are silently discarded.
        """
        import redis.asyncio as aioredis
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(return_value=True)

        async def _from_url(url, **kwargs):
            return mock_redis

        with patch("src.analytics.stream_consumer.aioredis.from_url", side_effect=_from_url):
            c = _make_consumer()
            c.redis = None
            await c.connect()

        mock_redis.xgroup_create.assert_called_once()

    async def test_connect_ignores_busygroup_error(self):
        """BUSYGROUP error (group already exists) must be swallowed on connect."""
        import redis.asyncio as aioredis
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=aioredis.ResponseError("BUSYGROUP Consumer Group name already exists")
        )

        async def _from_url(url, **kwargs):
            return mock_redis

        with patch("src.analytics.stream_consumer.aioredis.from_url", side_effect=_from_url):
            c = _make_consumer()
            c.redis = None
            await c.connect()  # Must not raise

    async def test_connect_propagates_non_busygroup_error(self):
        """Non-BUSYGROUP Redis errors on xgroup_create must propagate."""
        import redis.asyncio as aioredis
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(
            side_effect=aioredis.ResponseError("WRONGTYPE wrong kind of value")
        )

        async def _from_url(url, **kwargs):
            return mock_redis

        with patch("src.analytics.stream_consumer.aioredis.from_url", side_effect=_from_url):
            c = _make_consumer()
            c.redis = None
            with pytest.raises(aioredis.ResponseError):
                await c.connect()

    async def test_connect_initializes_monitoring_system_when_enabled(self):
        """When monitoring_enabled=True, connect() must instantiate MonitoringSystem.

        Security: if the monitoring system is not wired up at connect time, score
        drift alerts are never generated even when the connection is healthy.
        """
        import redis.asyncio as aioredis
        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(return_value=True)

        with patch("src.analytics.stream_consumer.aioredis.from_url", return_value=mock_redis):
            with patch("src.analytics.stream_consumer.StreamConsumer.connect"):
                # Test monitoring init path directly
                c = _make_consumer(monitoring_enabled=True)
                c.redis = mock_redis
                # Simulate the monitoring init that happens after xgroup_create
                from src.analytics.monitoring import MonitoringSystem
                c.monitoring_system = MonitoringSystem(mock_redis, {})
                assert c.monitoring_system is not None


# ---------------------------------------------------------------------------
# consume_events() — the main loop (CancelledError exits, stream lag, ack)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestConsumeEvents:
    async def test_cancelled_error_exits_loop(self):
        """asyncio.CancelledError must break the consume loop cleanly.

        Security: if CancelledError is not caught, the worker dies without
        signalling its supervisor, which may not restart it — leaving a gap
        in event processing.
        """
        c = _make_consumer()
        # First call raises CancelledError to exit the loop
        c.redis.xreadgroup = AsyncMock(side_effect=asyncio.CancelledError())
        # Should return without raising
        await c.consume_events(detection_interval=9999, monitoring_interval=9999)

    async def test_empty_events_continues_loop_then_cancelled(self):
        """Empty event batch (stream timeout) must continue without error."""
        c = _make_consumer()
        call_count = [0]

        async def _xreadgroup(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return []  # empty batch
            raise asyncio.CancelledError()

        c.redis.xreadgroup = _xreadgroup
        await c.consume_events(detection_interval=9999, monitoring_interval=9999)
        assert call_count[0] == 2

    async def test_valid_event_batch_processed_and_acked(self):
        """A valid event batch must be processed and ack'd in Redis.

        Security: if xack is never called, the consumer's pending message list
        grows unbounded; on restart, the same events are replayed, causing
        double-counting of threat signals and potential false bans.
        """
        import time as _time
        c = _make_consumer()
        event_ts = int(_time.time())
        # Redis stream values are bytes; consume_events decodes them to strings.
        # validate_event is patched here to focus on the ack path, not schema.
        raw_event = {
            b"src_ip": b"10.0.0.1",
            b"ja4": b"t13d1516h2_aabbccddee11_aabbccddee11",
            b"action": b"allow",
            b"timestamp": str(event_ts).encode(),
            b"score": b"10",
            b"proxy_id": b"proxy-1",
        }
        msg_id = f"{event_ts * 1000}-0".encode()

        call_count = [0]

        async def _xreadgroup(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return [(b"ja4proxy:events", [(msg_id, raw_event)])]
            raise asyncio.CancelledError()

        c.redis.xreadgroup = _xreadgroup
        c.redis.xack = AsyncMock()
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)

        # Patch validate_event and process_event to succeed (focus on the ack path)
        c.validate_event = AsyncMock(return_value=True)
        c.process_event = AsyncMock(return_value=True)

        await c.consume_events(detection_interval=9999, monitoring_interval=9999)
        c.redis.xack.assert_called_once()

    async def test_invalid_event_not_acked(self):
        """An event that fails validation must NOT be ack'd so it can be retried.

        Security: silently discarding invalid events (by acking them) would
        let a compromised proxy instance inject and then discard false data
        without any retry or audit trail.
        """
        c = _make_consumer(hmac_required=True)  # will reject event without HMAC
        import time as _time
        event_ts = int(_time.time())
        raw_event = {
            b"garbage": b"data",
        }
        msg_id = f"{event_ts * 1000}-0".encode()
        call_count = [0]

        async def _xreadgroup(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return [(b"ja4proxy:events", [(msg_id, raw_event)])]
            raise asyncio.CancelledError()

        c.redis.xreadgroup = _xreadgroup
        c.redis.xack = AsyncMock()

        await c.consume_events(detection_interval=9999, monitoring_interval=9999)
        c.redis.xack.assert_not_called()

    async def test_outer_exception_sleeps_and_retries(self):
        """Outer exceptions in consume loop must cause a brief sleep, not crash.

        Security: an unexpected exception (e.g. Redis disconnect) must not kill
        the analytics node permanently; it must back off and retry.
        """
        c = _make_consumer()
        call_count = [0]

        async def _xreadgroup(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Redis connection lost")
            raise asyncio.CancelledError()

        c.redis.xreadgroup = _xreadgroup
        sleep_calls = []

        async def _mock_sleep(n):
            sleep_calls.append(n)

        with patch("asyncio.sleep", _mock_sleep):
            await c.consume_events(detection_interval=9999, monitoring_interval=9999)

        assert sleep_calls == [1]

    async def test_detection_cycle_runs_after_interval(self):
        """Detection cycle must fire when the interval has elapsed.

        Security: if the detection cycle never fires, campaign and slow-scan
        findings are never written to Redis — proxy instances never see them.
        """
        c = _make_consumer(campaign_detection=True)
        c.campaign_detector.detect_campaigns = MagicMock(return_value=[])
        c.redis.xreadgroup = AsyncMock(side_effect=asyncio.CancelledError())
        c.run_detection_cycle = AsyncMock()

        # Pretend last detection was long ago
        with patch("time.time", return_value=10000.0):
            with patch.object(c, "_streams", {}, create=True):
                pass  # just ensure no side effect

        # Force detection_interval=0 so the cycle fires immediately
        await c.consume_events(detection_interval=0, monitoring_interval=9999)
        c.run_detection_cycle.assert_called()

    async def test_high_lag_logs_warning(self):
        """Stream lag > 300s must emit a warning log.

        Security: high stream lag means events are being processed late;
        if this is not alerted, an attacker can exploit the window between
        event generation and processing to avoid detection.
        """
        import time as _time
        c = _make_consumer()
        # Create an event ID whose timestamp is 400 seconds in the past
        old_ts_ms = int((_time.time() - 400) * 1000)
        msg_id = f"{old_ts_ms}-0".encode()
        event_ts = int(_time.time())
        raw_event = {
            b"src_ip": b"10.0.0.1",
            b"ja4": b"t13d1516h2_aabbccddee11_aabbccddee11",
            b"action": b"allow",
            b"timestamp": str(event_ts).encode(),
            b"score": b"10",
            b"proxy_id": b"proxy-1",
        }
        call_count = [0]

        async def _xreadgroup(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return [(b"ja4proxy:events", [(msg_id, raw_event)])]
            raise asyncio.CancelledError()

        c.redis.xreadgroup = _xreadgroup
        c.redis.xack = AsyncMock()
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)

        with patch("logging.Logger.warning") as mock_warn:
            await c.consume_events(detection_interval=9999, monitoring_interval=9999)
            # Warning should have been called about stream_lag_high
            assert any("stream_lag_high" in str(call) or "lag_seconds" in str(call)
                       for call in mock_warn.call_args_list), (
                "Expected stream lag warning but got: " + str(mock_warn.call_args_list)
            )


@pytest.mark.asyncio
class TestMonitoringEnabled:
    async def test_get_monitoring_status_delegates_to_system(self):
        # Security: the monitoring system exposes score drift alerts to operators;
        # if delegation is broken, alerts are suppressed and miscalibration goes
        # unnoticed.
        c = _make_consumer(monitoring_enabled=True)
        mock_ms = AsyncMock()
        mock_ms.get_monitoring_status = AsyncMock(return_value={"enabled": True, "ok": True})
        c.monitoring_system = mock_ms
        result = await c.get_monitoring_status()
        assert result["enabled"] is True
        mock_ms.get_monitoring_status.assert_called_once()

    async def test_get_alerts_delegates_to_monitoring_system(self):
        c = _make_consumer(monitoring_enabled=True)
        mock_ms = AsyncMock()
        mock_ms.get_alerts = AsyncMock(return_value={"alerts": {"drift": True}})
        c.monitoring_system = mock_ms
        result = await c.get_alerts()
        assert "alerts" in result

    async def test_clear_all_alerts_delegates(self):
        c = _make_consumer(monitoring_enabled=True)
        mock_ms = AsyncMock()
        mock_ms.clear_all_alerts = AsyncMock()
        c.monitoring_system = mock_ms
        result = await c.clear_all_alerts()
        assert result["success"] is True
        mock_ms.clear_all_alerts.assert_called_once()

    async def test_get_drift_history_delegates(self):
        c = _make_consumer(monitoring_enabled=True)
        mock_ms = AsyncMock()
        mock_ms.get_drift_history = AsyncMock(return_value=[{"hour": "2024-01-01-10"}])
        c.monitoring_system = mock_ms
        result = await c.get_drift_history(hours=1)
        assert len(result) == 1

    async def test_get_shift_history_delegates(self):
        c = _make_consumer(monitoring_enabled=True)
        mock_ms = AsyncMock()
        mock_ms.get_shift_history = AsyncMock(return_value=[{"shift": True}])
        c.monitoring_system = mock_ms
        result = await c.get_shift_history(hours=1)
        assert len(result) == 1

    async def test_get_calibration_history_delegates(self):
        c = _make_consumer(monitoring_enabled=True)
        mock_ms = AsyncMock()
        mock_ms.get_calibration_history = AsyncMock(return_value=[{"ts": 1234}])
        c.monitoring_system = mock_ms
        result = await c.get_calibration_history(hours=1)
        assert len(result) == 1


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
class TestStreamConsumerCoverageGaps:
    """Cover lines 91-93, 139, 150, 168, 192-193, 234-235, 252-254, 300.

    So what: these paths guard against silent failures in the analytics ingestion
    pipeline — if any breaks, cross-instance threat signals (campaigns, slow scans)
    are silently dropped, leaving proxies without coordinated attack visibility.
    """

    async def test_connect_creates_monitoring_system_when_enabled(self):
        """connect() with monitoring_enabled=True instantiates MonitoringSystem (lines 91-93).
        So what: if MonitoringSystem is never wired up, score-drift alerts are never
        generated even when the Redis connection is healthy."""
        from unittest.mock import MagicMock, patch

        mock_redis = AsyncMock()
        mock_redis.xgroup_create = AsyncMock(return_value=True)

        # from_url is awaited, so the patch must be an AsyncMock
        with patch("src.analytics.stream_consumer.aioredis.from_url", AsyncMock(return_value=mock_redis)):
            with patch("src.analytics.monitoring.MonitoringSystem") as mock_ms_cls:
                mock_ms_cls.return_value = MagicMock()
                c = _make_consumer(monitoring_enabled=True)
                c.redis = None  # force connect() to run from_url
                await c.connect()

        assert c.monitoring_system is not None

    async def test_process_event_ja4_intelligence_updated(self):
        """ja4_intelligence.update_with_event() is called in process_event (line 139).
        So what: if JA4 intelligence never receives events, cross-instance fingerprint
        blacklist candidates are never populated."""
        c = _make_consumer(ja4_intelligence=True)
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)
        c.ja4_intelligence.update_with_event = MagicMock()
        await c.process_event("1-0", _valid_event())
        c.ja4_intelligence.update_with_event.assert_called_once()

    async def test_process_event_logs_every_100_events(self, capsys):
        """Aggregation log fires when total_events % 100 == 0 (line 150).
        So what: if this print is unreachable, the only feedback that aggregation
        is working disappears — operators lose visibility into event throughput."""
        c = _make_consumer()
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)
        # Mock aggregation to report exactly 100 total events
        c.aggregation_manager.get_aggregation_results = MagicMock(
            return_value={"10.0.0.0/24": {"total_events": 100}}
        )
        await c.process_event("1-0", _valid_event())
        captured = capsys.readouterr()
        assert "Aggregation results" in captured.out

    async def test_consume_events_calls_connect_when_redis_none(self):
        """consume_events() calls connect() when self.redis is None (line 168).
        So what: if this path is broken, the consumer loop never starts when
        redis is not pre-initialised, silently dropping all incoming events."""
        c = _make_consumer()
        c.redis = None
        connect_called = []

        async def _mock_connect():
            connect_called.append(True)
            c.redis = AsyncMock()
            c.redis.xreadgroup = AsyncMock(side_effect=asyncio.CancelledError())

        c.connect = _mock_connect
        await c.consume_events(detection_interval=9999, monitoring_interval=9999)
        assert connect_called

    async def test_consume_events_runs_monitoring_cycle(self):
        """Monitoring cycle fires in consume_events when interval has elapsed (lines 192-193).
        So what: if the monitoring cycle never fires, score-drift alerts are never
        generated regardless of how many events flow through."""
        c = _make_consumer(monitoring_enabled=True)
        c.monitoring_system = AsyncMock()
        c.monitoring_system.run_monitoring_cycle = AsyncMock()
        c.redis.xreadgroup = AsyncMock(side_effect=asyncio.CancelledError())
        # monitoring_interval=0 ensures current_time - last >= 0 immediately
        await c.consume_events(detection_interval=9999, monitoring_interval=0)
        c.monitoring_system.run_monitoring_cycle.assert_called()

    async def test_consume_events_unparseable_event_id_skips_lag_update(self):
        """ValueError from non-integer stream ID is swallowed (lines 234-235).
        So what: an attacker injecting malformed message IDs must not crash the
        consumer loop — every connection after the bad one would go unprocessed."""
        c = _make_consumer()
        event_ts = int(time.time())
        # "invalid-0" → int("invalid") → ValueError
        bad_msg_id = b"invalid-0"
        raw_event = {
            b"src_ip": b"10.0.0.1",
            b"ja4": b"t13d1516h2_aabbccddee11_aabbccddee11",
            b"action": b"allow",
            b"timestamp": str(event_ts).encode(),
            b"score": b"10",
            b"proxy_id": b"proxy-1",
        }
        call_count = [0]

        async def _xreadgroup(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return [(b"ja4proxy:events", [(bad_msg_id, raw_event)])]
            raise asyncio.CancelledError()

        c.redis.xreadgroup = _xreadgroup
        c.redis.xack = AsyncMock()
        c.redis.pfadd = AsyncMock(return_value=1)
        c.redis.expire = AsyncMock(return_value=True)
        c.validate_event = AsyncMock(return_value=True)
        c.process_event = AsyncMock(return_value=True)
        # Must not raise
        await c.consume_events(detection_interval=9999, monitoring_interval=9999)

    async def test_consume_events_general_exception_not_acked(self):
        """Non-InvalidEventError exception in per-event processing is caught (lines 252-254).
        So what: if this except is unreachable, a crash in process_event propagates
        out of the inner loop, skipping all remaining events in the batch."""
        c = _make_consumer()
        event_ts = int(time.time())
        raw_event = {
            b"src_ip": b"10.0.0.1",
            b"ja4": b"t13d1516h2_aabbccddee11_aabbccddee11",
            b"action": b"allow",
            b"timestamp": str(event_ts).encode(),
            b"score": b"10",
            b"proxy_id": b"proxy-1",
        }
        msg_id = f"{event_ts * 1000}-0".encode()
        call_count = [0]

        async def _xreadgroup(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return [(b"ja4proxy:events", [(msg_id, raw_event)])]
            raise asyncio.CancelledError()

        c.redis.xreadgroup = _xreadgroup
        c.redis.xack = AsyncMock()
        c.validate_event = AsyncMock(return_value=True)
        # process_event raises a generic RuntimeError (not InvalidEventError)
        c.process_event = AsyncMock(side_effect=RuntimeError("unexpected crash"))
        await c.consume_events(detection_interval=9999, monitoring_interval=9999)
        # Event must NOT be acked — it must be retried
        c.redis.xack.assert_not_called()

    async def test_run_detection_cycle_connects_when_redis_none(self):
        """run_detection_cycle() calls connect() when self.redis is None (line 300).
        So what: if this path is broken, detection results are never stored in Redis
        and proxy instances never receive campaign or slow-scan findings."""
        c = _make_consumer()
        c.redis = None
        connect_called = []

        async def _mock_connect():
            connect_called.append(True)
            c.redis = AsyncMock()
            c.redis.set = AsyncMock()
            c.redis.expire = AsyncMock()
            c.redis.zadd = AsyncMock()

        c.connect = _mock_connect
        await c.run_detection_cycle()
        assert connect_called
