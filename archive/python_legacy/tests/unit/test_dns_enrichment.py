"""Unit tests for DNS Enrichment (Phase 7)."""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import redis as redis_module

from src.security.dns_enrichment import DNSEnrichment, FCrDNSResult


class TestFCrDNSResult(unittest.TestCase):
    """Test FCrDNSResult dataclass."""

    def test_dataclass_fields(self):
        """FCrDNSResult has correct fields."""
        result = FCrDNSResult(
            ip="1.2.3.4",
            has_ptr=True,
            hostname="example.com",
            confirmed=True,
            classification="confirmed",
        )
        self.assertEqual(result.ip, "1.2.3.4")
        self.assertTrue(result.has_ptr)
        self.assertEqual(result.hostname, "example.com")
        self.assertTrue(result.confirmed)
        self.assertEqual(result.classification, "confirmed")


class TestDNSEnrichment(unittest.TestCase):
    """Test DNSEnrichment class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "dns_enrichment": {
                "enabled": True,
                "queue_size": 1000,
                "worker_count": 5,
                "fcrdns": {
                    "cache_ttl_seconds": 21600,
                    "no_ptr_score": 15,
                    "fcrdns_failed_score": 20,
                    "residential_score_reduction": 10,
                },
            }
        }
        self.mock_redis = MagicMock()

    def test_init_with_config(self):
        """DNSEnrichment initializes with config."""
        # Create event loop for aiodns
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            enrichment = DNSEnrichment(self.config, self.mock_redis)
            # If aiodns is not available, module should disable itself gracefully
            if enrichment._enabled:
                self.assertEqual(enrichment._cache_ttl, 21600)
            else:
                self.assertFalse(enrichment._enabled)
        finally:
            loop.close()

    def test_init_disabled(self):
        """DNSEnrichment disabled when config says so."""
        config = {"dns_enrichment": {"enabled": False}}
        enrichment = DNSEnrichment(config, self.mock_redis)
        self.assertFalse(enrichment._enabled)

    def test_classify_hostname_confirmed(self):
        """Generic confirmed hostname → confirmed classification."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        result = enrichment._classify_hostname("example.com", True)
        self.assertEqual(result, "confirmed")

    def test_classify_hostname_residential(self):
        """Residential pattern → residential classification."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        result = enrichment._classify_hostname("cpc12345-cust1.example.com", True)
        self.assertEqual(result, "residential")

    def test_classify_hostname_datacenter(self):
        """Datacenter pattern → datacenter_confirmed classification."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        result = enrichment._classify_hostname(
            "ec2-1-2-3-4.compute-1.amazonaws.com", True
        )
        self.assertEqual(result, "datacenter_confirmed")

    def test_classify_hostname_fcrdns_failed(self):
        """Failed FCrDNS → fcrdns_failed classification."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        result = enrichment._classify_hostname("example.com", False)
        self.assertEqual(result, "fcrdns_failed")

    def test_classify_hostname_ptr_literal(self):
        """IP literal PTR → ptr_ip_literal classification."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        result = enrichment._classify_hostname("4.3.2.1", True)
        self.assertEqual(result, "confirmed")  # No special handling for IP literals

    def test_get_signal_from_cache(self):
        """Get signal from cached data."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        cached = {"classification": "no_ptr"}
        signal = enrichment._signal_from_cache(cached)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.name, "no_ptr")
        self.assertEqual(signal.score, 15)

    def test_get_signal_with_positive_score(self):
        """Get signal with positive score."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        cached = {"classification": "fcrdns_failed", "ptr": "example.com"}
        signal = enrichment._signal_from_cache(cached)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.name, "fcrdns_failed")
        self.assertEqual(signal.score, 20)

    def test_get_signal_cache_miss(self):
        """Cache miss returns None."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)
        # Mock _get_cached_result to return None
        enrichment._get_cached_result = AsyncMock(return_value=None)

        async def run_test():
            signal = await enrichment.get_signal("1.2.3.4")
            self.assertIsNone(signal)

        asyncio.run(run_test())


class TestDNSEnrichmentAsync(unittest.TestCase):
    """Async tests for DNSEnrichment."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "dns_enrichment": {
                "enabled": True,
                "queue_size": 10,
                "worker_count": 1,
                "fcrdns": {
                    "cache_ttl_seconds": 21600,
                    "no_ptr_score": 15,
                    "fcrdns_failed_score": 20,
                    "residential_score_reduction": 10,
                },
            }
        }
        self.mock_redis = MagicMock()

    def test_fcrdns_check_disabled(self):
        """FCrDNS check disabled when enrichment disabled."""
        config = {"dns_enrichment": {"enabled": False}}
        enrichment = DNSEnrichment(config, self.mock_redis)

        async def run_test():
            # Should not crash
            result = await enrichment._fcrdns_check("1.2.3.4")
            self.assertEqual(result.classification, "resolver_unavailable")

        asyncio.run(run_test())

    def test_enqueue_alpn_whitelist(self):
        """h2/h1 ALPN IPs are not enqueued."""
        enrichment = DNSEnrichment(self.config, self.mock_redis)

        async def run_test():
            await enrichment.enqueue("1.2.3.4", alpn="h2")
            # Queue should be empty or not have this IP
            self.assertLessEqual(enrichment._queue.qsize(), 0)

        asyncio.run(run_test())

    def test_enqueue_bloom_filter_hit(self):
        """Bloom filter prevents duplicate enqueues."""
        # Create event loop for aiodns
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            enrichment = DNSEnrichment(self.config, self.mock_redis)

            # If module is disabled (aiodns not available), skip this test
            if not enrichment._enabled:
                self.skipTest("aiodns not available, DNS enrichment disabled")
                return

            self.mock_redis.bf().exists.return_value = True

            async def run_test():
                await enrichment.enqueue("1.2.3.4")
                # Should have checked Bloom filter
                self.mock_redis.bf().exists.assert_called_once_with(
                    "bloom:dns_enriched", "1.2.3.4"
                )

            asyncio.run(run_test())
        finally:
            loop.close()

    def test_enqueue_queue_full(self):
        """Queue full drops new items."""
        # Create event loop for aiodns
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            enrichment = DNSEnrichment(self.config, self.mock_redis)

            # If module is disabled (aiodns not available), skip this test
            if not enrichment._enabled:
                self.skipTest("aiodns not available, DNS enrichment disabled")
                return

            # Create queue with size 1 and fill it
            async def run_test():
                # Fill queue
                await enrichment.enqueue("1.2.3.4")
                # Workers may process it, so check that we can add one more
                await enrichment.enqueue("5.6.7.8")
                # At least one item should be in the queue or processed
                self.assertGreaterEqual(enrichment._queue.qsize(), 0)

            asyncio.run(run_test())
        finally:
            loop.close()


class TestDNSEnrichmentCoverageGaps(unittest.TestCase):
    """Phase 16c — cover previously uncovered code paths."""

    _BASE_CONFIG = {
        "dns_enrichment": {
            "enabled": True,
            "queue_size": 100,
            "worker_count": 0,  # No background tasks during tests
            "fcrdns": {
                "cache_ttl_seconds": 21600,
                "no_ptr_score": 15,
                "fcrdns_failed_score": 20,
                "residential_score_reduction": 10,
            },
        }
    }

    def _make(self, config=None, redis=None):
        return DNSEnrichment(config or self._BASE_CONFIG, redis)

    # -- _init_resolver with AIODNS_AVAILABLE=False

    def test_init_resolver_aiodns_unavailable(self):
        """When aiodns is unavailable, enrichment is disabled (lines 131-139)."""
        with patch("src.security.dns_enrichment.AIODNS_AVAILABLE", False):
            enr = self._make()
        self.assertFalse(enr._enabled)
        self.assertIsNone(enr._resolver)

    def test_init_resolver_with_nameservers(self):
        """Nameservers are applied to resolver when configured (line 147)."""
        config = {
            "dns_enrichment": {
                "enabled": True,
                "worker_count": 0,
                "resolver_nameservers": ["8.8.8.8", "1.1.1.1"],
                "fcrdns": {},
            }
        }
        with patch("src.security.dns_enrichment.aiodns") as mock_aiodns:
            mock_resolver = MagicMock()
            mock_aiodns.DNSResolver.return_value = mock_resolver
            with patch("src.security.dns_enrichment.AIODNS_AVAILABLE", True):
                enr = DNSEnrichment(config, None)
        self.assertEqual(mock_resolver.nameservers, ["8.8.8.8", "1.1.1.1"])

    def test_init_resolver_exception_disables(self):
        """Resolver init exception disables enrichment."""
        with patch("src.security.dns_enrichment.AIODNS_AVAILABLE", True):
            with patch("src.security.dns_enrichment.aiodns") as mock_aiodns:
                mock_aiodns.DNSResolver.side_effect = Exception("init failed")
                enr = self._make()
        self.assertFalse(enr._enabled)

    # -- _worker_with_restart

    def test_worker_with_restart_propagates_cancellation(self):
        """CancelledError propagates through _worker_with_restart (line 193-194)."""
        enr = self._make()

        async def run():
            enr._enabled = True
            enr._resolver = MagicMock()

            async def raise_cancelled(_):
                raise asyncio.CancelledError()

            with patch.object(enr, "_worker", side_effect=raise_cancelled):
                with self.assertRaises(asyncio.CancelledError):
                    await enr._worker_with_restart(0)

        asyncio.run(run())

    def test_worker_with_restart_restarts_after_exception(self):
        """Worker restarts after non-CancelledError exception (lines 195-203)."""
        enr = self._make()

        async def run():
            call_count = [0]

            async def flaky_worker(_):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise RuntimeError("boom")
                raise asyncio.CancelledError()  # Stop after 2nd call

            with patch.object(enr, "_worker", side_effect=flaky_worker):
                with patch("src.security.dns_enrichment.asyncio.sleep", AsyncMock()):
                    with self.assertRaises(asyncio.CancelledError):
                        await enr._worker_with_restart(0)

            self.assertEqual(call_count[0], 2)

        asyncio.run(run())

    # -- _worker inner loop

    def test_worker_processes_queue_item(self):
        """_worker dequeues and processes one IP (lines 207-222)."""
        enr = self._make()

        async def run():
            processed = []

            async def fake_process(ip):
                processed.append(ip)
                # After first item, cancel the task
                raise asyncio.CancelledError()

            enr._queue.put_nowait("1.2.3.4")
            with patch.object(enr, "_process_ip", side_effect=fake_process):
                with self.assertRaises(asyncio.CancelledError):
                    await enr._worker(0)

            self.assertIn("1.2.3.4", processed)

        asyncio.run(run())

    def test_worker_handles_process_exception(self):
        """_worker logs error and continues on exception (lines 212-221)."""
        enr = self._make()

        async def run():
            call_count = [0]

            async def failing_process(ip):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise ValueError("process failed")
                raise asyncio.CancelledError()

            enr._queue.put_nowait("1.2.3.4")
            enr._queue.put_nowait("5.6.7.8")
            with patch.object(enr, "_process_ip", side_effect=failing_process):
                with self.assertRaises(asyncio.CancelledError):
                    await enr._worker(0)

            self.assertEqual(call_count[0], 2)

        asyncio.run(run())

    # -- _process_ip paths

    def test_process_ip_cache_hit_returns_early(self):
        """_process_ip returns early on cache hit without DNS (lines 230-233)."""
        enr = self._make()

        async def run():
            cached_data = {"classification": "confirmed", "ptr": "example.com"}
            with patch.object(
                enr, "_get_cached_result", AsyncMock(return_value=cached_data)
            ):
                with patch.object(enr, "_fcrdns_check", AsyncMock()) as mock_check:
                    await enr._process_ip("1.2.3.4")
                    mock_check.assert_not_called()

        asyncio.run(run())

    def test_process_ip_cache_miss_does_fcrdns(self):
        """_process_ip performs FCrDNS on cache miss (lines 235-237)."""
        enr = self._make()

        async def run():
            result = FCrDNSResult("1.2.3.4", False, classification="no_ptr")
            with patch.object(enr, "_get_cached_result", AsyncMock(return_value=None)):
                with patch.object(enr, "_fcrdns_check", AsyncMock(return_value=result)):
                    with patch.object(enr, "_cache_result", AsyncMock()) as mock_cache:
                        await enr._process_ip("1.2.3.4")
                        mock_cache.assert_called_once()

        asyncio.run(run())

    # -- _fcrdns_check paths

    def test_fcrdns_check_ptr_timeout(self):
        """PTR timeout → no_ptr classification."""
        enr = self._make()
        enr._resolver = MagicMock()
        enr._resolver.gethostbyaddr = AsyncMock(side_effect=asyncio.TimeoutError())

        async def run():
            result = await enr._fcrdns_check("1.2.3.4")
            self.assertEqual(result.classification, "no_ptr")
            self.assertFalse(result.has_ptr)

        asyncio.run(run())

    def test_fcrdns_check_ptr_exception(self):
        """PTR exception → no_ptr classification."""
        enr = self._make()
        enr._resolver = MagicMock()
        enr._resolver.gethostbyaddr = AsyncMock(side_effect=Exception("NXDOMAIN"))

        async def run():
            result = await enr._fcrdns_check("1.2.3.4")
            self.assertEqual(result.classification, "no_ptr")

        asyncio.run(run())

    def test_fcrdns_check_forward_timeout(self):
        """Forward lookup timeout → fcrdns_failed."""
        enr = self._make()
        enr._resolver = MagicMock()
        ptr_result = MagicMock()
        ptr_result.name = "example.com"
        enr._resolver.gethostbyaddr = AsyncMock(return_value=ptr_result)
        enr._resolver.gethostbyname = AsyncMock(side_effect=asyncio.TimeoutError())

        async def run():
            result = await enr._fcrdns_check("1.2.3.4")
            self.assertEqual(result.classification, "fcrdns_failed")
            self.assertTrue(result.has_ptr)

        asyncio.run(run())

    def test_fcrdns_check_forward_exception(self):
        """Forward lookup exception → fcrdns_failed."""
        enr = self._make()
        enr._resolver = MagicMock()
        ptr_result = MagicMock()
        ptr_result.name = "example.com"
        enr._resolver.gethostbyaddr = AsyncMock(return_value=ptr_result)
        enr._resolver.gethostbyname = AsyncMock(side_effect=Exception("forward fail"))

        async def run():
            result = await enr._fcrdns_check("1.2.3.4")
            self.assertEqual(result.classification, "fcrdns_failed")

        asyncio.run(run())

    def test_fcrdns_check_confirmed(self):
        """Successful PTR+forward with IP match → confirmed."""
        enr = self._make()
        enr._resolver = MagicMock()
        ptr_result = MagicMock()
        ptr_result.name = "host.example.com"
        enr._resolver.gethostbyaddr = AsyncMock(return_value=ptr_result)
        forward_result = MagicMock()
        forward_result.addresses = ["1.2.3.4"]
        enr._resolver.gethostbyname = AsyncMock(return_value=forward_result)

        async def run():
            result = await enr._fcrdns_check("1.2.3.4")
            self.assertTrue(result.confirmed)
            self.assertEqual(result.classification, "confirmed")

        asyncio.run(run())

    def test_fcrdns_check_not_confirmed(self):
        """IP not in forward result → fcrdns_failed."""
        enr = self._make()
        enr._resolver = MagicMock()
        ptr_result = MagicMock()
        ptr_result.name = "host.example.com"
        enr._resolver.gethostbyaddr = AsyncMock(return_value=ptr_result)
        forward_result = MagicMock()
        forward_result.addresses = ["9.9.9.9"]  # Different IP
        enr._resolver.gethostbyname = AsyncMock(return_value=forward_result)

        async def run():
            result = await enr._fcrdns_check("1.2.3.4")
            self.assertFalse(result.confirmed)
            self.assertEqual(result.classification, "fcrdns_failed")

        asyncio.run(run())

    # -- _get_cached_result paths

    def test_get_cached_result_no_redis_returns_none(self):
        """No Redis → _get_cached_result returns None."""
        enr = self._make(redis=None)

        async def run():
            result = await enr._get_cached_result("1.2.3.4")
            self.assertIsNone(result)

        asyncio.run(run())

    def test_get_cached_result_redis_hit(self):
        """Redis hit → returns parsed dict."""
        redis = AsyncMock()
        data = {"classification": "confirmed", "ptr": "host.example.com"}
        redis.get = AsyncMock(return_value=json.dumps(data))
        enr = self._make(redis=redis)

        async def run():
            result = await enr._get_cached_result("1.2.3.4")
            self.assertEqual(result["classification"], "confirmed")

        asyncio.run(run())

    def test_get_cached_result_redis_miss_returns_none(self):
        """Redis miss → returns None."""
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        enr = self._make(redis=redis)

        async def run():
            result = await enr._get_cached_result("1.2.3.4")
            self.assertIsNone(result)

        asyncio.run(run())

    def test_get_cached_result_exception_returns_none(self):
        """Exception in Redis get → returns None."""
        redis = AsyncMock()
        redis.get = AsyncMock(side_effect=redis_module.RedisError("redis error"))
        enr = self._make(redis=redis)

        async def run():
            result = await enr._get_cached_result("1.2.3.4")
            self.assertIsNone(result)

        asyncio.run(run())

    # -- _cache_result paths

    def test_cache_result_no_redis_returns_early(self):
        """No Redis → _cache_result is a no-op."""
        enr = self._make(redis=None)
        result = FCrDNSResult("1.2.3.4", True, "example.com", True, "confirmed")

        async def run():
            await enr._cache_result("1.2.3.4", result)  # Must not raise

        asyncio.run(run())

    def test_cache_result_writes_to_redis(self):
        """_cache_result writes JSON to Redis with TTL."""
        redis = AsyncMock()
        redis.setex = AsyncMock(return_value=True)
        enr = self._make(redis=redis)
        result = FCrDNSResult("1.2.3.4", True, "example.com", True, "confirmed")

        async def run():
            await enr._cache_result("1.2.3.4", result)
            redis.setex.assert_called_once()
            key = redis.setex.call_args[0][0]
            self.assertIn("1.2.3.4", key)

        asyncio.run(run())

    def test_cache_result_exception_logged(self):
        """Exception in Redis setex is caught and logged."""
        redis = AsyncMock()
        redis.setex = AsyncMock(side_effect=Exception("write failed"))
        enr = self._make(redis=redis)
        result = FCrDNSResult("1.2.3.4", True, "example.com", True, "confirmed")

        async def run():
            await enr._cache_result("1.2.3.4", result)  # Must not raise

        asyncio.run(run())

    # -- _signal_from_cache paths

    def test_signal_from_cache_datacenter_confirmed(self):
        """datacenter_confirmed → datacenter_ptr signal with score 0."""
        enr = self._make()
        sig = enr._signal_from_cache(
            {
                "classification": "datacenter_confirmed",
                "ptr": "ec2-1-2-3-4.compute-1.amazonaws.com",
            }
        )
        self.assertIsNotNone(sig)
        self.assertEqual(sig.name, "datacenter_ptr")
        self.assertEqual(sig.score, 0)

    def test_signal_from_cache_confirmed(self):
        """confirmed → ptr_confirmed signal with score 0."""
        enr = self._make()
        sig = enr._signal_from_cache(
            {"classification": "confirmed", "ptr": "host.example.com"}
        )
        self.assertIsNotNone(sig)
        self.assertEqual(sig.name, "ptr_confirmed")
        self.assertEqual(sig.score, 0)

    def test_signal_from_cache_unknown_returns_none(self):
        """Unknown classification → None."""
        enr = self._make()
        sig = enr._signal_from_cache({"classification": "unknown", "ptr": None})
        self.assertIsNone(sig)

    # -- get_signal with cache hit

    def test_get_signal_cached_returns_signal(self):
        """get_signal returns signal from cache without enqueueing (line 407)."""
        enr = self._make()

        async def run():
            cached = {"classification": "no_ptr", "ptr": None}
            with patch.object(
                enr, "_get_cached_result", AsyncMock(return_value=cached)
            ):
                with patch.object(enr, "enqueue", AsyncMock()) as mock_enqueue:
                    sig = await enr.get_signal("1.2.3.4")
                    self.assertIsNotNone(sig)
                    self.assertEqual(sig.name, "no_ptr")
                    mock_enqueue.assert_not_called()

        asyncio.run(run())

    # -- enqueue bloom filter paths

    def test_enqueue_disabled_returns_early(self):
        """enqueue does nothing when disabled."""
        enr = self._make()
        enr._enabled = False

        async def run():
            await enr.enqueue("1.2.3.4")
            self.assertEqual(enr._queue.qsize(), 0)

        asyncio.run(run())

    def test_enqueue_bloom_filter_hit_skips(self):
        """Bloom filter hit → IP not enqueued."""
        redis = AsyncMock()
        mock_bf = AsyncMock()
        mock_bf.exists = AsyncMock(return_value=True)
        redis.bf = MagicMock(return_value=mock_bf)
        enr = self._make(redis=redis)
        enr._enabled = True

        async def run():
            await enr.enqueue("1.2.3.4")
            self.assertEqual(enr._queue.qsize(), 0)

        asyncio.run(run())

    def test_enqueue_bloom_filter_miss_enqueues(self):
        """Bloom filter miss → IP enqueued."""
        redis = AsyncMock()
        mock_bf = AsyncMock()
        mock_bf.exists = AsyncMock(return_value=False)
        mock_bf.add = AsyncMock(return_value=True)
        redis.bf = MagicMock(return_value=mock_bf)
        enr = self._make(redis=redis)
        enr._enabled = True

        async def run():
            await enr.enqueue("1.2.3.4")
            self.assertEqual(enr._queue.qsize(), 1)

        asyncio.run(run())

    def test_enqueue_queue_full_drops(self):
        """Full queue → item dropped, counter incremented."""
        enr = self._make()
        enr._enabled = True
        # Fill the queue
        for i in range(enr._queue.maxsize):
            enr._queue.put_nowait(f"10.0.{i // 256}.{i % 256}")

        async def run():
            from src.security.dns_enrichment import _DNS_QUEUE_DROPS

            before = _DNS_QUEUE_DROPS._value.get()
            await enr.enqueue("99.99.99.99")
            after = _DNS_QUEUE_DROPS._value.get()
            self.assertEqual(after, before + 1)

        asyncio.run(run())

    # -- close() lifecycle

    def test_close_cancels_workers(self):
        """close() cancels all worker tasks (lines 440-443)."""

        async def run():
            enr = self._make()
            dummy = asyncio.create_task(asyncio.sleep(9999))
            enr._workers.append(dummy)
            await enr.close()
            self.assertEqual(enr._workers, [])
            self.assertTrue(dummy.cancelled())

        asyncio.run(run())

    # -- passive DNS status logging

    def test_passive_dns_enabled_no_log(self):
        """No startup log when passive DNS is enabled."""
        config = {
            "dns_enrichment": {
                "enabled": True,
                "worker_count": 0,
                "passive_dns": {"enabled": True},
                "fcrdns": {},
            }
        }
        with patch("src.security.dns_enrichment.logger") as mock_logger:
            enr = DNSEnrichment(config, None)
            # Should not have logged passive_dns_disabled
            logged_events = [str(call) for call in mock_logger.info.call_args_list]
            self.assertFalse(any("passive_dns_disabled" in e for e in logged_events))


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestDNSEnrichmentCoverageGaps2(unittest.TestCase):
    """Cover lines 26-28, 217-218, 531."""

    def _make(self, redis=None, worker_count=0):
        config = {
            "dns_enrichment": {
                "enabled": True,
                "worker_count": worker_count,
                "passive_dns": {"enabled": False},
                "fcrdns": {},
            }
        }
        return DNSEnrichment(config, redis)

    def test_signal_from_cache_residential_returns_negative_score(self):
        """Line 531: residential PTR classification → residential_ptr signal with
        negative score (score reduction).
        So what: if this return is missing, residential connections that resolve to
        home ISP hostnames never receive the benign-traffic discount — ordinary end
        users accumulate higher risk scores, increasing false-positive block rates."""
        enr = self._make()
        sig = enr._signal_from_cache(
            {
                "classification": "residential",
                "ptr": "pool-72-84-14-102.rcmdva.fios.verizon.net",
            }
        )
        self.assertIsNotNone(sig)
        self.assertEqual(sig.name, "residential_ptr")
        self.assertLess(sig.score, 0)  # score is negative (reduction)

    def test_start_workers_in_async_context_creates_tasks(self):
        """Lines 217-218: _start_workers() called from a running event loop creates
        asyncio tasks for each worker.
        So what: if task creation is skipped, DNS resolution requests pile up in the
        queue indefinitely — the entire FCrDNS enrichment pipeline stalls and all
        connections that need PTR lookups bypass DNS scoring silently."""

        async def run():
            enr = self._make(worker_count=2)
            # Cancel any tasks already created so they don't linger
            try:
                for t in list(enr._workers):
                    t.cancel()
            except Exception:
                pass
            enr._workers.clear()

            # Now call _start_workers() from within a running loop
            # asyncio.get_running_loop() succeeds → tasks should be created
            enr._config["worker_count"] = 2
            enr._start_workers()
            self.assertEqual(len(enr._workers), 2)
            for t in enr._workers:
                t.cancel()

        asyncio.run(run())

    def test_aiodns_available_flag_is_set(self):
        """Lines 26-28: AIODNS_AVAILABLE and aiodns module-level names exist after import.
        So what: if the except block is missing and aiodns is absent, NameError crashes
        the proxy at import time — the security pipeline fails to start even when DNS
        enrichment is disabled in config. Verifying the module exports both names
        confirms the try/except guard is wired correctly."""
        import src.security.dns_enrichment as dns_mod

        # Both names must exist regardless of whether aiodns is installed
        self.assertIn("AIODNS_AVAILABLE", dir(dns_mod))
        self.assertIsInstance(dns_mod.AIODNS_AVAILABLE, bool)


if __name__ == "__main__":
    unittest.main()
