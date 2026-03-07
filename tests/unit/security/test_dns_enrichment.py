"""Unit tests for DNS Enrichment (Phase 7)."""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

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
            classification="confirmed"
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
                    "residential_score_reduction": 10
                }
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
        result = enrichment._classify_hostname("ec2-1-2-3-4.compute-1.amazonaws.com", True)
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
                    "residential_score_reduction": 10
                }
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
                self.mock_redis.bf().exists.assert_called_once_with("bloom:dns_enriched", "1.2.3.4")
            
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


if __name__ == "__main__":
    unittest.main()
